# sshenanigans: Build your own SSH server

![Crates.io Version](https://img.shields.io/crates/v/sshenanigans)

sshenanigans is an extensible SSH server. Build your own [SSH game](https://github.com/ajeetdsouza/clidle), [honeypot](https://github.com/telekom-security/tpotce), or SSH server that integrates with your custom user database!

Implement a "Gatekeeper" executable (eg., a [Python script](./examples/basic.py)) that answers questions about who can authenticate and what commands they can execute, and sshenanigans takes care of the rest. sshenanigans works by relaying requests to The Gatekeeper in JSON over stdin. The Gatekeeper then responds with JSON on stdout. That's it... that's all you need!

Features:

- **Bring your own authentication**: Implement your own authentication logic. Accept everyone, consult your org's employee database, send a 2FA request, flip a coin, launch a rocket, etc.
- **Detailed execution control**: Control what commands get run, and with what permissions. Build an SSH game by running your game's binary instead of the shell. Replace the user's requested command with a [Rickroll](https://github.com/keroserene/rickrollrc) for 10% of logins. Or build a honeypot.
- **Any language, any logic**: You're free to implement The Gatekeeper however you like. The API spec is defined in [`src/lib.rs`](./src/lib.rs). Check out [`examples/basic.py`](./examples/basic.py) to get started.

## Gatekeeper API

There are five types of requests sent to The Gatekeeper: `Auth`, `Shell`, `Exec`, `LocalPortForward`, and `Subsystem`. The Gatekeeper will receive one request per invocation. The Gatekeeper should exit with status zero in nominal operation, even when rejecting requests. Exiting in a non-zero status code will cause sshenanigans to produce an error and reject the request.

The Gatekeeper may implement handling for any subset of the request types, but should always terminate. A malformed or missing response will be interpreted as a rejection of the request by sshenanigans.

Every request includes `client_address` and `client_id` fields. `client_address` is the IP address and port of the client. `client_id` is a unique identifier for the client and can be useful for tracking a client across multiple requests. Note however that a single user or machine may maintain multiple connections, each with their own `client_id`, in the same way that you may have multiple browser tabs connected to the same website.

### `Auth` requests

There are three types of `Auth` requests: `None`, `Password`, and `PublicKey`. For example,

```json
{
  "client_address": "127.0.0.1:63107",
  "client_id": "62783347-a23f-42d6-b05b-0c107384f583",
  "request": {
    "Auth": {
      "unverified_credentials": { "username": "sam", "method": "None" }
    }
  }
}
```

```json
{
  "client_address": "127.0.0.1:63146",
  "client_id": "62783347-a23f-42d6-b05b-0c107384f583",
  "request": {
    "Auth": {
      "unverified_credentials": {
        "username": "sam",
        "method": { "Password": { "password": "topsecret" } }
      }
    }
  }
}
```

```json
{
  "client_address": "127.0.0.1:63155",
  "client_id": "62783347-a23f-42d6-b05b-0c107384f583",
  "request": {
    "Auth": {
      "unverified_credentials": {
        "username": "sam",
        "method": {
          "PublicKey": {
            "public_key_algorithm": "ssh-ed25519",
            "public_key_base64": "AAA...wLq"
          }
        }
      }
    }
  }
}
```

Responses should either accept the reqeust or respond with a rejection and a set of suggested authentication methods:

```json
{ "accept": true }
```

```json
{ "accept": false, "proceed_with_methods": ["PASSWORD"] }
```

Allowed `proceed_with_methods` values are 'none', 'password', 'publickey', 'hostbased', 'keyboard-interactive' (case sensitive).

### `Shell` requests

This request is associated with the standard invocation of `ssh user@host`. Requests look like

```json
{
  "client_address": "127.0.0.1:63166",
  "client_id": "62783347-a23f-42d6-b05b-0c107384f583",
  "request": {
    "Shell": {
      "verified_credentials": { "username": "sam", "method": "None" },
      "requested_environment_variables": { "LC_TERMINAL": "xterm-256color" }
    }
  }
}
```

And responses look like

```json
{
  "accept": {
    "command": "/bin/bash",
    "arguments": [],
    "working_directory": "/",
    "uid": 501,
    "gid": 20
  }
}
```

or simply `{}` for a rejection.

### `Exec` requests

This request is commonly triggered by invoking SSH with a command, eg. `ssh user@host ls -al`. In this case, the request will take the form

```json
{
  "client_address": "127.0.0.1:63173",
  "client_id": "62783347-a23f-42d6-b05b-0c107384f583",
  "request": {
    "Exec": {
      "verified_credentials": { "username": "sam", "method": "None" },
      "requested_environment_variables": { "LC_TERMINAL": "xterm-256color" },
      "command": "ls -al"
    }
  }
}
```

And responses follow the same structure as for `Shell` requests.

### `LocalPortForward` requests

This request is commonly triggered by invoking SSH with a local port forward, eg. `ssh -L 8080:localhost:8080 user@host`. Specifically, this request is triggered upon receiving a `direct-tcpip` SSH message from the client, per [RFC 4254 Sec. 7.2](https://datatracker.ietf.org/doc/html/rfc4254#autoid-25). In this case, the request will take the form

```json
{
  "client_address": "174.168.101.116:60531",
  "client_id": "bf001b29-29e1-4754-be0c-37810b6fc703",
  "request": {
    "LocalPortForward": {
      "verified_credentials": { "username": "sam", "method": "None" },
      "host_to_connect": "localhost",
      "port_to_connect": 8888,
      "originator_address": "::1",
      "originator_port": 60548
    }
  }
}
```

And responses follow the same structure as for `Shell` requests. If sshenanigans receives an approval response, it will spawn a process as specified by the response. sshenanigans will send TCP bytes received from the client to the process's stdin, and will send TCP bytes received from the process's stdout to the client.

### `Subsystem` requests

This request is commonly triggered by invoking `scp` which relies on the SFTP subsystem, eg. `scp file.txt user@host:~`. In this case, the request will take the form

```json
{
  "client_address": "174.168.101.116:60531",
  "client_id": "bf001b29-29e1-4754-be0c-37810b6fc703",
  "request": {
    "Subsystem": {
      "verified_credentials": { "username": "sam", "method": "None" },
      "requested_environment_variables": { "LC_TERMINAL": "xterm-256color" },
      "subsystem": "sftp"
    }
  }
}
```

And responses follow the same structure as for `Shell` requests. If sshenanigans receives an approval response, it will spawn a process as specified by the response. sshenanigans will send TCP bytes received from the client to the process's stdin, and will send TCP bytes received from the process's stdout to the client.

## Getting started

1. First, we'll need to create an SSH key pair for the server: `ssh-keygen -N '' -t ed25519 -f ./hostkey`.

   This will create files `hostkey` and `hostkey.pub` in your current directory. This key pair is used to identify the SSH server to clients. If you have ever seen a "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" message, that's because the SSH server changed their host key.

2. Run sshenanigans: `sshenanigans --host-key-path=./hostkey --listen=0.0.0.0:2222 --gatekeeper=./examples/basic.py`

   This will start sshenanigans on port 2222, using the host key we generated in step 1, and using the gatekeeper script `./examples/basic.py`.

3. Connect in a separate terminal: `ssh -p 2222 -t sam@localhost`

   Use password "topsecret" when prompted. You should see a bash shell!

Check out `examples/basic.py` for more information.

# Security considerations

sshenanigans is in active development. Please report any issues you find! A few things to keep in mind:

1. You are responsible for the security and correctness of your Gatekeeper. By transferring security decision-making to The Gatekeeper, we reduce the TCB of sshenanigans and offer more flexibility, but at the cost of increased responsibility for end-users. Hopefully this tradeoff proves worthwhile in certain use cases, and an ecosystem of trusted Gatekeepers/Gatekeeper libraries emerges.
2. Consider running sshenanigans behind a firewall, VPN, or private network like [Tailscale](https://tailscale.com/).
3. Consider running sshenanigans as a minimally privileged user. When executing client commands, sshenanigans will drop privileges to the uid and gid specified by The Gatekeeper. Therefore, you only need to run sshenanigans with the privileges required to bind to a port, read the host key, and spawn processes with the uid/gid values outputted by The Gatekeeper.
4. sshenanigans is not intended to replace OpenSSH. If OpenSSH suits your needs, use it for its stability and battle-hardened security.

If you are curious about sshenanigans's security, you are encouraged to check out the source. The implementation is <750 lines of Rust code.

# Licensing

sshenanigans is licensed under the [AGPLv3 license](https://www.gnu.org/licenses/agpl-3.0.en.html). In short, if you use sshenanigans to provide a service over a network, you must make the source code of the complete product available to the users of that service, regardless of whether you modify sshenanigans. That being said, sshenanigans is also available under an MIT license in the following contexts:

1. You are using sshenanigans for personal, non-commercial use.
2. You are using sshenanigans in a not-for-profit organization and for non-commercial use, eg. academia.
3. You are using sshenanigans in a commercial context and the total number of users, internal and external, of sshenanigans-based services/products is less than 100. In this context, a "user" is defined as any account, human or computer, that can authenticate to sshenanigans, or any account that can (transitively) access a service provided by sshenanigans.

Please [reach out](mailto:skainsworth+sshenanigans@gmail.com) to discuss licensing options if you are interested in using sshenanigans under an MIT license in any other context. A portion of all proceeds go to axial spondyloarthritis (aka ankylosing spondylitis) research.
