# sshenanigans: Build your own SSH server

sshenanigans is an extensible SSH server. Build your own [SSH game](https://github.com/ajeetdsouza/clidle), [honeypot](https://github.com/telekom-security/tpotce), or SSH server that integrates with your custom user database!

Implement a "Gatekeeper" executable (eg., a [Python script](./examples/basic.py)) that answers questions about who can authenticate and what commands they can execute, and sshenanigans takes care of the rest. sshenanigans works by relaying requests to The Gatekeeper in JSON over stdin. The Gatekeeper then responds with JSON on stdout. That's it... that's all you need!

Features:

- **Bring your own authentication**: Implement your own authentication logic. Accept everyone, consult your org's employee database, send a 2FA request, flip a coin, launch a rocket, etc.
- **Detailed execution control**: Control what commands get run, and with what permissions. Build an SSH game by running your game's binary instead of the shell. Replace the user's requested command with a [Rickroll](https://github.com/keroserene/rickrollrc) for 10% of logins. Or build a honeypot.
- **Any language, any logic**: You're free to implement The Gatekeeper however you like. The API spec is defined in [`src/lib.rs`](./src/lib.rs). Check out [`examples/basic.py`](./examples/basic.py) to get started.

## Gatekeeper API

There are three types of requests sent to The Gatekeeper: `Auth`, `Shell`, and `Exec`. The Gatekeeper will receive one request per invocation. The Gatekeeper should exit with status zero in nominal operation, even when rejecting requests. Exiting in a non-zero status code will cause sshenanigans to produce an error and reject the request.

### `Auth` requests

There are three types of `Auth` requests: `None`, `Password`, and `PublicKey`. For example,

```json
{
  "client_address": "127.0.0.1:50710",
  "request": {
    "Auth": {
      "username": "sam",
      "method": "None"
    }
  }
}
```

```json
{
  "client_address": "127.0.0.1:51591",
  "request": {
    "Auth": {
      "username": "sam",
      "method": { "Password": { "password": "topsecret" } }
    }
  }
}
```

```json
{
  "client_address": "127.0.0.1:51636",
  "request": {
    "Auth": {
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
```

Responses should either accept the reqeust or respond with a rejection and a set of suggested authentication methods:

```json
{ "accept": true }
```

```json
{ "accept": false, "proceed_with_methods": ["PASSWORD"] }
```

### `Shell` requests

This request is associated with the standard invocation of `ssh user@host`. Requests look like

```json
{
  "client_address": "127.0.0.1:51591",
  "request": { "Shell": { "username": "sam" } }
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
  "client_address": "127.0.0.1:56797",
  "request": {
    "Exec": {
      "username": "sam",
      "command": "ls -al"
    }
  }
}
```

And responses follow the same structure as for `Shell` requests.

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
