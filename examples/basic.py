#!/usr/bin/env python3

import json
import os
import sys

# The Gatekeeper is a call/response executable that modulates sshenanigans
# behavior, enabling you to build the SSH server of your dreams. This script is
# a demo Gatekeeper implementation.
#
# When an SSH request is received, sshenanigans will spawn a Gatekeeper process
# and send it a JSON request over stdin. The Gatekeeper is expected to respond
# with a JSON response over stdout and exit with a zero status code in nominal
# execution.

# Let's start by reading the JSON request from stdin.
message = json.loads(input())
request = message["request"]

# We'll print the incoming request to stderr for debugging purposes. This stderr
# will be ignored by sshenanigans, and printed to the same terminal that
# sshenanigans is running in.
#
# NOTE: Do _not_ do this production since it will contain passwords!
print(message, file=sys.stderr)

respond = lambda x: print(json.dumps(x))

# There are 3 types of requests that can be received by The Gatekeeper:
#   * Auth  -- Sent when a client attempts to authenticate.
#   * Shell -- After successful Auth, sent when a client runs eg `ssh user@host`.
#   * Exec  -- After successful Auth, sent when a client runs eg `ssh user@host ls -al`
#
# Depending on how The Gatekeeper responds, sshenanigans all accept/reject
# connections, execute commands, or start shells.
#
# You can read the full spec for the Gatekeeper protocol in `src/lib.rs`.
if "Auth" in request:
  # A new client has connected and is attempting to authenticate. You are free
  # to implement whatever logic you'd like here: check their public key against
  # ~/authorized_keys, consult your org's employee database, send a 2FA request,
  # flip a coin, launch a rocket, etc.
  #
  # Example requests:
  #   - {'client_address': '127.0.0.1:63895', 'client_id': '62783347-a23f-42d6-b05b-0c107384f583', 'request': {'Auth': {'unverified_credentials': {'username': 'sam', 'method': 'None'}}}}
  #   - {'client_address': '127.0.0.1:63895', 'client_id': '62783347-a23f-42d6-b05b-0c107384f583', 'request': {'Auth': {'unverified_credentials': {'username': 'sam', 'method': {'Password': {'password': 'topsecret'}}}}}}
  #   - {'client_address': '127.0.0.1:63895', 'client_id': '62783347-a23f-42d6-b05b-0c107384f583', 'request': {'Auth': {'unverified_credentials': {'username': 'sam', 'method': {'PublicKey': {'public_key_algorithm': 'ssh-ed25519', 'public_key_base64': 'AAA...wLq'}}}}}}

  # A username will always be provided, regardless of the authentication method:
  unverified_credentials = request["Auth"]["unverified_credentials"]
  username = unverified_credentials["username"]
  method = unverified_credentials["method"]

  # There are 3 types of authentication methods that can be used: "None",
  # "Password", and "PublicKey". For the purposes of this demo, we'll only allow
  # the "Password" method.
  password = "Password" in method and method["Password"]["password"]
  if username == "sam" and password == "topsecret":
    respond({ "accept": True })
  else:
    respond({ "accept": False, "proceed_with_methods": ["PASSWORD"] })

elif "Shell" in request:
  # `ssh user@host`
  #
  # In this case the client has successfully authenticated and is now asking for
  # a shell. You are free to accept or reject this request, and pick what
  # process is run. For example, if you wanted to implement an ssh game like
  # https://github.com/ajeetdsouza/clidle, you could accept the request and run
  # your CLI game of choice.
  #
  # Example: {'client_address': '127.0.0.1:63895', 'client_id': '62783347-a23f-42d6-b05b-0c107384f583', 'request': {'Shell': {'verified_credentials': {'username': 'sam', 'method': {'Password': {'password': 'topsecret'}}}}}}

  # Note that we run with the same uid/gid as the current process. You should
  # modify this to suit your needs, and probably run as a non-root user.
  respond({
    "accept": {
      "command": "/bin/bash",
      "arguments": [],
      "working_directory": "/",
      "uid": os.getuid(),
      "gid": os.getgid()
    }
  })

elif "Exec" in request:
  # `ssh user@host cmd arg0 arg1`
  #
  # Ok, so the client has successfully authenticated and is now attempting to
  # execute a command.
  #
  # Example: {'client_address': '127.0.0.1:63982', 'client_id': '26fff0f2-b747-46f8-b65a-59af30897eea', 'request': {'Exec': {'verified_credentials': {'username': 'sam', 'method': {'Password': {'password': 'topsecret'}}}, 'command': 'ls -al'}}}

  # Let's get the command and arguments that the client is attempting to run:
  cmd, *args = request["Exec"]["command"].split()

  # We'll only allow the client to run `ls`, and otherwise reject the request.
  if cmd == "ls":
    respond({
      "accept": {
        "command": cmd,
        "arguments": args,
        "working_directory": "/",
        "uid": os.getuid(),
        "gid": os.getgid()
      }
    })
  else:
    respond({})
