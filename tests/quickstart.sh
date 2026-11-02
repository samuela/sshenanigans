#!/usr/bin/env bash
# End-to-end smoke test for the documented quickstart.
#
# This starts sshenanigans with `examples/basic.py` as the gatekeeper and drives
# a real `ssh` client through password authentication and a remote command. It is
# the only check that exercises the full stack (russh handler API, gatekeeper
# JSON protocol, child process plumbing and exit status reporting), which
# `nix build` and unit tests cannot see. Changes to the gatekeeper schema or to
# russh's handler API are expected to fail here.
#
# Requires Linux for `setsid`. The Nix dev shell provides all test tools.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for tool in cargo rustc python3 ssh ssh-keygen setsid timeout realpath; do
  if ! command -v "$tool" >/dev/null; then
    echo "missing required tool: $tool (run this from 'nix develop' on Linux)" >&2
    exit 1
  fi
done

# Report the effective toolchain and resolved caches before building so local
# runs and CI cannot silently use an unexpected private cache or compiler.
cargo_home="$(realpath -m "${CARGO_HOME:-$HOME/.cargo}")"
target_dir="$(realpath -m "${CARGO_TARGET_DIR:-$repo_root/target}")"
printf 'HOME=%s\nCARGO_HOME=%s\nCARGO_TARGET_DIR=%s\n' "$HOME" "$cargo_home" "$target_dir"
command -v cargo rustc
cargo --version
rustc --version

cargo build --locked --quiet
binary="$target_dir/debug/sshenanigans"

workdir="$(mktemp -d)"
server_pid=""

cleanup() {
  status=$?
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 ]]; then
    echo "--- server log ---" >&2
    cat "$workdir/server.log" >&2 || true
    echo "--- ssh output ---" >&2
    cat "$workdir/ssh.stdout" >&2 || true
    cat "$workdir/ssh.stderr" >&2 || true
  fi
  rm -rf "$workdir"
  exit "$status"
}
trap cleanup EXIT

ssh-keygen -q -N '' -t ed25519 -f "$workdir/hostkey"

# Ask the kernel for an unused loopback port. There is a small race between
# closing the probe socket and the server binding it, which is acceptable for a
# smoke test.
port="$(python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

"$binary" \
  --host-key-path="$workdir/hostkey" \
  --listen="127.0.0.1:$port" \
  --gatekeeper="python3 $repo_root/examples/basic.py" \
  >"$workdir/server.log" 2>&1 &
server_pid=$!

# Wait for the listening socket to accept connections.
ready=""
for _ in $(seq 1 100); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    exec 3>&- 3<&-
    ready="yes"
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "server exited before accepting connections" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ -z "$ready" ]]; then
  echo "server did not start listening on port $port" >&2
  exit 1
fi

# Answer the password prompt non-interactively. `SSH_ASKPASS_REQUIRE=force` and
# `setsid` make ssh use the helper even though the test has no controlling
# terminal. The password matches the one hardcoded in examples/basic.py.
printf '#!/bin/sh\necho topsecret\n' >"$workdir/askpass"
chmod +x "$workdir/askpass"

ssh_options=(
  -p "$port"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o NumberOfPasswordPrompts=1
)

set +e
output="$(
  SSH_ASKPASS="$workdir/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
    setsid timeout 30 ssh "${ssh_options[@]}" sam@127.0.0.1 ls \
    2>"$workdir/ssh.stderr"
)"
status=$?
set -e
printf '%s\n' "$output" >"$workdir/ssh.stdout"

if [[ $status -ne 0 ]]; then
  echo "ssh exited with status $status" >&2
  exit 1
fi

# `examples/basic.py` runs the accepted command with working directory `/`, so a
# listing of the root directory proves the command actually executed and its
# stdout reached the client.
if ! grep -qx 'tmp' <<<"$output"; then
  echo "expected 'ls' to list the root directory, got:" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

# The server must still be running: a gatekeeper schema or handler panic would
# have killed the connection task at best and the process at worst.
if ! kill -0 "$server_pid" 2>/dev/null; then
  echo "server exited during the test" >&2
  exit 1
fi

# The headline quickstart flow: `ssh -t user@host` opens a shell. This exercises
# the PTY path, which the exec check above does not.
set +e
shell_output="$(
  # Keep the marker out of the input: terminal echo must not satisfy the check.
  printf '%s\n' "printf '%s%s\\n' SHELL_ OK" exit |
    SSH_ASKPASS="$workdir/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
      setsid timeout 30 ssh -tt "${ssh_options[@]}" sam@127.0.0.1 \
      2>>"$workdir/ssh.stderr"
)"
status=$?
set -e
if [[ $status -ne 0 ]]; then
  echo "interactive shell ssh exited with status $status" >&2
  exit 1
fi
if ! grep -q 'SHELL_OK' <<<"$shell_output"; then
  echo "interactive shell did not produce the expected output, got:" >&2
  printf '%s\n' "$shell_output" >&2
  exit 1
fi

echo "quickstart e2e: ok"
