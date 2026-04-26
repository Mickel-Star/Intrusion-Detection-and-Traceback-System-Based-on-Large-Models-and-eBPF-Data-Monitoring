#!/usr/bin/env bash
set -euo pipefail

if ! command -v unshare >/dev/null 2>&1; then
  echo "error: unshare is required" >&2
  exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "error: ip is required" >&2
  exit 1
fi

# This creates a private network namespace with a tun device for experiments.
# It does not provide upstream connectivity on its own, so it is not the
# right launcher for Codex traffic unless another tunnel/proxy is attached.
# Reuse the repo's existing proxy wiring when a local proxy port is supplied.
if [ -z "${HTTPS_PROXY:-}" ] && [ -n "${PROXY_PORT:-}" ]; then
  export HTTP_PROXY="http://127.0.0.1:${PROXY_PORT}"
  export HTTPS_PROXY="http://127.0.0.1:${PROXY_PORT}"
  export ALL_PROXY="http://127.0.0.1:${PROXY_PORT}"
fi

if [ "$#" -eq 0 ]; then
  set -- bash
fi

exec unshare --user --map-root-user --mount --net --fork \
  bash -c '
    set -euo pipefail

    # /dev/net/tun is required for tuntap creation in the namespace.
    if [ ! -e /dev/net/tun ]; then
      mkdir -p /dev/net
      mknod /dev/net/tun c 10 200
      chmod 666 /dev/net/tun
    fi

    if ! ip link show tun0 >/dev/null 2>&1; then
      ip tuntap add dev tun0 mode tun
      ip link set tun0 up
    fi

    exec "$@"
  ' bash "$@"
