#!/usr/bin/env bash
set -euo pipefail

# Launch Codex with a stable outbound path. This script does not create a
# separate network namespace; instead it forwards Codex through a proxy that
# already exists on the host or inside WSL.

if ! command -v codex >/dev/null 2>&1; then
  echo "error: codex is not installed or not on PATH" >&2
  exit 1
fi

if [ -z "${HTTP_PROXY:-}" ] && [ -z "${HTTPS_PROXY:-}" ] && [ -z "${ALL_PROXY:-}" ]; then
  if [ -n "${CODEX_PROXY_URL:-}" ]; then
    export HTTP_PROXY="${CODEX_PROXY_URL}"
    export HTTPS_PROXY="${CODEX_PROXY_URL}"
    export ALL_PROXY="${CODEX_PROXY_URL}"
  elif [ -n "${PROXY_PORT:-}" ]; then
    export HTTP_PROXY="http://127.0.0.1:${PROXY_PORT}"
    export HTTPS_PROXY="http://127.0.0.1:${PROXY_PORT}"
    export ALL_PROXY="http://127.0.0.1:${PROXY_PORT}"
  elif [ -n "${WSL_HOST_PROXY_PORT:-}" ]; then
    host_ip="$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')"
    if [ -z "${host_ip:-}" ] && [ -r /etc/resolv.conf ]; then
      host_ip="$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf)"
    fi
    if [ -z "${host_ip:-}" ]; then
      echo "error: unable to determine WSL host IP" >&2
      exit 1
    fi
    export HTTP_PROXY="http://${host_ip}:${WSL_HOST_PROXY_PORT}"
    export HTTPS_PROXY="http://${host_ip}:${WSL_HOST_PROXY_PORT}"
    export ALL_PROXY="http://${host_ip}:${WSL_HOST_PROXY_PORT}"
  fi
fi

# Keep local traffic local; only the Codex egress should traverse the proxy.
export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1,::1}"

exec codex "$@"
