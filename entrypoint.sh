#!/bin/sh
# TailRelay container entrypoint: run Tailscale via containerboot (official
# Tailscale container init) for proper kernel-mode networking, then exec
# the Go binary.
#
# Why containerboot? Running `tailscaled` directly ignores TS_USERSPACE
# (it's only read by containerboot), so it defaults to userspace WireGuard
# which doesn't handle kernel-forwarded + NATed packets (our WireGuard
# clients via exit node). Containerboot honors TS_USERSPACE=false and sets
# up kernel (TUN) mode correctly.
#
# TUN detection: if /dev/net/tun is unavailable (e.g. CI smoke test),
# skip Tailscale entirely — the Go binary still starts and serves the UI.
#
# Env (passed through to containerboot):
#   TS_AUTHKEY    one-time Tailscale auth key. Persists in /var/lib/tailscale.
#   TS_HOSTNAME   tailnet hostname (default: tailrelay)
#   TS_EXTRA_ARGS extra args for `tailscale set`
#   TS_USERSPACE  "false" (default) for kernel mode; "true" forces userspace.
set -e

SOCK=/var/run/tailscale/tailscaled.sock
mkdir -p /var/lib/tailscale /var/run/tailscale

if [ -c /dev/net/tun ]; then
    echo "entrypoint: TUN available, starting Tailscale via containerboot"
    export TS_STATE_DIR=/var/lib/tailscale
    export TS_SOCKET="$SOCK"
    export TS_USERSPACE="${TS_USERSPACE:-false}"
    # TS_AUTHKEY, TS_HOSTNAME, TS_EXTRA_ARGS pass through to containerboot
    /usr/local/bin/containerboot &
    CB_PID=$!
    # Bounded wait for socket
    for i in $(seq 1 50); do
        if [ -S "$SOCK" ]; then
            break
        fi
        if ! kill -0 "$CB_PID" 2>/dev/null; then
            break
        fi
        sleep 0.2
    done
    if [ -S "$SOCK" ]; then
        echo "entrypoint: tailscaled socket ready"
    else
        echo "entrypoint: warning: tailscaled socket not available; starting web UI anyway"
    fi
    # Bounded wait for Tailscale IPv4 (so Go binds tailnet IP, not 127.0.0.1).
    # Each `tailscale ip` call has its own timeout so a missing socket
    # doesn't hang the loop forever (containerboot failure case).
    for i in $(seq 1 30); do
        if [ -n "$(timeout 2 tailscale ip -4 2>/dev/null)" ]; then
            break
        fi
        sleep 1
    done
else
    echo "entrypoint: no /dev/net/tun, skipping Tailscale (CI smoke test mode)"
fi

exec /usr/local/bin/tailrelay "$@"
