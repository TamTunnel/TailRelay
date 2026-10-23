#!/bin/sh
# TailRelay container entrypoint: run our own tailscaled in this network
# namespace (tailguard-style isolation), then exec the Go binary.
#
# Uses the official tailscale/tailscale:stable base image (Alpine) which
# ships a full Tailscale build. TS_USERSPACE=false requests kernel (TUN)
# mode instead of userspace netstack; kernel mode is required for iptables
# forwarding + NAT of WireGuard client traffic (userspace doesn't handle
# forwarded packets). If /dev/net/tun is unavailable (e.g. CI smoke test),
# tailscaled fails gracefully and the UI still comes up.
#
# Env:
#   TS_AUTHKEY    one-time Tailscale auth key. If set and not already logged
#                 in, we run `tailscale up` automatically. Persists in
#                 /var/lib/tailscale (volume).
#   TS_HOSTNAME   tailnet hostname (default: tailrelay)
#   TS_EXTRA_ARGS extra args for `tailscale up` (e.g. "--ssh")
#   TS_USERSPACE  "false" (default) for kernel mode; "true" forces userspace.
set -e

SOCK=/var/run/tailscale/tailscaled.sock
mkdir -p /var/lib/tailscale /var/run/tailscale

# Request kernel mode. Honored by tailscaled when /dev/net/tun is available.
export TS_USERSPACE="${TS_USERSPACE:-false}"

# Start tailscaled in the background. If it can't start (e.g. no
# /dev/net/tun in a smoke-test container), the Go binary still comes up
# and the UI reports Tailscale as unreachable — never fail the container.
tailscaled --state=/var/lib/tailscale/tailscaled.state --socket="$SOCK" &
TAILSCALED_PID=$!

# Wait for the control socket (bounded; warn and continue without it).
for i in $(seq 1 50); do
    if [ -S "$SOCK" ]; then
        break
    fi
    # tailscaled already gone? Don't wait out the full timeout.
    if ! kill -0 "$TAILSCALED_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if [ -S "$SOCK" ]; then
    if [ -n "$TS_AUTHKEY" ]; then
        if ! tailscale status --json 2>/dev/null | grep -q '"BackendState":"Running"'; then
            echo "entrypoint: tailscale up --hostname=${TS_HOSTNAME:-tailrelay}"
            # Non-fatal: a bad key must not crash-loop the container; the
            # web UI's Tailscale section offers manual login as fallback.
            # shellcheck disable=SC2086
            if ! tailscale up --authkey="$TS_AUTHKEY" \
                --hostname="${TS_HOSTNAME:-tailrelay}" \
                ${TS_EXTRA_ARGS}; then
                echo "entrypoint: warning: tailscale up failed; use the web UI to log in"
            fi
        else
            echo "entrypoint: tailscaled already running, skipping tailscale up"
        fi
    fi
else
    echo "entrypoint: warning: tailscaled socket not available; starting web UI anyway"
fi

# Wait for Tailscale to have an IPv4 (bounded) so the Go binary binds to the
# tailnet IP, not 127.0.0.1. The socket existing doesn't mean we're logged in.
for i in $(seq 1 30); do
    if [ -n "$(tailscale ip -4 2>/dev/null)" ]; then
        break
    fi
    sleep 1
done

exec /usr/local/bin/tailrelay "$@"
