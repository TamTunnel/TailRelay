#!/bin/sh
# TailRelay container entrypoint: run our own tailscaled in this network
# namespace (tailguard-style isolation), then exec the Go binary.
#
# Env:
#   TS_AUTHKEY    one-time Tailscale login (auth key). If set and this node
#                 isn't already up, we run `tailscale up` automatically.
#                 Identity persists in /var/lib/tailscale (volume).
#   TS_HOSTNAME   tailnet hostname for `tailscale up` (default: tailrelay)
#   TS_EXTRA_ARGS extra args appended to `tailscale up` (e.g. "--ssh")
set -e

SOCK=/var/run/tailscale/tailscaled.sock
mkdir -p /var/lib/tailscale /var/run/tailscale

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
            # Note: tailscale up requires --authkey flag (TS_AUTHKEY env is
            # only honored by tailscaled, not the CLI). The key is one-time.
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

exec /usr/local/bin/tailrelay "$@"
