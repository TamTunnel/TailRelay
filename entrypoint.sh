#!/bin/sh
# TailRelay container entrypoint: run Tailscale via containerboot (official
# Tailscale container init) for proper kernel-mode networking, then exec
# the Go binary.
#
# Why containerboot? Running `tailscaled` directly defaults to userspace
# WireGuard (wireguard-go), which doesn't handle kernel-forwarded + NATed
# packets (our WireGuard clients via exit node). Containerboot honors
# TS_USERSPACE=false and sets up kernel (TUN) mode correctly.
#
# Env:
#   TS_AUTHKEY    one-time Tailscale auth key. If set and not already logged
#                 in, containerboot logs in automatically. Persists in
#                 /var/lib/tailscale (volume).
#   TS_HOSTNAME   tailnet hostname (default: tailrelay)
#   TS_EXTRA_ARGS extra args for `tailscale set` (e.g. "--ssh")
#   TS_USERSPACE  set to "false" for kernel mode (default; required for
#                 forwarding). Set to "true" to force userspace.
set -e

export TS_STATE_DIR=/var/lib/tailscale
export TS_SOCKET=/var/run/tailscale/tailscaled.sock
# Kernel mode is REQUIRED for iptables forwarding + NAT of WireGuard client
# traffic (userspace netstack doesn't handle forwarded packets). This is
# the default; set TS_USERSPACE=true to override.
export TS_USERSPACE="${TS_USERSPACE:-false}"

mkdir -p /var/lib/tailscale /var/run/tailscale

# Start containerboot in the background. It starts tailscaled, handles
# auth, and configures kernel mode. If it fails, the Go binary still comes
# up and the UI reports Tailscale as unreachable.
/usr/local/bin/containerboot &
CONTAINERBOOT_PID=$!

# Wait for the control socket (bounded; warn and continue without it).
SOCK="$TS_SOCKET"
for i in $(seq 1 50); do
    if [ -S "$SOCK" ]; then
        break
    fi
    if ! kill -0 "$CONTAINERBOOT_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if [ -S "$SOCK" ]; then
    echo "entrypoint: tailscaled socket ready"
else
    echo "entrypoint: warning: tailscaled socket not available; starting web UI anyway"
fi

# Wait for Tailscale to have an IPv4 (bounded) so the Go binary binds to the
# tailnet IP, not 127.0.0.1.
for i in $(seq 1 30); do
    if [ -n "$(tailscale ip -4 2>/dev/null)" ]; then
        break
    fi
    sleep 1
done

exec /usr/local/bin/tailrelay "$@"
