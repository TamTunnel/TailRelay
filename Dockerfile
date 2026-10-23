# ---- build ----
FROM golang:1.24-bookworm AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /tailrelay ./cmd/tailrelay

# ---- run ----
# Use the official Tailscale image as base: it ships a full Tailscale build
# with kernel (TUN) mode support. The static binaries from pkgs.tailscale.com
# are userspace-only, which breaks iptables forwarding + NAT for WireGuard
# client traffic (userspace netstack doesn't handle forwarded packets).
# TS_USERSPACE=false (set in entrypoint.sh) forces kernel mode.
# The container runs its OWN tailscaled in the same network namespace as
# WireGuard (tailguard-style isolation): the host's Tailscale — if any — is
# never touched, and host routing is unaffected.
FROM tailscale/tailscale:stable
# Install WireGuard tools and iptables (Debian-based image).
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iptables wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/tailrelay /var/lib/tailscale /var/run/tailscale /etc/wireguard
COPY --from=build /tailrelay /usr/local/bin/tailrelay
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
