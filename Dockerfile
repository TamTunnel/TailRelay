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
# Use the official Tailscale image as base: it ships containerboot (the
# official container init) which honors TS_USERSPACE=false for kernel (TUN)
# mode. Running tailscaled directly ignores TS_USERSPACE and defaults to
# userspace WireGuard, which breaks forwarded + NATed WireGuard client
# traffic via exit nodes. Containerboot is required for the data path.
# Version pinned (not :stable) because containerboot behavior changes
# across releases; bump deliberately after testing.
FROM tailscale/tailscale:v1.104.2
# Alpine-based. Already ships iptables, iproute2, ca-certificates. Add
# wireguard-tools (for `wg` CLI) and tcpdump (for exit-node debugging).
RUN apk add --no-cache wireguard-tools tcpdump \
 && mkdir -p /var/lib/tailrelay /var/lib/tailscale /var/run/tailscale /etc/wireguard
COPY --from=build /tailrelay /usr/local/bin/tailrelay
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
