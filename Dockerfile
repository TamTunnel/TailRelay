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
# alpine: tiny base with a package manager for the runtime tools tailrelay
# shells out to (wg, ip, iptables). tailscaled itself runs on the HOST;
# the container talks to it via the mounted socket + tailscale CLI.
FROM alpine:3.21
RUN apk add --no-cache wireguard-tools iproute2 iptables ca-certificates \
    && mkdir -p /var/lib/tailrelay /etc/wireguard
COPY --from=build /tailrelay /usr/local/bin/tailrelay
# tailscale CLI is mounted from the host at runtime (see docker-compose.yml)
# so the version always matches the host's tailscaled.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/tailrelay"]
