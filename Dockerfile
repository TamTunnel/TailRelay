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
# Alpine, kept lean. The container runs its OWN tailscaled in the same
# network namespace as WireGuard (tailguard-style isolation): the host's
# Tailscale — if any — is never touched, and host routing is unaffected.
# Tailscale is fetched as a static build from the official stable channel
# at image build time (no version pinning); weekly CI rebuilds keep it
# current. `docker pull` is the update path.
FROM alpine:3.21
ARG TARGETARCH
RUN apk add --no-cache ca-certificates iproute2 iptables wireguard-tools curl \
 && TS_VERSION=$(curl -fsSL https://pkgs.tailscale.com/stable/ \
      | grep -oE 'tailscale_[0-9]+\.[0-9]+\.[0-9]+_' \
      | sed 's/^tailscale_//; s/_$//' | sort -uV | tail -1) \
 && echo "Installing Tailscale ${TS_VERSION} for ${TARGETARCH}" \
 && curl -fsSL "https://pkgs.tailscale.com/stable/tailscale_${TS_VERSION}_${TARGETARCH}.tgz" \
      | tar -xz -C /tmp \
 && mv "/tmp/tailscale_${TS_VERSION}_${TARGETARCH}/tailscale" /usr/local/bin/tailscale \
 && mv "/tmp/tailscale_${TS_VERSION}_${TARGETARCH}/tailscaled" /usr/local/bin/tailscaled \
 && rm -rf "/tmp/tailscale_${TS_VERSION}_${TARGETARCH}" \
 && apk del curl \
 && mkdir -p /var/lib/tailrelay /var/lib/tailscale /var/run/tailscale /etc/wireguard
COPY --from=build /tailrelay /usr/local/bin/tailrelay
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
