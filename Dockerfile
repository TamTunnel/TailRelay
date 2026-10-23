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
# Pinned Tailscale version + SHA256. Bump both together; the weekly rebuild
# workflow verifies the hash and fails the build on mismatch. (Upstream
# publishes no checksum files, so these were computed from a trusted
# download; treat a mismatch as a supply-chain red flag, not a typo.)
ARG TS_VERSION=1.104.2
ARG TS_SHA256_AMD64=512f613ed7d04fc7282f7dc5bd76aa105aae28168fbb9357eb749ebcbc29f0ae
ARG TS_SHA256_ARM64=5776aaa901b5ef1916e66be5bb54b9f481cd399c9c28db123a8cab620efa237b
RUN apk add --no-cache ca-certificates iproute2 iptables wireguard-tools curl \
 && echo "Installing Tailscale ${TS_VERSION} for ${TARGETARCH}" \
 && curl -fsSL "https://pkgs.tailscale.com/stable/tailscale_${TS_VERSION}_${TARGETARCH}.tgz" -o /tmp/ts.tgz \
 && case "${TARGETARCH}" in \
      amd64) echo "${TS_SHA256_AMD64}  /tmp/ts.tgz" | sha256sum -c - ;; \
      arm64) echo "${TS_SHA256_ARM64}  /tmp/ts.tgz" | sha256sum -c - ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && tar -xz -C /tmp -f /tmp/ts.tgz \
 && mv "/tmp/tailscale_${TS_VERSION}_${TARGETARCH}/tailscale" /usr/local/bin/tailscale \
 && mv "/tmp/tailscale_${TS_VERSION}_${TARGETARCH}/tailscaled" /usr/local/bin/tailscaled \
 && rm -rf "/tmp/tailscale_${TS_VERSION}_${TARGETARCH}" /tmp/ts.tgz \
 && apk del curl \
 && mkdir -p /var/lib/tailrelay /var/lib/tailscale /var/run/tailscale /etc/wireguard
COPY --from=build /tailrelay /usr/local/bin/tailrelay
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
