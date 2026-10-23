# Tailrelay

**Turn a cheap VPS into a WireGuard VPN server whose traffic rides your Tailscale network — managed from a tiny web UI.**

**[Live demo](https://tamtunnel.github.io/TailRelay/)** — screenshots of the real web UI, plus a [73-second explainer video](https://tamtunnel.github.io/TailRelay/#video).

## The problem, in plain language

You have devices that can't run Tailscale (a travel router, a smart TV, a friend's laptop, an IoT box) but they *can* run WireGuard. You also have a Tailscale tailnet with exit nodes in the places you want your traffic to come out of. Today there's no simple glue between the two: either you hand-edit `wg0.conf` files and fight iptables, or you run a heavyweight VPN product.

## The solution

Tailrelay runs on a VPS and does three small jobs:

1. **It's a WireGuard server.** It generates the server keys, hands each client the next free IP (from `10.7.0.0/24` by default), and gives you a `.conf` file plus a QR code per client. Presets for DNS, MTU and keepalive are tunable.
2. **It bridges into Tailscale.** Client traffic is NATed onto the tailnet interface, so WireGuard-only devices can reach your tailnet.
3. **It lets you pick a Tailscale exit node** from the web UI — so all that WireGuard traffic exits through whichever country/node you choose.

One static Go binary (~9 MB), no runtime, no database — state is a single JSON file. A web UI manages everything. It was inspired by [TailGuard](https://github.com/juhovh/tailguard) (which bridges an *existing* WireGuard network into Tailscale); Tailrelay goes the other direction and *creates* the WireGuard server.

## Quick start

### Prerequisites

- A Linux VPS (any distro with a modern kernel).
- **Kernel WireGuard** (`wireguard` kernel module) and the `wg`, `ip`, `iptables`, `sysctl` tools (`ip6tables` too if you keep the default dual-stack IPv6).
- Tailrelay enables `net.ipv4.ip_forward=1` itself on start, plus `net.ipv6.conf.all.forwarding=1` when the IPv6 pool is enabled.
- **Tailscale installed and logged in** on the VPS (`tailscaled` running). Tailrelay does not install Tailscale for you — installing it is distro-specific and privileged, so it stays out of scope. It *can* run `tailscale up --authkey=...` for you from the UI if you hand it a key.
- Root (or at least `NET_ADMIN`) — creating network interfaces and NAT rules requires it.

### Run it

```sh
# install the binary
sudo install -m 755 tailrelay /usr/local/bin/tailrelay

# first run creates /var/lib/tailrelay/state.json and brings up wg0
sudo tailrelay
```

Open the web UI at your VPS's tailnet IP, port 8080 — e.g. `http://100.64.0.5:8080`. By default Tailrelay binds **only** to the Tailscale interface, so your tailnet login *is* the authentication. No password needed.

Then: **Clients → Add client → scan the QR code** with the WireGuard app. Traffic from that client now flows `device → VPS (wg0) → tailnet → your chosen exit node`.

### systemd (recommended)

```sh
sudo cp deploy/tailrelay.service /etc/systemd/system/
sudo mkdir -p /etc/tailrelay
# optional: echo 'TR_ADMIN_PASSWORD=...' | sudo tee /etc/tailrelay/env
sudo systemctl enable --now tailrelay
```

### Docker

The container is a self-contained bridge appliance: it runs its **own**
`tailscaled` in the same network namespace as WireGuard (tailguard-style
isolation). The host does **not** need Tailscale installed, and the host's
network stack — including any host Tailscale — is never touched.

**Prerequisites:**
- Docker installed.
- A Tailscale auth key ([generate one](https://login.tailscale.com/admin/settings/keys)) — one time; the container's node identity persists in a volume. (Or skip it and log in from the web UI's Tailscale section.)
- UDP port `51820` (or your chosen WireGuard port) reachable from the internet — open it in your cloud firewall / security group (e.g. Oracle NSG).

**Quick start** (prebuilt image from GHCR):

```sh
docker pull ghcr.io/tamtunnel/tailrelay:latest

docker run -d --name tailrelay --restart unless-stopped \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -p 51820:51820/udp -p 8080:8080 \
  -v tailrelay-state:/var/lib/tailrelay \
  -v tailscale-state:/var/lib/tailscale \
  -e TS_AUTHKEY=tskey-auth-... \
  -e TR_ENDPOINT=$(curl -s api.ipify.org):51820 \
  ghcr.io/tamtunnel/tailrelay:latest
```

Then open the web UI at `http://<container-tailscale-ip>:8080` (shown in the
container log on startup, or `docker exec tailrelay tailscale ip -4`).

**With docker compose:**

```sh
# set TS_AUTHKEY in docker-compose.yml (or leave it out and use the web UI)
docker compose up -d
```

**Configuration** — environment variables:

| Variable | Default | Description |
|---|---|---|
| `TS_AUTHKEY` | *(none)* | Tailscale auth key for the container's own node; omit to log in via web UI |
| `TS_HOSTNAME` | `tailrelay` | Tailnet hostname for the container's node |
| `TR_PORT` | `8080` | Web UI port |
| `TR_BIND_ADDR` | `tailscale ip -4` (else `127.0.0.1`) | Web UI bind address |
| `TR_ADMIN_PASSWORD` | *(none)* | **Required** if binding beyond localhost/tailnet |
| `TR_ENDPOINT` | *(none)* | Public `IP:port` clients connect to (e.g. `203.0.113.1:51820`) |

**Updating:**

```sh
docker pull ghcr.io/tamtunnel/tailrelay:latest
docker stop tailrelay && docker rm tailrelay
# re-run the same docker run command above
```

Keys, settings, and the Tailscale node identity persist in the
`tailrelay-state` and `tailscale-state` volumes. The image bundles the latest
stable Tailscale at build time (rebuilt weekly by CI), and the dashboard
shows the running Tailscale version — `docker pull` is the whole update path.

**Notes:**
- Bridge networking + `NET_ADMIN`: the container owns its network namespace,
  so exit-node routing stays inside the container and can't fight the host.
- The old host-socket setup (mounting `/var/run/tailscale`) is gone; if
  you're migrating, remove the old container and its volumes are *not*
  reused — the container registers as a new tailnet node on first `TS_AUTHKEY`
  login.
- If `/usr/bin/tailscale` doesn't exist on your host, adjust the CLI mount path to wherever your `tailscale` binary lives (`which tailscale`).

See [Docker vs binary](#docker-vs-binary) below for the tradeoff. The compose file uses host networking and mounts the host's Tailscale socket plus the `tailscale` CLI.

## Configuration

Everything network-related lives in the web UI (Settings page). Process-level config is flags or env vars:

| Variable | Flag | Default | Description |
|---|---|---|---|
| `TR_BIND_ADDR` | `-bind` | `tailscale ip -4` (else `127.0.0.1`) | Web UI bind address |
| `TR_PORT` | `-port` | `8080` | Web UI port |
| `TR_ADMIN_PASSWORD` | `-password` | *(none)* | Admin password; **required** if binding beyond localhost/tailnet, otherwise the process refuses to start |
| `TR_STATE_PATH` | `-state` | `/var/lib/tailrelay/state.json` | State file (0600, holds private keys) |
| `TR_CONF_PATH` | `-conf` | `/etc/wireguard/wg0.conf` | Generated server config |
| `TR_IFACE` | `-iface` | `wg0` | WireGuard interface name |
| `TR_TAILSCALE_IFACE` | `-ts-iface` | `tailscale0` | Tailscale interface the NAT rules target; startup fails loudly if it doesn't exist |
| `TR_ENDPOINT` | `-endpoint` | *(none)* | Pre-seed the public endpoint on first run; skips the ipify.org auto-detection (see Privacy) |
| `TR_IPV6_POOL` | `-ipv6-pool` | random ULA `/64` | Pre-seed the IPv6 client pool on first run instead of generating one |
| `TR_TLS_CERT` | `-tls-cert` | *(none)* | TLS certificate file for the web UI (requires `TR_TLS_KEY`) |
| `TR_TLS_KEY` | `-tls-key` | *(none)* | TLS private key file for the web UI (requires `TR_TLS_CERT`) |

## Security

Threat model, plainly stated:

**The tailnet is the auth boundary (default mode).** Binding to the Tailscale interface means only devices on your tailnet can reach the UI — no password needed, tailnet identity is the gate. Consequence, by design: **any device on your tailnet can download every client's WireGuard private key** via the UI (`/conf/…`, `/qr/…`). If your tailnet includes devices you don't fully trust, don't use the default mode — bind `0.0.0.0` with `TR_ADMIN_PASSWORD` (mandatory; the process refuses to start without it) and put TLS in front (see below).

**Public binds need TLS.** Without it, the admin password and session cookie travel in cleartext HTTP. Either pass `-tls-cert`/`-tls-key` (or `TR_TLS_CERT`/`TR_TLS_KEY`) so Tailrelay serves HTTPS directly — session/CSRF cookies then carry the `Secure` attribute — or terminate TLS in a reverse proxy in front of it.

**Exit nodes never auto-switch.** A dead pinned exit node fails closed: Tailscale stops routing (it does not pick another node — `auto:any` is never offered in the picker), so WireGuard client traffic stops too. Recovery is manual: the dashboard shows a prominent warning banner naming the offline node, and you pick another one. Nodes are pinned by MagicDNS hostname, never by tailnet IP.

**Kill switch (default: on).** Setting *Kill Switch (Pause when Tailscale is down)* installs firewall rules that drop any WireGuard traffic not headed for the Tailscale interface (`-i wg0 ! -o tailscale0 -j DROP` in both `iptables` and `ip6tables`, appended after the relay ACCEPTs). If `tailscaled` itself crashes and `tailscale0` vanishes, client traffic is dropped — it can never fall through to the VPS's direct WAN and expose your real IP. `Apply` reconciles the rules from the setting on every run; turning the switch off removes them. The dashboard shows the live state:

| State | Meaning |
|---|---|
| `Active & tunneling` | Kill switch on, Tailscale healthy — traffic relaying |
| `Paused — Tailscale down` | Kill switch on, Tailscale down — traffic dropped, not leaked |
| `Kill switch off` | Switch disabled — traffic could leak via WAN if tailscaled crashes |

Other posture notes:

- With a password set: bcrypt-hashed (never stored), 12-hour session cookie (`HttpOnly`, `SameSite=Lax`, `Secure` under TLS), per-session CSRF tokens on every POST, login throttling (5 failures → exponential backoff per IP).
- Tailscale auth keys entered in the UI are passed once to `tailscale up` and never written to disk; failures show a generic message, never the raw CLI output. Caveat: the key travels on the command line, so it is briefly visible in the process list (`ps`) to local root while that command runs — unavoidable with the CLI.
- The state file (`state.json`) contains WireGuard private keys and is written atomically (temp file + rename) with mode `0600`.

## Architecture

```
                  ┌─────────────────────────────────────────┐
  WireGuard       │  VPS                                      │
  clients         │                                           │
   (phone,        │  wg0 ──NAT──▶ tailscale0 ─┐                │
   laptop, ...) ─▶│  10.7.0.1, fd..::1  ▲      │                │
                  │       │ tailrelay (Go, :8080)             │
                  │       │  - generates wg0.conf             │
                  │       │  - manages peers via wg setconf   │
                  │       │  - iptables/ip6tables MASQUERADE  │
                  └───────┼──────────────────────────────┼───┘
                          │                               │
                     tailnet                   chosen exit node
```

- **Single static binary** (`CGO_ENABLED=0`, ~9 MB). No wireguard-go vendored — it drives the kernel WireGuard module via the `wg`/`ip` CLI tools, which keeps the binary small and the datapath in the kernel where it's fast.
- **stdlib-first**: `net/http` + `html/template` with `//go:embed` templates, server-rendered pages, a pinch of vanilla JS (none, actually — plain forms). Only two external deps: `golang.org/x/crypto` (X25519 keygen with correct clamping, bcrypt) and `github.com/skip2/go-qrcode`.
- **State**: one JSON file, atomic writes, 0600. No database to back up — copy the file.
- **Idempotent apply**: every change (add/remove/rename client, settings save) rewrites `wg0.conf` and re-syncs peers with `wg setconf`, then re-asserts the iptables rules (checked with `-C` first, so re-applying is safe).
- **Tailscale bridge**: `tailscale status --json` for the dashboard, `tailscale exit-node list` for candidates, `tailscale set --exit-node=` to steer all relayed traffic. The desired exit node and advertised routes are re-asserted on startup.

Package layout:

```
cmd/tailrelay      main: config, first-run init, apply, serve
internal/config    flags/env, bind-address safety rules
internal/state     JSON store, atomic 0600 writes
internal/wg        keygen, config rendering, ip/wg/iptables orchestration
internal/ts        tailscale CLI wrapper (status, exit nodes, routes, up)
internal/web       handlers, templates, sessions, CSRF
```

## FAQ

**Do I need Docker?**
No. The binary + systemd unit is the primary, lightest path. Docker is provided for those who prefer containers — see below.

**How is this different from TailGuard?**
TailGuard connects an *existing* WireGuard network into your tailnet (you bring `wg0.conf`). Tailrelay *creates* the WireGuard server for you — key generation, client configs, QR codes — and bridges it into Tailscale. Different direction, complementary tools.

**Can WireGuard clients reach my tailnet devices, or only the exit node?**
Both. With an exit node selected, all client traffic exits through it (full tunnel). Without one, clients are NATed onto the tailnet and can reach tailnet IPs directly.

**Where are the private keys?**
`/var/lib/tailrelay/state.json` (0600) and the generated `/etc/wireguard/wg0.conf` (0600). Back up the state file and you can rebuild the server anywhere.

**What if I change the IP pool?**
You can't while clients exist — the UI refuses the change and tells you to remove them first. (Reason: the server would take `.1` of the new pool while clients kept stale IPs from the old one, silently breaking them.) Pick the pool before enrolling clients.

**Does it support IPv6 clients?**
Yes — dual-stack is the default (WG Easy-style). On first run Tailrelay generates a random ULA `/64` (e.g. `fd12:3456:789a::/64`), the server takes `::1`, clients get `::2`, `::3`…, and the default client `AllowedIPs` is `0.0.0.0/0, ::/0`. NAT (`ip6tables` MASQUERADE) and the kill-switch DROP cover both families. To run IPv4-only, clear the IPv6 pool field in Settings (the UI also normalizes the default `AllowedIPs` back to `0.0.0.0/0` for you — leaving `::/0` with no v6 pool would blackhole client IPv6 traffic). The v6 pool, like the v4 pool, can't be changed while clients exist.

**How do I update?**
Replace the binary, `systemctl restart tailrelay`. State and `wg0.conf` are preserved; the interface is re-applied on start.

## Docker vs binary

We ship both, but they aren't equal:

| | Binary + systemd | Docker |
|---|---|---|
| Overhead | none | container runtime, image pull |
| Needs | root once at install | `NET_ADMIN`, host networking, `/dev/net/tun`, Tailscale socket + CLI mounts |
| Tailscale access | native (host `tailscaled`) | via mounted `/var/run/tailscale/` dir |
| Best for | a VPS you control | fleets / immutable infra |

Honest take: on a single VPS, the binary is simpler and lighter — Docker buys you nothing except packaging familiarity, while adding socket-mount fragility. Use Docker if your workflow is already container-based; otherwise take the binary.

## Tailscale prerequisite

Tailrelay assumes `tailscaled` is **already installed and (usually) logged in** on the VPS:

```sh
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

If it's installed but not logged in, the dashboard offers a `tailscale up` form — paste an auth key (from https://login.tailscale.com/admin/settings/keys), and Tailrelay runs `tailscale up --authkey=...` once. The key is never stored.

Why not install Tailscale automatically? Installing a privileged network daemon is distro-specific (apt/dnf/pacman/apk…) and a security-sensitive step that should be a conscious admin decision, not a side effect of starting a web UI. Out of scope by design.

## Privacy

On first run only, Tailrelay makes one outbound HTTPS request to `https://api.ipify.org` to auto-detect the VPS's public IPv4 and pre-fill the client endpoint. That's the only network call it ever makes on its own — no telemetry, no update checks.

To skip it entirely, set `TR_ENDPOINT` (or `-endpoint`) to your public `host[:port]` before the first start; the lookup is then never made. You can also just clear or override the endpoint in Settings at any time.

## Building from source

```sh
go build -o tailrelay ./cmd/tailrelay
go test ./...
```

Requires Go 1.24+. `gofmt`/`go vet` clean is enforced.

## License

Apache-2.0 — see [LICENSE](LICENSE). Inspiration credit in [NOTICE](NOTICE).
