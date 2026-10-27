# Tailrelay

**Turn a cheap VPS into a WireGuard VPN server whose traffic rides your Tailscale network — managed from a tiny web UI.**

**[Live demo](https://tamtunnel.github.io/TailRelay/)** — screenshots of the real web UI, plus a [73-second explainer video](https://tamtunnel.github.io/TailRelay/#video).

## The problem, in plain language

You have devices that can't run Tailscale (a travel router, a smart TV, a friend's laptop, an IoT box) but they *can* run WireGuard. You also have a Tailscale tailnet with exit nodes in the places you want your traffic to come out of. Today there's no simple glue between the two: either you hand-edit `wg0.conf` files and fight iptables, or you run a heavyweight VPN product.

## The solution

Tailrelay runs on a VPS and does three small jobs:

1. **It's a WireGuard server.** It generates the server keys, hands each client the next free IP (from `10.7.0.0/24` by default), and gives you a `.conf` file plus a QR code per client. Presets for DNS, MTU and keepalive are tunable.
2. **It bridges into Tailscale.** Client traffic is NATed onto the tailnet interface, so WireGuard-only devices can reach your tailnet.
3. **It lets you pick a Tailscale exit node** from the web UI — so all that WireGuard traffic exits through whichever country/node you choose. Or pick direct mode and traffic exits via the VPS itself.

One static Go binary (~14 MB), no runtime, no database — state is a single JSON file. A web UI manages everything. It was inspired by [TailGuard](https://github.com/juhovh/tailguard) (which bridges an *existing* WireGuard network into Tailscale); Tailrelay goes the other direction and *creates* the WireGuard server.

## Quick start

### Prerequisites

- A Linux VPS (any distro with a modern kernel).
- **Kernel WireGuard** (`wireguard` kernel module) and the `wg`, `ip`, `iptables`, `sysctl` tools (`ip6tables` too if you keep the default dual-stack IPv6).
- **Tailscale installed and logged in** on the VPS (`tailscaled` running, kernel mode). Tailrelay does not install Tailscale for you — installing it is distro-specific and privileged, so it stays out of scope. It *can* run `tailscale up --authkey=...` for you from the UI if you hand it a key.
- Root — creating network interfaces and NAT rules requires it.
- **UDP port 51820** (or your chosen WireGuard port) reachable from the internet — open it in your cloud firewall / security group (e.g. Oracle NSG, AWS Security Group). This is the one firewall rule TailRelay cannot add for you, because it lives outside the host.

### Install

```sh
# 1. Install Tailscale (if not already installed)
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# 2. Install WireGuard tools (if not already installed)
# Ubuntu/Debian: sudo apt install wireguard-tools
# Fedora: sudo dnf install wireguard-tools
# Arch: sudo pacman -S wireguard-tools

# 3. Install TailRelay
sudo install -m 755 tailrelay /usr/local/bin/tailrelay
sudo cp deploy/tailrelay.service /etc/systemd/system/
sudo systemctl enable --now tailrelay
```

That's it. TailRelay creates `/var/lib/tailrelay/state.json` on first run, brings up `wg0`, and sets up all firewall rules automatically (see [Firewall rules](#firewall-rules) below).

### Use it

Open the web UI at your VPS's tailnet IP, port 8080 — e.g. `http://100.100.20.5:8080`. By default TailRelay binds **only** to the Tailscale interface, so your tailnet login *is* the authentication. No password needed.

Then: **Clients → Add client → scan the QR code** with the WireGuard app. Traffic from that client now flows:

- **Exit node mode:** `device → VPS (wg0) → tailnet → your chosen exit node → internet`
- **Direct mode:** `device → VPS (wg0) → VPS WAN → internet`

Pick the mode in the dashboard: select an exit node from the list, or "No exit node (direct)".

### If you're behind 1:1 NAT (e.g. Digital Ocean/AWS/Oracle Cloud)

If your VPS has a private IP (e.g. `10.0.0.50`) NATed to a public IP (e.g. `202.19.29.40`), set the public endpoint before first run so client configs use the right address:

```sh
# Option 1: env file (recommended with systemd)
echo 'TR_ENDPOINT=202.19.29.40:51820' | sudo tee /etc/tailrelay/env
sudo systemctl restart tailrelay

# Option 2: flag
sudo TR_ENDPOINT=202.19.29.40:51820 tailrelay
```

Without this, TailRelay auto-detects via `api.ipify.org` on first run only (see [Privacy](#privacy)).

## Firewall rules

TailRelay sets up **all host firewall rules automatically** on startup and on every Apply. You never need to touch iptables manually.

### What TailRelay adds

| Rule | Purpose |
|---|---|
| `sysctl net.ipv4.ip_forward=1` | Enable IPv4 forwarding |
| `sysctl net.ipv6.conf.all.forwarding=1` | Enable IPv6 forwarding (if v6 pool enabled) |
| `INPUT -p udp --dport 51820 -j ACCEPT` | Allow WireGuard handshakes (inserted at top, beats host REJECT-all) |
| `FORWARD -i wg0 -o tailscale0 -j ACCEPT` | Client → tailnet (exit mode) |
| `FORWARD -i tailscale0 -o wg0 --ctstate RELATED,ESTABLISHED -j ACCEPT` | Return traffic (exit mode) |
| `FORWARD -i wg0 -o <WAN> -j ACCEPT` | Client → WAN (direct mode) |
| `FORWARD -i <WAN> -o wg0 --ctstate RELATED,ESTABLISHED -j ACCEPT` | Return traffic (direct mode) |
| `POSTROUTING -s 10.7.0.0/24 -o tailscale0 -j MASQUERADE` | NAT client traffic to tailnet IP (exit mode) |
| `POSTROUTING -s 10.7.0.0/24 -o <WAN> -j MASQUERADE` | NAT client traffic to WAN IP (direct mode) |
| `FORWARD -i wg0 ! -o tailscale0 -j DROP` | Kill switch (exit mode only, inserted at top) |
| `ip rule: to 10.7.0.0/24 lookup main pref 5268` | Route return traffic to wg0, not back to exit node |
| `ip rule: fwmark <port> lookup main pref 5269` | WireGuard handshakes bypass exit node |

The same rules exist for IPv6 (`ip6tables`) when the v6 pool is enabled.

### What you must do manually

Only one thing: **open UDP 51820 in your cloud firewall** (Oracle NSG, AWS Security Group, GCP Firewall, etc.). TailRelay cannot do this because it lives outside the host. Everything else is automatic.

### Rule reconciliation

On every startup and every Apply (settings save, exit-node change, client add/remove), TailRelay re-asserts all rules from state and removes stale rules from the previous mode. Switching between exit-node and direct mode cleanly swaps the rule sets — no leftovers, no leaks.

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

**No IP leaks.** The kill switch (default: on) installs firewall rules that drop any WireGuard traffic not headed for the Tailscale interface (`-i wg0 ! -o tailscale0 -j DROP` in both `iptables` and `ip6tables`, inserted at the top of FORWARD). If `tailscaled` crashes and `tailscale0` vanishes, client traffic is dropped — it can never fall through to the VPS's direct WAN and expose your real IP. DNS goes via the tunnel (client DNS `1.1.1.1` with full-tunnel `AllowedIPs`), so queries exit via the exit node, never via the client's ISP. Cloud metadata endpoints (`169.254.169.254`, `169.254.0.0/16`) are blocked in FORWARD in both modes, so WG clients can't harvest instance credentials.

**WG clients are trusted.** Two trust equivalences to understand:
- **Dashboard:** WG clients cannot reach the dashboard — TailRelay drops `wg0 → dashboard port` traffic in INPUT. Only tailnet devices (not WG clients) can administer TailRelay. But in password-less mode, *any tailnet device* is a full admin (can download all client keys, change exit nodes, re-auth Tailscale). If your tailnet includes devices you don't fully trust, set `TR_ADMIN_PASSWORD`.
- **Tailnet access:** WG→tailnet traffic is MASQUERADEd, so to tailnet devices it appears sourced from the VPS node itself. Tailscale ACLs see the VPS node, never the individual WG client. A WG client can therefore reach anything the VPS can reach on the tailnet. Treat WG clients as fully trusted tailnet members. There is no per-client tailnet ACL, and WG clients can reach each other by default (no inter-client isolation) — suitable for personal/family use, not multi-tenant setups.

**Traffic looks normal.** WireGuard MTU 1420 is inside the encrypted tunnel (not visible to the internet). Egress from the exit node uses the exit node's standard MTU and networking — no Tailscale headers, no VPN signatures, no fixed TCPMSS values. The internet sees plain traffic from the exit node's IP. One known weak signal: client TCP MSS ≈ 1380 (from MTU 1420) instead of the typical 1460 — detectable as an anomaly but not a definitive VPN identifier, and it reveals nothing about the client's real IP.

**Exit nodes never auto-switch.** A dead pinned exit node fails closed: Tailscale stops routing (it does not pick another node — `auto:any` is never offered in the picker), so WireGuard client traffic stops too. Recovery is manual: the dashboard shows a prominent warning banner naming the offline node, and you pick another one. Nodes are pinned by MagicDNS hostname, never by tailnet IP.

**Kill switch states.** The dashboard shows the live state:

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
  WireGuard       │  VPS (host deployment)                    │
  clients         │                                           │
   (phone,        │  wg0 ──NAT──▶ tailscale0 ─┐                │
   laptop, ...) ─▶│  10.7.0.1, fd..::1  ▲      │                │
                  │       │ tailrelay (Go, :8080)             │
                  │       │  - generates wg0.conf             │
                  │       │  - manages peers via wg setconf   │
                  │       │  - iptables/ip6tables MASQUERADE  │
                  │       │  - ip rules 5268/5269 for routing │
                  └───────┼──────────────────────────────┼───┘
                          │                               │
                     tailnet                   chosen exit node
                                               (or direct WAN)
```

- **Single static binary** (`CGO_ENABLED=0`, ~14 MB). No wireguard-go vendored — it drives the kernel WireGuard module via the `wg`/`ip` CLI tools, which keeps the binary small and the datapath in the kernel where it's fast. Host Tailscale runs in kernel mode too, so forwarded traffic uses full kernel conntrack/NAT.
- **stdlib-first**: `net/http` + `html/template` with `//go:embed` templates, server-rendered pages, plain forms. Only two external deps: `golang.org/x/crypto` (X25519 keygen with correct clamping, bcrypt) and `github.com/skip2/go-qrcode`.
- **State**: one JSON file, atomic writes, 0600. No database to back up — copy the file.
- **Idempotent apply**: every change (add/remove/rename client, settings save, exit-node switch) rewrites `wg0.conf` and re-syncs peers with `wg setconf`, then re-asserts the iptables rules (checked with `-C` first, so re-applying is safe) and removes stale rules from the previous mode.
- **Tailscale bridge**: `tailscale status --json` for the dashboard, `tailscale exit-node list` for candidates, `tailscale set --exit-node=` to steer all relayed traffic. The desired exit node and advertised routes are re-asserted on startup.
- **Routing**: two `ip rule` entries make exit-node mode work. Pref 5269 sends WireGuard's own traffic (handshakes, marked with the listen-port fwmark) via the main table, bypassing Tailscale's exit-node table 52. Pref 5268 sends de-NATed return traffic (dst = client pool) via the main table, so it reaches `wg0` instead of looping back to the exit node.

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

**How is this different from TailGuard?**
TailGuard connects an *existing* WireGuard network into your tailnet (you bring `wg0.conf`). Tailrelay *creates* the WireGuard server for you — key generation, client configs, QR codes — and bridges it into Tailscale. Different direction, complementary tools.

**Can WireGuard clients reach my tailnet devices, or only the exit node?**
Both. With an exit node selected, all client traffic exits through it (full tunnel). Without one (direct mode), clients are NATed onto the tailnet and can reach tailnet IPs directly, and internet traffic exits via the VPS WAN.

**Where are the private keys?**
`/var/lib/tailrelay/state.json` (0600) and the generated `/etc/wireguard/wg0.conf` (0600). Back up the state file and you can rebuild the server anywhere.

**What if I change the IP pool?**
You can't while clients exist — the UI refuses the change and tells you to remove them first. (Reason: the server would take `.1` of the new pool while clients kept stale IPs from the old one, silently breaking them.) Pick the pool before enrolling clients.

**Does it support IPv6 clients?**
Yes — dual-stack is the default (WG Easy-style). On first run Tailrelay generates a random ULA `/64` (e.g. `fd12:3456:789a::/64`), the server takes `::1`, clients get `::2`, `::3`…, and the default client `AllowedIPs` is `0.0.0.0/0, ::/0`. NAT (`ip6tables` MASQUERADE) and the kill-switch DROP cover both families. To run IPv4-only, clear the IPv6 pool field in Settings (the UI also normalizes the default `AllowedIPs` back to `0.0.0.0/0` for you — leaving `::/0` with no v6 pool would blackhole client IPv6 traffic). The v6 pool, like the v4 pool, can't be changed while clients exist.

**How do I update?**
Replace the binary, `systemctl restart tailrelay`. State and `wg0.conf` are preserved; the interface and firewall rules are re-applied on start.

**What if my firewall rules get flushed?**
Restart TailRelay (`systemctl restart tailrelay`) or click Apply in Settings — both re-assert all rules from state.

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
