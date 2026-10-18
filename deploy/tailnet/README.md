# Deploy the session-balanced fork on a tailnet

Use one Linux hosting machine for Nginx and one gateway process. Your Linux and Windows machines build/test or use the dashboard over the tailnet. They do not run additional production gateways against the same credential directory.

```
Linux + Windows clients ── Tailscale HTTPS ── host Nginx ── 127.0.0.1:8317
                                                         gateway + management.html
                                                         persistent auths + pins
```

Choose **Docker Compose** for the simplest first installation. The native systemd option has the same network layout. These are deployment templates, not an executed deployment. The host's distribution, CPU architecture, tailnet address and DNS name still need to be supplied. Examples assume a Linux host with systemd; build on the hosting architecture or a matching Linux build runner.

## 1. Build the matching frontend

Requirements: GitHub CLI authenticated for your forks, Git, Bun 1.3.14; Go 1.26+ and a C compiler for native builds, or Docker Engine with Compose for containers. Keep the backend and frontend revisions together when upgrading.

```bash
mkdir -p ~/services
cd ~/services
gh repo clone codewithsam110g/CLIProxyAPI backend
gh repo clone codewithsam110g/Cli-Proxy-API-Management-Center frontend
cd frontend
bun install --frozen-lockfile
bun run verify
cd ../backend
mkdir -p deploy/tailnet/static
cp ../frontend/dist/index.html deploy/tailnet/static/management.html
git rev-parse HEAD
git -C ../frontend rev-parse HEAD
```

Record both hashes in your deployment notes. Build from those exact commits on subsequent machines (`git checkout <recorded-sha>`). The frontend is served by the backend; you do not need a Node/Bun process in production. Automatic panel updates are disabled so an upstream dashboard cannot silently replace this fork's controls. Keep the HTML file present; the upstream asset handler may try a first-access download if it is missing.

## 2A. Docker Compose

From the backend directory:

```bash
mkdir -p deploy/tailnet/runtime/auths
cp deploy/tailnet/config.docker.example.yaml deploy/tailnet/runtime/config.yaml
# Edit runtime/config.yaml before starting: replace BOTH key placeholders.
# Generate distinct random values, for example with openssl rand -hex 32.
chmod 700 deploy/tailnet/runtime deploy/tailnet/runtime/auths
chmod 600 deploy/tailnet/runtime/config.yaml
sudo chown -R 10001:10001 deploy/tailnet/runtime
docker compose -f deploy/tailnet/compose.yaml config
docker compose -f deploy/tailnet/compose.yaml build
docker compose -f deploy/tailnet/compose.yaml up -d
docker compose -f deploy/tailnet/compose.yaml logs --tail=100 gateway
```

The image builds for the Docker host's architecture. Only `127.0.0.1:8317` is published. Management allows non-local source addresses **inside the container** because Docker bridge traffic is not localhost. It still requires the management key and is reached externally only through Nginx. Do not change the host port binding to `0.0.0.0`.

The whole `/data` directory is a persistent mount. This includes the config (startup hashes its management key), OAuth credentials and `auths/.session-affinity.state`. Run one Compose replica. Generated HTML and runtime files are ignored by Git.

## 2B. Native systemd alternative

Do this instead of starting Compose. Build on the host architecture, or copy an artifact built on a matching Linux runner:

```bash
CGO_ENABLED=1 go build -trimpath -o cli-proxy-api ./cmd/server
sudo useradd --system --home-dir /var/lib/cliproxyapi --shell /usr/sbin/nologin cliproxy
sudo install -d -m 755 /opt/cliproxyapi/static
sudo install -m 755 cli-proxy-api /opt/cliproxyapi/cli-proxy-api
sudo install -m 644 deploy/tailnet/static/management.html /opt/cliproxyapi/static/management.html
sudo install -d -o cliproxy -g cliproxy -m 700 /var/lib/cliproxyapi/auths
sudo install -o cliproxy -g cliproxy -m 600 deploy/tailnet/config.native.example.yaml /var/lib/cliproxyapi/config.yaml
# Edit /var/lib/cliproxyapi/config.yaml and replace BOTH key placeholders.
sudo install -m 644 deploy/tailnet/cliproxyapi.service /etc/systemd/system/cliproxyapi.service
sudo systemctl daemon-reload
sudo systemctl enable --now cliproxyapi
sudo journalctl -u cliproxyapi -n 100 --no-pager
```

Skip `useradd` if the service user already exists. Native management is localhost-only because host Nginx connects over loopback. Leave `server.trusted-proxies` empty unless you deliberately want forwarded-address processing and have adjusted management access accordingly.

## 3. Put host Nginx in front

1. Get the host's Tailscale IPv4 (`tailscale ip -4`) and full MagicDNS hostname. Use a hostname covered by your chosen TLS certificate.
2. Obtain a certificate, for example using [Tailscale HTTPS certificates](https://tailscale.com/docs/how-to/set-up-https-certificates). With HTTPS enabled for the tailnet, run `sudo tailscale cert --cert-file=/etc/nginx/tailscale/gateway.crt --key-file=/etc/nginx/tailscale/gateway.key <host>.<tailnet>.ts.net` after creating that directory. Restrict access to the private key. Arrange certificate renewal and a validated Nginx reload; downloaded certificate files do not renew themselves.
3. Adapt `nginx.conf.example` to your existing Nginx `http {}` setup. Replace the IP, DNS name and certificate paths. Define its Upgrade map only once. Ensure the listener is on the Tailscale IP, not every interface.
4. Check `sudo nginx -t`, then reload Nginx as part of your normal hosting change process. On boot, make Nginx start after Tailscale has assigned its address, or let your service manager retry. An exact-IP listener cannot bind before that address exists.
5. Open `https://<host>.<tailnet>.ts.net/management.html` and log in with the **management** key. Clients use the separate **client** key and base URL `https://<host>.<tailnet>.ts.net/v1` (or the provider-compatible endpoint their tool expects).

The [Nginx proxy configuration](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) disables response/request buffering and upstream retries. Its [WebSocket Upgrade headers](https://nginx.org/en/docs/http/websocket.html) preserve Codex connections. The one-day settings are idle windows; active streams keep them alive. There is no proxy response cache. Do not add request replay/retry middleware in another proxy layer.

Use your existing CrowdSec/Nginx integration if desired. Check that its decisions do not indiscriminately block the tailnet or a Docker bridge address shared by all clients. It is additional host protection; it does not replace API authentication or tailnet policy.

## 4. Restrict the tailnet

Merge the example policy into your existing policy; **do not replace your tailnet policy with the example**. Replace `you@example.com`, tag the host `tag:llm-gateway`, and optionally tag your CI boxes `tag:llm-ci`. The [grant syntax](https://tailscale.com/docs/reference/syntax/grants) permits selected users/devices to reach TCP 443. Existing broad allow rules still grant access: adding this rule alone cannot narrow a broader rule. Validate the final policy in Tailscale's editor.

No router port forward, public listener or Tailscale Funnel is needed. The example permits the selected clients to reach both the client API and management login; the management key remains a separate boundary. For tighter administrative separation, use a separate management listener/proxy policy as a later change.

## 5. Add accounts and check the policy

Upload the Claude/Codex OAuth auth files through the authenticated dashboard, or follow the upstream OAuth login flow. Do not publish OAuth callback ports just to complete login: use the supported management callback flow or an SSH tunnel when a local CLI callback is needed. Keep provider credentials on the hosting machine. Use synthetic credentials for build/UI tests.

Confirm the configuration uses:

```yaml
routing:
  strategy: session-balanced
  session-affinity-ttl: 24h
```

The Sessions & routing page should show accounts. Send two requests with the same `X-Session-Id` and the same client API key, provider/model route; they should retain the same account. Native Claude/Codex stable session headers are also recognized. New conversations should use different stable IDs. A per-request random ID defeats pinning. Changing client API keys or model namespaces creates a different binding scope.

- Unknown quota until fresh provider response headers arrive is normal. Dashboard quota probes are separate from passive router observations.
- Drain an account: existing sessions should stay; new independent sessions should avoid it.
- Request move: it is pending until the next safe request. Stateful continuations need reconnect/full-history replay. A live in-flight request is not interrupted.
- Restart the gateway and confirm pins survive. Keep the hidden state file with the auth directory. Default idle expiry is 24 hours, not permanent storage.
- A generic 429/5xx returns/retries on the same account. Confirmed subscription quota or unrecoverable account failure permits migration. Live failure injection needs a controlled test account or local stub, not production quota exhaustion.

## 6. Your Linux and Windows CI/test boxes

Use Linux for Linux production artifacts and container builds. Use Windows for native compatibility checks and dashboard/browser testing. A Windows binary is not a Linux deployment artifact.

Backend checks on either box (Go 1.26+, C compiler compatible with CGO; Windows can use a configured MinGW toolchain):

```bash
go test ./...
go test -race ./sdk/cliproxy/auth ./sdk/cliproxy ./internal/api/handlers/management ./internal/api
go build -o cli-proxy-api ./cmd/server
```

Use `cli-proxy-api.exe` for the Windows build output. The race detector requires a supported architecture/toolchain. Frontend checks are `bun install --frozen-lockfile` followed by `bun run verify`. Open the tailnet dashboard on each UI test box and check sessions, drain/resume, pending moves, refresh and connection changes. For isolated tests, run a separate gateway with synthetic auths and its own port/data directory.

You can run these commands in your CI system without giving either runner production OAuth files. If using self-hosted GitHub runners for these public forks, restrict jobs to trusted code; do not run untrusted PR code on machines that hold deployment access. Publication/deployment should remain an explicit step after tests pass. No runners or unattended deploys were configured here.

## 7. Upgrades, backup and recovery

Keep a paired backend/frontend revision record and a previous binary/image plus HTML. Before an upgrade, stop accepting new work, allow active requests to finish, then stop the gateway and make an encrypted backup of its whole persistent directory. This preserves OAuth files, hashed config and session bindings together. Start the new version on the same directory, then verify account pins and streaming through Nginx. Expect live WebSockets to reconnect across restarts.

For rollback, stop the gateway and restore the matching artifact pair and compatible state backup. Never run old and new processes concurrently on one state file. Normal restarts preserve pins; recent usage/activity counters are checkpointed at most every 30 seconds and are not a billing ledger. The file is synced before replacement, but the containing directory is not separately synced, so hard power-loss durability is not guaranteed.

If state is corrupt or unwritable, routing fails closed rather than silently redistributing sessions. Stop the service, repair permissions or restore the backup, then restart. Deleting the state file deliberately abandons pins and drain settings; do that only as a conscious recovery choice.

## Verification boundary

Backend tests and frontend checks were run on macOS; see the fork notes for results. These templates were statically checked. Docker daemon, Nginx, systemd and your remote Linux/Windows hosts were not available for live deployment validation. No real Claude/Codex OAuth account was exercised. Measure provider cache-read tokens after a controlled live rollout; stable account routing preserves the opportunity for a cache hit but cannot guarantee a provider cache hit.
