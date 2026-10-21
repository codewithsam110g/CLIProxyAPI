# Session-balanced CLIProxyAPI fork

This fork adds persistent account ownership for conversations and a matching management dashboard. Backend base: `router-for-me/CLIProxyAPI` at `2422c6b0f5fe16495320fa29456493874c1977a0`. Dashboard base: `router-for-me/Cli-Proxy-API-Management-Center` at `fe2963330f32a933f562282165f62ae52cf57145`.

[Deployment guide](deploy/tailnet/README.md) · [Frontend fork](https://github.com/codewithsam110g/Cli-Proxy-API-Management-Center)

## Policy

A conversation starts on account A. All its requests stay on A through temporary transport failures, 5xx responses and ordinary request-rate 429s. The proxy can report an error rather than quietly sending the request to B. **1% remaining or less in either shared quota window is the stopping point**, for existing conversations as well as new assignments. A stopped account, confirmed subscription exhaustion, account removal/disablement or unrecoverable authentication failure permits one coordinated move to B. Recovery of A does not move the conversation back. A later independent confirmed failure can cause a further recorded move.

The existing credential acquisition/refresh path gets its normal opportunity to refresh a token before a terminal authentication result is classified. A model-permission 403 alone is not evidence of a dead account. Confirmed 429s require provider quota markers or the manager's credential-scoped quota classification. User-defined request-scoped error rules retain their stop/skip semantics.

Enable explicitly in existing installations (the fork's example and deployment templates already select it):

```yaml
routing:
  strategy: session-balanced
  session-affinity-ttl: 24h
```

`session-affinity: true` is not required for this strategy. Its old `rebind-on` and `subagents` switches configure the upstream affinity wrapper, not this policy. This mode always inherits a known parent's account for new subagents. Other upstream strategies retain their existing behavior.

## Identity and ownership

Bindings are scoped by caller, route provider namespace, canonical model and session identity. API authentication supplies a hash of the downstream API key as caller scope. Give independent clients distinct keys when they need isolation; rotating a client key changes that scope. Upstream access-token refresh does not change credential identity and does not move a session.

The existing session parser recognizes Claude/Codex headers, body/session/cache identities, hierarchy aliases and derived conversation roots. Prefer an explicit stable `X-Session-Id` when the client does not supply a native session ID. A per-request random ID cannot preserve a conversation binding. History-derived identities remain approximate; this mode does not add a new LCP matcher or promise identity continuity through arbitrary compaction. Each model/provider namespace has its own pin.

The selector's mutex serializes first assignment and migration. Concurrent requests cannot publish competing initial accounts. A generation guards result handling: late results from A cannot invalidate B's newer pin. Requests already executing on A can finish; migrations govern subsequent selections and do not forcibly interrupt live work.

Native session ownership takes precedence over plugin account selection while this mode is enabled. Home mode has a separate authoritative scheduler and cannot be combined with session-balanced; execution returns a policy-conflict error rather than bypassing pins. Other plugin capabilities remain available.

## Placement heuristic

Only new bindings and approved migrations are scored. Candidate filtering respects model support, configured priority, positive weight, credential eligibility, health/cooldown and drain state. Existing pins are honored across priority recovery. Weights are admission gates here, not round-robin shares.

For Claude/Codex, the smallest remaining fraction across fresh shared short/long quota windows limits placement. Observations come from provider response headers, are timestamped and expire after five minutes for scoring. Missing/stale quota stays unknown and uses a conservative score of 0.25. **A remembered quota stop does not expire with that scoring snapshot:** the affected window must reach its reported reset or supply a newer fresh observation above 1%. Missing fields cannot clear another window's stop. Without a reset, a stop remains until verified recovery; unknown accounts can still receive an initial request to learn their quota. The score is `headroom_fraction / (1 + sessions_active_in_last_15_minutes)`. Reset hints break equal scores, then account ID makes selection deterministic.

Confirmed credential quota is considered for every conversation using that account, including bindings other than the one that received the failure. Each conversation migrates on its own next safe request. Quota-stopped accounts are excluded before priority selection and cannot be manual-move targets. If all compatible accounts are stopped, routing returns an error and retains ownership. Subagents inherit a usable parent's account; a quota-stopped parent does not force a new child onto the stopped account.

This is a session-load heuristic, not an exact token-budget predictor. There is no subscription-percent-to-token conversion, synthetic remaining allowance, cross-account cache merger, latency predictor or provider quota polling service. The quota dashboard's probes remain separate from the router's passive observations. Provider-side usage outside this proxy can make observations stale.

## Persistence and safe continuation

`oauth.auth-dir/.session-affinity.state` contains versioned routing metadata, aliases, generations, migration history, drain flags, per-account quota stops and usage counters. It contains no OAuth tokens or conversation bodies; session/account identifiers and hashed caller scopes are still private operational data. Files are created with mode 0600. Keep them out of Git and include the hidden state file in encrypted backups with credentials.

Initial assignments, moves and drain changes are synced to a temporary file and atomically replaced before dispatch. Corrupt/unwritable state fails closed. Normal restarts preserve pins; usage/activity updates checkpoint at 30-second intervals, so abrupt termination can lose recent counters or activity timestamps. The containing directory is not separately synced, so hard power-loss durability is not guaranteed. The store has a 16 MiB size ceiling and supports at most 4,096 live bindings and 16 migration entries per binding; capacity exhaustion returns an error rather than evicting live pins. Idle bindings expire after the configured TTL.

Run exactly one process against the directory. This file store does not provide cross-process locking, replicated ownership or multi-host failover. Switching back to an upstream strategy stops enforcing these pins; switching back before expiry reloads saved bindings.

Management OAuth callback forwarders bind to `127.0.0.1`, so opening the dashboard login flow does not expose a callback port on the LAN. Remote login uses callback submission or an SSH tunnel.

A request with `previous_response_id` or a transport-pinned account cannot safely migrate as a delta. It receives 409 with a reconnect/full-history replay message. After visible streaming output, the existing stream boundary stops replay; the new selector does not add a retry layer. A manual move stays pending until a safe subsequent request. No eligible replacement means an error with the original ownership retained, not paid/model/provider fallback.

## Dashboard and API

Use the matching frontend fork's **Sessions & routing** page. It shows accounts, fresh/unknown headroom, recent sessions, session/parent/caller scope, account pin, generation, activity/expiry, placement reason, request results, token buckets and migration history. Account IDs disambiguate equal labels. Drain stops new assignments while preserving existing conversations. A manual move requires a current binding generation and a compatible non-draining account, and takes effect on the next safe request.

Protected v8 endpoints:

| Endpoint | Operation |
| --- | --- |
| `GET /v8/management/routing/sessions` | Snapshot; `enabled:false` when another strategy is selected |
| `POST /v8/management/routing/accounts/drain` | `{ "auth_id": "...", "draining": true }` |
| `POST /v8/management/routing/sessions/move` | `{ "id": "...", "auth_id": "...", "expected_generation": 1 }` |

Token accounting uses the canonical non-overlapping input/cache-read/cache-write/output buckets. Cache-read ratio is total cache-read tokens divided by total input tokens for complete observations. Incomplete observations are counted and disclosed. Counters cover requests through this proxy during the binding lifetime and are not a permanent analytics/billing ledger. Cache-write tokens are not cache hits. Stable account routing preserves cache opportunity; cache hits still depend on the provider, model, prompt prefix and cache lifetime.

## Validation and remaining deployment checks

Verified on macOS:

- `go test ./...` across backend packages; local review repros isolated as a nested module.
- Race tests in auth, service, management handlers and API packages.
- Regression coverage for concurrent first assignment, caller/parent separation, restart/token rotation, transient errors, confirmed migration, priority recovery, late results, drain/manual moves, generation checks, corrupt/unwritable state, complete usage buckets, plugin ownership, and no replay after visible streaming output.
- Both deployment YAML templates load through the real config loader; Compose syntax validates.
- Backend server build.
- Frontend `bun run verify`: 1,639 tests, lint and production build.
- In-app Chromium browser against the real local backend: synthetic session creation, drain/resume, pending manual move and next-request migration. The dummy provider targets loopback only; its connection failures are deliberate. No real OAuth account was used.

Not yet verified: live Claude/Codex subscription behavior/cache savings; Linux/Windows runner execution; image build/runtime, Nginx TLS/WebSockets and systemd on the hosting machine. No production deployment or CI runner registration was performed. See the deployment guide for rollout checks.

Both repositories remain public forks. GitHub does not permit making a public fork private independently; no detached private copy was created.
