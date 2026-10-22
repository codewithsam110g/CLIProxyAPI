# Session-balanced CLIProxyAPI fork

This fork adds persistent account ownership for conversations and a matching management dashboard. Backend base: `router-for-me/CLIProxyAPI` at `2422c6b0f5fe16495320fa29456493874c1977a0`. Dashboard base: `router-for-me/Cli-Proxy-API-Management-Center` at `fe2963330f32a933f562282165f62ae52cf57145`.

[Deployment guide](deploy/tailnet/README.md) · [Frontend fork](https://github.com/codewithsam110g/Cli-Proxy-API-Management-Center)

## Policy

A conversation starts on account A. All its requests stay on A through temporary transport failures, 5xx responses and ordinary request-rate 429s. The proxy can report an error rather than quietly sending the request to B. **A configurable reserve of remaining quota in either shared window is the stopping point** (defaults: 5% for the short window, 2% for the long window), for existing conversations as well as new assignments. A stopped account, confirmed subscription exhaustion, account removal/disablement or unrecoverable authentication failure permits one coordinated move to B. Recovery of A does not move the conversation back. A later independent confirmed failure can cause a further recorded move.

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

For Claude/Codex, the smallest remaining fraction across fresh shared short/long quota windows limits placement. Observations come from provider response headers and from the usage poller below, are timestamped and expire after five minutes for scoring. Missing/stale quota stays unknown and uses a conservative score of 0.25. **A remembered quota stop does not expire with that scoring snapshot:** the affected window must reach its reported reset or supply a newer fresh observation above that window's reserve. Missing fields cannot clear another window's stop. Without a reset, a stop remains until verified recovery; unknown accounts can still receive an initial request to learn their quota. The score is `headroom_fraction / (1 + sessions_active_in_last_15_minutes)`. Reset hints break equal scores, then account ID makes selection deterministic.

Confirmed credential quota is considered for every conversation using that account, including bindings other than the one that received the failure. Each conversation migrates on its own next safe request. Quota-stopped accounts are excluded before priority selection and cannot be manual-move targets. **Reserves are soft:** a reserve-only stop moves a conversation and blocks new assignments only while some compatible account is outside its reserve. When every compatible account is inside its reserve, existing conversations stay on their account (keeping its cache) and new conversations go to the account with the most room, until the provider actually refuses. An exhausted account (confirmed quota, or a window at 0% remaining) is never used; if every compatible account is exhausted, routing returns an error and retains ownership. Subagents inherit a usable parent's account; a quota-stopped parent does not force a new child onto the stopped account.

This is a session-load heuristic, not an exact token-budget predictor. There is no subscription-percent-to-token conversion, synthetic remaining allowance, cross-account cache merger or latency predictor. Provider-side usage outside this proxy can make observations stale; the poller below narrows that gap but does not close it.

## Quota reserves and usage polling

Reserves are set per window class under `routing.session-quota` and are hot-reloaded:

```yaml
routing:
  session-quota:
    short-window-reserve-percent: 5   # Claude 5-hour / Codex primary; 0-50, default 5
    long-window-reserve-percent: 2    # Claude 7-day / Codex secondary; 0-50, default 2
    poll-interval: 5m                 # "0" disables polling; otherwise at least 1m, default 5m
```

An account is stopped when any one of its windows has its reserve or less remaining, and the stop reason names the window, for example `5-hour window at 3% remaining (reserve 5%)`. The short reserve is wider because one long agent turn can use more than 1% of a five-hour window. Out-of-range values are rejected, not clamped, so a typo cannot silently weaken or strengthen the policy. A Codex window is classed by its reported length when present, so a plan that reports only a weekly window as "primary" gets the long reserve.

A reserve change takes effect without a restart and never invalidates the state file. Stops are stored with the observation that caused them, not the reserve in force at the time. Raising a reserve stops accounts already inside it at once. Lowering a reserve does not release a stop by itself: only a newer fresh observation above the lower reserve does, as for any recovery, and, while polling is enabled, the poller fetches one immediately when a reserve changes. Conversations already pinned to a stopped account still move on their next safe request when another compatible account is outside its reserve (see the soft-reserve rule above).

**Usage poller.** Every `poll-interval` the proxy fetches usage for each enabled Claude and Codex OAuth account, using the endpoints and headers the dashboard's quota page uses (Claude `GET /api/oauth/usage` with `anthropic-beta: oauth-2025-04-20`; Codex `GET /backend-api/wham/usage` with the account's `Chatgpt-Account-Id`), and records the result as the account's quota observation. It reaches the router by the same path as header observations, so scoring, stops and migration are unchanged. The first poll runs at startup. It runs only while `session-balanced` is selected and never in Home mode. `POST /v8/management/routing/accounts/refresh-quota` polls on demand.

- A poll replaces the base rate-limit signals it owns (the 5-hour/7-day or primary/secondary windows, their resets and limit flags, and Retry-After) and keeps the descriptive ones only response headers carry (plan, credits, additional and code-review limits). A window the provider omits is dropped, so an old reading never sits under a fresh timestamp. A poll that finishes after a newer response-header observation is discarded.
- A poll writes only the observation. It never touches cooldown state, so it cannot start a cooldown or end one early; a confirmed credential-quota stop is released only by the existing recovery rules.
- A failed poll (HTTP error, unparseable or empty response, token refresh failure) keeps the last observation, never stops or releases an account and is reported as `last_poll_error` in the snapshot. Access tokens come from the credential's own metadata; a token that is expired or about to expire goes through the normal refresh path first, whose own failure handling applies. Tokens and response bodies are never logged or stored.
- No timeout is set on a poll once its connection is established. At most one poll per account runs at a time: a tick skips an account that is still being polled, and a stuck poll holds only its own account. Shutdown cancels in-flight polls.
- The usage endpoints are the provider's own internal ones, not a published API; a provider change shows up as `unparseable response` or `no usage windows in response` rather than as a wrong reading.

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
| `POST /v8/management/routing/accounts/refresh-quota` | `{ "auth_id": "..." }` for one account, `{}` for all; polls usage now |

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
