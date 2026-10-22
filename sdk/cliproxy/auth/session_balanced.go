package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	usage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
)

const balancedStateMaxBytes = 16 << 20

const balancedIDKey = "session_balanced_id"
const balancedGenerationKey = "session_balanced_generation"

// SessionMigration is an account ownership change, never a replay of a request.
type SessionMigration struct {
	At     time.Time `json:"at"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason"`
}

// SessionBinding contains routing metadata only, never credentials or conversation text.
type SessionBinding struct {
	ID                  string             `json:"id"`
	SessionID           string             `json:"session_id"`
	ParentSessionID     string             `json:"parent_session_id,omitempty"`
	CallerScope         string             `json:"caller_scope,omitempty"`
	Namespace           string             `json:"namespace"`
	Provider            string             `json:"provider"`
	Model               string             `json:"model"`
	AuthID              string             `json:"auth_id"`
	Generation          uint64             `json:"generation"`
	CreatedAt           time.Time          `json:"created_at"`
	LastSeen            time.Time          `json:"last_seen"`
	ExpiresAt           time.Time          `json:"expires_at"`
	Reason              string             `json:"reason"`
	PendingReason       string             `json:"pending_reason,omitempty"`
	PendingAuthID       string             `json:"pending_auth_id,omitempty"`
	Successes           uint64             `json:"successes"`
	Failures            uint64             `json:"failures"`
	InputTokens         int64              `json:"input_tokens"`
	CacheReadTokens     int64              `json:"cache_read_tokens"`
	CacheWriteTokens    int64              `json:"cache_write_tokens"`
	OutputTokens        int64              `json:"output_tokens"`
	UsageSamples        uint64             `json:"usage_samples"`
	MissingUsageSamples uint64             `json:"missing_usage_samples"`
	Aliases             []string           `json:"aliases,omitempty"`
	Migrations          []SessionMigration `json:"migrations,omitempty"`
}

type balancedState struct {
	Version    int                                    `json:"version"`
	Sessions   map[string]*SessionBinding             `json:"sessions"`
	Draining   map[string]bool                        `json:"draining"`
	QuotaStops map[string]map[string]sessionQuotaStop `json:"quota_stops,omitempty"`
}

type RoutingAccount struct {
	ID               string    `json:"id"`
	Label            string    `json:"label"`
	Provider         string    `json:"provider"`
	Disabled         bool      `json:"disabled"`
	Draining         bool      `json:"draining"`
	RecentSessions   int       `json:"recent_sessions"`
	RemainingPercent *float64  `json:"remaining_percent"`
	ObservedAt       time.Time `json:"observed_at"`
	QuotaStopped     bool      `json:"quota_stopped"`
	QuotaStopReason  string    `json:"quota_stop_reason,omitempty"`
	// QuotaExhausted distinguishes a provider-enforced stop from a reserve-only
	// stop, which still serves when every compatible account is in reserve.
	QuotaExhausted bool `json:"quota_exhausted"`
	// Windows lists the shared quota windows (short, then long) for Claude and
	// Codex accounts; it is empty for other providers.
	Windows []RoutingWindow `json:"windows"`
	// LastPollAt, LastPollSuccessAt are RFC3339 or "" when never polled.
	// LastPollError is a short non-secret classification of the latest failed poll.
	LastPollAt        string `json:"last_poll_at"`
	LastPollSuccessAt string `json:"last_poll_success_at"`
	LastPollError     string `json:"last_poll_error"`
}

type BalancedRoutingSnapshot struct {
	Enabled    bool             `json:"enabled"`
	StateError string           `json:"state_error,omitempty"`
	Sessions   []SessionBinding `json:"sessions"`
	Accounts   []RoutingAccount `json:"accounts"`
	// QuotaPollIntervalSeconds is the effective polling cadence; 0 when polling is off.
	QuotaPollIntervalSeconds  int     `json:"quota_poll_interval_seconds"`
	ShortWindowReservePercent float64 `json:"short_window_reserve_percent"`
	LongWindowReservePercent  float64 `json:"long_window_reserve_percent"`
}

// SessionBalancedSelector chooses accounts only for new sessions and confirmed
// migrations. One mutex owns selection, binding generations and durable publication.
// It is for a single server process, not a shared multi-writer store.
type SessionBalancedSelector struct {
	mu             sync.Mutex
	state          balancedState
	aliases        map[string]string
	path           string
	ttl            time.Duration
	now            func() time.Time
	lastCheckpoint time.Time
	loadErr        error
	storeErr       error
	stopped        bool
	accounts       func() []*Auth
	supports       func(*Auth, string) bool
	reserves       SessionQuotaReserves
	pollInfo       quotaPollInfo
}

func NewSessionBalancedSelector(path string, ttl time.Duration) *SessionBalancedSelector {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	s := &SessionBalancedSelector{path: path, ttl: ttl, now: time.Now, reserves: DefaultSessionQuotaReserves()}
	s.reload()
	return s
}

func (s *SessionBalancedSelector) reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = balancedState{Version: 1, Sessions: map[string]*SessionBinding{}, Draining: map[string]bool{}}
	s.aliases = map[string]string{}
	s.loadErr = nil
	if s.path == "" {
		return
	}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.loadErr = err
		return
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(io.LimitReader(f, balancedStateMaxBytes+1))
	var state balancedState
	if err = dec.Decode(&state); err != nil {
		s.loadErr = fmt.Errorf("read session state: %w", err)
		return
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		s.loadErr = errors.New("session state has trailing data")
		return
	}
	if state.Version != 1 || state.Sessions == nil || len(state.Sessions) > 4096 {
		s.loadErr = errors.New("unsupported or oversized session state")
		return
	}
	for id, b := range state.Sessions {
		if b == nil || id != b.ID || b.AuthID == "" || b.Generation == 0 || len(b.Aliases) > 65 {
			s.loadErr = errors.New("invalid session binding")
			return
		}
	}
	s.state = state
	if s.state.Draining == nil {
		s.state.Draining = map[string]bool{}
	}
	if len(s.state.QuotaStops) > 4096 {
		s.loadErr = errors.New("oversized quota stop state")
		return
	}
	for _, windows := range s.state.QuotaStops {
		if len(windows) > 5 {
			s.loadErr = errors.New("invalid quota stop state")
			return
		}
		for name, stop := range windows {
			if !validSessionQuotaStop(name, stop) {
				s.loadErr = errors.New("invalid quota stop state")
				return
			}
		}
	}
	s.rebuildAliases()
}

func (s *SessionBalancedSelector) rebuildAliases() {
	s.aliases = map[string]string{}
	for id, b := range s.state.Sessions {
		for _, alias := range b.Aliases {
			s.aliases[alias] = id
		}
	}
}

func (s *SessionBalancedSelector) persist() error {
	if s.path == "" {
		s.lastCheckpoint = s.now()
		s.storeErr = nil
		return nil
	}
	err := func() error {
		if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
			return err
		}
		data, err := json.Marshal(s.state)
		if err != nil {
			return err
		}
		if len(data) > balancedStateMaxBytes {
			return errors.New("session state exceeds size limit")
		}
		f, err := os.CreateTemp(filepath.Dir(s.path), ".routing-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(f.Name()) }()
		if _, err = f.Write(data); err != nil {
			_ = f.Close()
			return err
		}
		if err = f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		return os.Rename(f.Name(), s.path)
	}()
	s.storeErr = err
	if err == nil {
		s.lastCheckpoint = s.now()
	}
	return err
}

func routingError(code, message string, status int) error {
	return &Error{Code: code, Message: message, HTTPStatus: status, Retryable: false}
}

func balancedKey(scope, provider, model, session string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{scope, provider, canonicalModelKey(model), session}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func (m *Manager) attachBalancedSelector(selector Selector) {
	if s, ok := selector.(*SessionBalancedSelector); ok {
		s.accounts = m.List
		s.supports = func(a *Auth, model string) bool {
			return m.authSupportsRouteModel(registry.GetGlobalRegistry(), a, model)
		}
		s.pollInfo = m
	}
}

func (s *SessionBalancedSelector) account(id string) *Auth {
	if s.accounts != nil {
		for _, a := range s.accounts() {
			if a != nil && a.ID == id {
				return a
			}
		}
	}
	return nil
}

func (s *SessionBalancedSelector) lookup(key string, now time.Time) *SessionBinding {
	id := s.aliases[key]
	if id == "" {
		id = key
	}
	b := s.state.Sessions[id]
	if b != nil && now.Before(b.ExpiresAt) {
		return b
	}
	return nil
}

func (s *SessionBalancedSelector) Pick(ctx context.Context, provider, model string, opts executor.Options, auths []*Auth) (*Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil, routingError("session_router_stopped", "session router is reloading", 503)
	}
	if s.loadErr != nil {
		return nil, routingError("session_state_unavailable", "session state could not be loaded; repair or restore the state file", 503)
	}
	if s.storeErr != nil {
		if err := s.persist(); err != nil {
			return nil, routingError("session_state_unavailable", "session state could not be persisted", 503)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := s.now()
	aliasAdded := false
	primary, parent := extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	if primary == "" {
		return nil, routingError("session_id_required", "session-balanced routing requires a stable session ID or replayable conversation root", 400)
	}
	if s.refreshQuotaStops(auths, now) {
		if err := s.persist(); err != nil {
			return nil, routingError("session_state_unavailable", "quota stops could not be persisted", 503)
		}
	}
	scope := sessionMetadataString(opts.Metadata, executor.CallerScopeMetadataKey)
	key := balancedKey(scope, provider, model, primary)
	b := s.lookup(key, now)
	parentBinding := s.lookup(balancedKey(scope, provider, model, parent), now)
	if b == nil && parent != "" && parentBinding != nil && !isSubagentSession(primary, parent) {
		b = parentBinding
		if len(b.Aliases) < 65 {
			b.Aliases = mergeSessionAliases(b.Aliases, key)
			s.aliases[key] = b.ID
			aliasAdded = true
		}
	}
	pickByID := func(id string) *Auth {
		for _, a := range auths {
			if a != nil && a.ID == id {
				return a
			}
		}
		return nil
	}
	// hasRoomOutsideReserve reports a compatible account other than exclude that is
	// not quota-stopped; without one, reserve-only stops do not force a move.
	hasRoomOutsideReserve := func(exclude, provider string) bool {
		for _, a := range auths {
			if a != nil && a.ID != exclude && (provider == "" || a.Provider == provider) && !s.state.Draining[a.ID] && authWeight(a) > 0 && s.quotaStopReason(a.ID) == "" {
				return true
			}
		}
		return false
	}
	reason := "quota and recent-session load"
	if b != nil && b.PendingAuthID == "" && b.PendingReason != "" && pickByID(b.AuthID) != nil && s.quotaStopReason(b.AuthID) != "" && !s.quotaExhausted(b.AuthID) && !hasRoomOutsideReserve(b.AuthID, b.Provider) {
		// Every alternative is inside its reserve too: staying keeps the cache and
		// spends this account's reserve instead of failing the conversation.
		b.PendingReason = ""
		if err := s.persist(); err != nil {
			return nil, routingError("session_state_unavailable", "session state could not be persisted", 503)
		}
	}
	if b != nil && b.PendingReason == "" {
		if stopped := s.quotaStopReason(b.AuthID); stopped != "" && (s.quotaExhausted(b.AuthID) || hasRoomOutsideReserve(b.AuthID, b.Provider)) {
			b.PendingReason = stopped
			if err := s.persist(); err != nil {
				return nil, routingError("session_state_unavailable", "session migration could not be persisted", 503)
			}
		}
	}
	if b != nil && b.PendingReason == "" {
		if a := pickByID(b.AuthID); a != nil {
			if pinned := pinnedAuthIDFromMetadata(opts.Metadata); pinned != "" && pinned != b.AuthID {
				return nil, sessionReconnectRequired()
			}
			b.LastSeen = now
			b.ExpiresAt = now.Add(s.ttl)
			s.tag(opts, b)
			if aliasAdded || now.Sub(s.lastCheckpoint) >= 30*time.Second {
				if err := s.persist(); err != nil {
					return nil, routingError("session_state_unavailable", "session activity could not be persisted", 503)
				}
			}
			return a, nil
		}
		// Candidate exclusion after a transient failure is not permission to move.
		a := s.account(b.AuthID)
		if s.accounts != nil && (a == nil || a.Disabled || a.Status == StatusDisabled || hasUnauthorizedAuthFailure(a)) {
			b.PendingReason = "account unavailable"
			if err := s.persist(); err != nil {
				return nil, routingError("session_state_unavailable", "session migration could not be persisted", 503)
			}
		} else {
			return nil, routingError("session_account_unavailable", "the pinned account is temporarily unavailable; retry this session on the same account", 503)
		}
	}
	if b != nil && b.PendingReason != "" && (gjson.GetBytes(opts.OriginalRequest, "previous_response_id").String() != "" || pinnedAuthIDFromMetadata(opts.Metadata) != "") {
		return nil, sessionReconnectRequired()
	}
	var chosen *Auth
	if b != nil && b.PendingAuthID != "" {
		chosen = pickByID(b.PendingAuthID)
		if chosen == nil || s.state.Draining[chosen.ID] || s.quotaStopReason(chosen.ID) != "" || chosen.Provider != b.Provider {
			return nil, routingError("session_target_unavailable", "the requested target account is not eligible for this request", 503)
		}
		reason = "manual move"
	} else if b == nil && pinnedAuthIDFromMetadata(opts.Metadata) != "" {
		chosen = pickByID(pinnedAuthIDFromMetadata(opts.Metadata))
		if chosen == nil || s.quotaStopReason(chosen.ID) != "" {
			return nil, sessionReconnectRequired()
		}
		reason = "transport session"
	} else if b == nil && parentBinding != nil && isSubagentSession(primary, parent) && (s.quotaStopReason(parentBinding.AuthID) == "" || (!s.quotaExhausted(parentBinding.AuthID) && !hasRoomOutsideReserve("", parentBinding.Provider))) {
		chosen = pickByID(parentBinding.AuthID)
		if chosen == nil {
			return nil, routingError("session_account_unavailable", "the parent session account is unavailable", 503)
		}
		reason = "parent session"
	} else {
		provider := ""
		if b != nil {
			provider = b.Provider
		}
		// Prefer accounts outside their reserve; when none exists, spend reserves.
		allowReserve := !hasRoomOutsideReserve("", provider)
		if b != nil {
			allowReserve = !hasRoomOutsideReserve(b.AuthID, provider)
		}
		candidates := make([]*Auth, 0, len(auths))
		for _, a := range auths {
			if a == nil || s.state.Draining[a.ID] || authWeight(a) <= 0 {
				continue
			}
			if s.quotaStopReason(a.ID) != "" && (!allowReserve || s.quotaExhausted(a.ID)) {
				continue
			}
			if b != nil && (a.Provider != b.Provider || a.ID == b.AuthID) {
				continue
			}
			candidates = append(candidates, a)
		}
		candidates = highestPriorityAuths(candidates)
		best := -1.0
		var bestReset time.Time
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
		for _, a := range candidates {
			if b != nil && a.ID == b.AuthID {
				continue
			}
			remaining, reset := accountHeadroom(a, now)
			capacity := 0.25
			if remaining != nil {
				capacity = *remaining / 100
			}
			if capacity <= 0 {
				continue
			}
			score := capacity / float64(1+s.recentSessions(a.ID, now))
			if score > best || (score == best && !reset.IsZero() && (bestReset.IsZero() || reset.Before(bestReset))) {
				best = score
				bestReset = reset
				chosen = a
			}
		}
	}
	if chosen == nil {
		return nil, routingError("session_capacity_unavailable", "no eligible replacement or new-session capacity is available", 503)
	}
	if b != nil && chosen.ID != b.AuthID {
		// Delta continuations belong to the previous upstream account. Never replay them blindly.
		if gjson.GetBytes(opts.OriginalRequest, "previous_response_id").String() != "" || pinnedAuthIDFromMetadata(opts.Metadata) != "" {
			return nil, sessionReconnectRequired()
		}
		reason = b.PendingReason
		b.Migrations = append(b.Migrations, SessionMigration{At: now, From: b.AuthID, To: chosen.ID, Reason: reason})
		if len(b.Migrations) > 16 {
			b.Migrations = b.Migrations[len(b.Migrations)-16:]
		}
		b.AuthID = chosen.ID
		b.Generation++
		b.PendingAuthID = ""
		b.PendingReason = ""
		b.Reason = reason
	} else if b == nil {
		for id, old := range s.state.Sessions {
			if !now.Before(old.ExpiresAt) {
				delete(s.state.Sessions, id)
			}
		}
		s.rebuildAliases()
		if len(s.state.Sessions) >= 4096 {
			return nil, routingError("session_capacity_unavailable", "session binding capacity is full; existing pins were retained", 503)
		}
		b = &SessionBinding{ID: key, SessionID: primary, ParentSessionID: parent, CallerScope: scope, Namespace: provider, Provider: chosen.Provider, Model: canonicalModelKey(model), AuthID: chosen.ID, Generation: 1, CreatedAt: now, Reason: reason, Aliases: []string{key}}
		if parent != "" && !isSubagentSession(primary, parent) {
			b.Aliases = append(b.Aliases, balancedKey(scope, provider, model, parent))
		}
		s.state.Sessions[key] = b
		for _, alias := range b.Aliases {
			s.aliases[alias] = key
		}
	}
	b.LastSeen = now
	b.ExpiresAt = now.Add(s.ttl)
	s.tag(opts, b)
	if err := s.persist(); err != nil {
		return nil, routingError("session_state_unavailable", "account binding could not be persisted; request was not dispatched", 503)
	}
	return chosen, nil
}

func (s *SessionBalancedSelector) tag(opts executor.Options, b *SessionBinding) {
	if opts.Metadata != nil {
		opts.Metadata[balancedIDKey] = b.ID
		opts.Metadata[balancedGenerationKey] = b.Generation
		opts.Metadata[executor.CanonicalSessionIDMetadataKey] = b.SessionID
	}
}

func confirmedSessionFailure(r Result) string {
	if r.Error == nil || shouldSkipCredentialCooldown(r.Error) {
		return ""
	}
	status := statusCodeFromResult(r.Error)
	text := strings.ToLower(r.Error.Message)
	if status == http.StatusUnauthorized || isInvalidGrantResultError(r.Error) {
		return "account authentication failed"
	}
	if status == 429 {
		for _, marker := range []string{"usage_limit_reached", "insufficient_quota", "quota_exceeded", "weekly limit", "weekly_limit", "subscription limit", "five_hour", "five-hour", "7-day", "7d limit"} {
			if strings.Contains(text, marker) {
				return "confirmed quota exhaustion"
			}
		}
		if r.CredentialScope {
			return "confirmed credential quota"
		}
	}
	for _, marker := range []string{"account_deactivated", "account_suspended", "account_disabled"} {
		if strings.Contains(text, marker) {
			return "account disabled"
		}
	}
	return ""
}

func (s *SessionBalancedSelector) OnResult(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	id, _ := r.Options.Metadata[balancedIDKey].(string)
	generation, _ := r.Options.Metadata[balancedGenerationKey].(uint64)
	b := s.state.Sessions[id]
	if b == nil || b.AuthID != r.AuthID || b.Generation != generation {
		return
	}
	if r.Success {
		b.Successes++
	} else {
		b.Failures++
	}
	if reason := confirmedSessionFailure(r); reason != "" {
		if b.PendingReason == "" {
			b.PendingReason = reason
		}
		if statusCodeFromResult(r.Error) == http.StatusTooManyRequests {
			s.recordConfirmedQuotaStop(r)
		}
		_ = s.persist() // A failed commit blocks subsequent selections via storeErr.
	}
	if s.refreshQuotaStops(nil, s.now()) {
		_ = s.persist()
	}
}

func (s *SessionBalancedSelector) InvalidateAuth(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	delete(s.state.QuotaStops, id)
	for _, b := range s.state.Sessions {
		if b.AuthID == id {
			b.PendingReason = "account removed"
		}
	}
	_ = s.persist()
}

func (s *SessionBalancedSelector) recentSessions(id string, now time.Time) int {
	count := 0
	for _, b := range s.state.Sessions {
		if b.AuthID == id && now.Before(b.ExpiresAt) && now.Sub(b.LastSeen) < 15*time.Minute {
			count++
		}
	}
	return count
}

// accountHeadroom uses fresh provider observations, never inferred token quotas.
// Unknown/stale observations remain unknown. Relevant short and long windows
// constrain placement together; reset hints only break otherwise equal scores.
func accountHeadroom(a *Auth, now time.Time) (*float64, time.Time) {
	if a == nil || a.Quota.ObservedAt.IsZero() || now.Sub(a.Quota.ObservedAt) > 5*time.Minute || a.Quota.ObservedAt.After(now.Add(time.Minute)) {
		return nil, time.Time{}
	}
	min := 100.0
	found := false
	var reset time.Time
	for _, window := range quotaWindowObservations(a) {
		if !window.ResetAt.IsZero() && !now.Before(window.ResetAt) {
			continue
		}
		found = true
		if window.RemainingPercent < min {
			min = window.RemainingPercent
		}
		if window.ResetAt.After(now) && (reset.IsZero() || window.ResetAt.Before(reset)) {
			reset = window.ResetAt
		}
	}
	if !found {
		return nil, reset
	}
	return &min, reset
}

func (s *SessionBalancedSelector) Snapshot() BalancedRoutingSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := BalancedRoutingSnapshot{Enabled: true, Sessions: []SessionBinding{}, Accounts: []RoutingAccount{}}
	if s.loadErr != nil {
		out.StateError = "session state could not be loaded"
	} else if s.storeErr != nil {
		out.StateError = "session state could not be persisted"
	}
	now := s.now()
	if s.loadErr == nil && !s.stopped && s.refreshQuotaStops(nil, now) {
		if err := s.persist(); err != nil {
			out.StateError = "session state could not be persisted"
		}
	}
	for _, b := range s.state.Sessions {
		if now.Before(b.ExpiresAt) {
			copy := *b
			copy.Aliases = nil
			copy.Migrations = append([]SessionMigration(nil), b.Migrations...)
			out.Sessions = append(out.Sessions, copy)
		}
	}
	sort.Slice(out.Sessions, func(i, j int) bool { return out.Sessions[i].LastSeen.After(out.Sessions[j].LastSeen) })
	out.Accounts = s.accountEntries(now, nil)
	out.ShortWindowReservePercent = s.reserves.Short
	out.LongWindowReservePercent = s.reserves.Long
	if s.pollInfo != nil {
		out.QuotaPollIntervalSeconds = int(s.pollInfo.QuotaPollInterval() / time.Second)
	}
	return out
}

// AccountSnapshots returns the routing entries of the given accounts, or of all
// accounts when none are named, after re-evaluating quota stops.
func (s *SessionBalancedSelector) AccountSnapshots(ids ...string) []RoutingAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.loadErr == nil && !s.stopped && s.refreshQuotaStops(nil, now) {
		_ = s.persist()
	}
	var only map[string]bool
	if len(ids) > 0 {
		only = make(map[string]bool, len(ids))
		for _, id := range ids {
			only[id] = true
		}
	}
	return s.accountEntries(now, only)
}

// Caller holds s.mu.
func (s *SessionBalancedSelector) accountEntries(now time.Time, only map[string]bool) []RoutingAccount {
	entries := []RoutingAccount{}
	if s.accounts != nil {
		for _, a := range s.accounts() {
			if a == nil || (only != nil && !only[a.ID]) {
				continue
			}
			remaining, _ := accountHeadroom(a, now)
			stopReason := s.quotaStopReason(a.ID)
			entry := RoutingAccount{ID: a.ID, Label: a.Label, Provider: a.Provider, Disabled: a.Disabled || a.Status == StatusDisabled, Draining: s.state.Draining[a.ID], RecentSessions: s.recentSessions(a.ID, now), RemainingPercent: remaining, ObservedAt: a.Quota.ObservedAt, QuotaStopped: stopReason != "", QuotaStopReason: stopReason, QuotaExhausted: s.quotaExhausted(a.ID), Windows: s.accountWindows(a, now)}
			if s.pollInfo != nil {
				status := s.pollInfo.QuotaPollStatus(a.ID)
				entry.LastPollAt = formatPollTime(status.LastPollAt)
				entry.LastPollSuccessAt = formatPollTime(status.LastSuccessAt)
				entry.LastPollError = status.LastError
			}
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

func (s *SessionBalancedSelector) SetDraining(id string, draining bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil || s.stopped {
		return errors.New("session state unavailable")
	}
	if s.account(id) == nil {
		return errors.New("account not found")
	}
	s.state.Draining[id] = draining
	return s.persist()
}

func (s *SessionBalancedSelector) RequestMove(id, target string, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil || s.stopped {
		return errors.New("session state unavailable")
	}
	b := s.state.Sessions[id]
	if b == nil || !s.now().Before(b.ExpiresAt) {
		return errors.New("session not found")
	}
	if b.Generation != generation {
		return errors.New("session changed; refresh before moving")
	}
	a := s.account(target)
	if s.refreshQuotaStops(nil, s.now()) {
		if err := s.persist(); err != nil {
			return err
		}
	}
	if s.quotaStopReason(target) != "" {
		return errors.New("target account has reached the quota stop")
	}
	if a != nil {
		if blocked, _, _ := isAuthBlockedForModel(a, b.Model, s.now()); blocked {
			return errors.New("target account is unavailable")
		}
	}
	if a == nil || a.Disabled || a.Provider != b.Provider || s.state.Draining[target] || (s.supports != nil && !s.supports(a, b.Model)) {
		return errors.New("target account does not support this session")
	}
	if target == b.AuthID {
		return errors.New("session already uses this account")
	}
	b.PendingAuthID = target
	b.PendingReason = "manual move"
	return s.persist()
}

func (s *SessionBalancedSelector) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	if s.loadErr == nil {
		_ = s.persist()
	}
}

// balancedExecutionContext tags usage without exposing account tokens or raw caller keys.
type balancedUsageContextKey struct{}
type balancedUsageIdentity struct {
	ID         string
	Generation uint64
}

func balancedExecutionContext(ctx context.Context, opts executor.Options) context.Context {
	id, _ := opts.Metadata[balancedIDKey].(string)
	gen, _ := opts.Metadata[balancedGenerationKey].(uint64)
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, balancedUsageContextKey{}, balancedUsageIdentity{id, gen})
}

func (s *SessionBalancedSelector) ObserveUsage(ctx context.Context, r usage.Record) {
	identity, ok := ctx.Value(balancedUsageContextKey{}).(balancedUsageIdentity)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	b := s.state.Sessions[identity.ID]
	if b == nil || b.Generation != identity.Generation || b.AuthID != r.AuthID {
		return
	}
	tokens := r.Detail.TokenBreakdown
	if tokens.Valid() && tokens.Quality == usage.TokenAccountingQualityComplete {
		b.InputTokens += tokens.Input.TotalTokens
		b.CacheReadTokens += tokens.Input.CacheReadTokens
		b.CacheWriteTokens += tokens.Input.CacheWriteTokens
		b.OutputTokens += tokens.Output.TotalTokens
		b.UsageSamples++
	} else {
		b.MissingUsageSamples++
	}
	if s.now().Sub(s.lastCheckpoint) >= 30*time.Second {
		_ = s.persist()
	}
}
