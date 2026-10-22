package auth

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// The poller learns provider quota actively, so an idle account does not stay
// "unknown" until traffic happens to hit it. It writes the same observation
// (Auth.Quota.Signals + ObservedAt) the passive header path writes and then lets
// the session-balanced selector re-evaluate its stops.
//
// There is deliberately no timeout on probes: once an upstream connection is
// established the project forbids one. A hung probe therefore holds only its own
// account's in-flight slot; ticks skip that account and every other account
// keeps polling. Stop cancels the poller's context, which ends any such probe.

const (
	// quotaPollCoalesceWindow is how recent a finished poll must be for an
	// explicit refresh to reuse it instead of calling the provider again.
	quotaPollCoalesceWindow = 15 * time.Second
	quotaPollTokenSkew      = 30 * time.Second
	maxQuotaPollErrorLength = 120
)

var (
	// ErrQuotaPollAuthNotFound reports a refresh for an unknown account.
	ErrQuotaPollAuthNotFound = errors.New("account not found")
	// ErrQuotaPollUnsupported reports a refresh for an account that cannot be polled
	// (not a Claude/Codex OAuth credential, disabled, or terminally unauthorized).
	ErrQuotaPollUnsupported = errors.New("account does not support quota polling")
	// ErrQuotaPollerStopped is returned once the poller has been stopped.
	ErrQuotaPollerStopped = errors.New("quota poller is stopped")
)

// QuotaProbe fetches the current usage of one credential and returns it as quota
// signals named like the passive response headers (for example
// Anthropic-Ratelimit-Unified-5h-Utilization or X-Codex-Primary-Used-Percent).
// Its error text is stored and served by the management API, so it must be a short
// classification that contains no token, header or response body.
type QuotaProbe func(ctx context.Context, auth *Auth, accessToken string) (map[string]string, error)

// QuotaPollStatus is the poller's record of one account.
type QuotaPollStatus struct {
	// LastPollAt is when the latest attempt finished, successful or not.
	LastPollAt time.Time
	// LastSuccessAt is when the latest successful attempt finished.
	LastSuccessAt time.Time
	// LastError classifies the latest attempt; empty after a success.
	LastError string
}

// QuotaRefreshResult is the outcome of an explicit refresh for one account.
type QuotaRefreshResult struct {
	AuthID string
	// Coalesced reports that a poll finished moments ago and nothing was fetched.
	Coalesced bool
	// Error classifies a failed poll; empty on success.
	Error string
}

// quotaPollInfo is what the selector's snapshot needs from the poller.
type quotaPollInfo interface {
	QuotaPollInterval() time.Duration
	QuotaPollStatus(authID string) QuotaPollStatus
}

type quotaPollCall struct {
	done chan struct{}
	err  string
}

type quotaPollAccount struct {
	call   *quotaPollCall
	status QuotaPollStatus
}

// QuotaPoller polls Claude and Codex usage on a fixed cadence and on demand.
type QuotaPoller struct {
	manager  *Manager
	probes   map[string]QuotaProbe
	now      func() time.Time
	after    func(time.Duration) (<-chan time.Time, func())
	coalesce time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	wake   chan struct{}

	mu       sync.Mutex
	interval time.Duration
	pollSoon bool
	started  bool
	stopped  bool
	accounts map[string]*quotaPollAccount
}

// NewQuotaPoller builds a poller for the given probes, keyed by lower-case provider.
// It does nothing until Start; polling stays off until Configure sets an interval.
// quotaPollTimeout bounds one usage probe, including token acquisition.
const quotaPollTimeout = 30 * time.Second

func NewQuotaPoller(manager *Manager, probes map[string]QuotaProbe) *QuotaPoller {
	ctx, cancel := context.WithCancel(context.Background())
	copied := make(map[string]QuotaProbe, len(probes))
	for provider, probe := range probes {
		if probe != nil {
			copied[strings.ToLower(strings.TrimSpace(provider))] = probe
		}
	}
	return &QuotaPoller{
		manager:  manager,
		probes:   copied,
		now:      time.Now,
		after:    realQuotaTimer,
		coalesce: quotaPollCoalesceWindow,
		ctx:      ctx,
		cancel:   cancel,
		wake:     make(chan struct{}, 1),
		accounts: make(map[string]*quotaPollAccount),
	}
}

func realQuotaTimer(d time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(d)
	return timer.C, func() { timer.Stop() }
}

// Configure sets the polling cadence; 0 turns background polling off while
// explicit refreshes keep working. Enabling polling schedules an immediate poll.
func (p *QuotaPoller) Configure(interval time.Duration) {
	if p == nil {
		return
	}
	if interval < 0 {
		interval = 0
	}
	p.mu.Lock()
	changed := interval != p.interval
	if changed && p.interval == 0 {
		p.pollSoon = true
	}
	p.interval = interval
	p.mu.Unlock()
	if changed {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
}

// Interval returns the effective cadence, or 0 while background polling is off.
func (p *QuotaPoller) Interval() time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.interval
}

// Start launches the polling loop. It is safe to call more than once.
func (p *QuotaPoller) Start() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started || p.stopped {
		return
	}
	p.started = true
	// The loop reads the current configuration on entry, so a wake queued by an
	// earlier Configure would only cost it a pointless restart.
	select {
	case <-p.wake:
	default:
	}
	p.wg.Add(1)
	go p.loop()
}

// Stop ends the loop, cancels in-flight probes and waits for them to return.
func (p *QuotaPoller) Stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.cancel()
	p.wg.Wait()
}

func (p *QuotaPoller) loop() {
	defer p.wg.Done()
	for {
		p.mu.Lock()
		interval := p.interval
		delay := interval
		if p.pollSoon {
			delay = 0
		}
		p.mu.Unlock()
		var tick <-chan time.Time
		stopTimer := func() {}
		if interval > 0 {
			tick, stopTimer = p.after(delay)
		}
		select {
		case <-p.ctx.Done():
			stopTimer()
			return
		case <-p.wake:
			// Re-read the interval: it changed, or polling was switched on/off.
			stopTimer()
		case <-tick:
			stopTimer()
			p.mu.Lock()
			p.pollSoon = false
			p.mu.Unlock()
			p.PollAllAsync()
		}
	}
}

// PollAllAsync starts a poll of every eligible account that is not already being
// polled and returns without waiting for the results.
func (p *QuotaPoller) PollAllAsync() {
	if p == nil {
		return
	}
	ids := p.eligibleIDs()
	for _, id := range ids {
		if _, _, err := p.acquire(id, 0); err != nil {
			return
		}
	}
	p.forgetMissing(ids)
}

// RefreshQuota polls the named accounts (all eligible ones when none are named)
// and waits for the polls to finish. An account already being polled is joined;
// one polled within the coalescing window is not polled again. Waiting ends early
// only when ctx is done; the polls themselves keep running.
func (p *QuotaPoller) RefreshQuota(ctx context.Context, ids ...string) ([]QuotaRefreshResult, error) {
	if p == nil {
		return nil, ErrQuotaPollerStopped
	}
	if ctx == nil {
		ctx = context.Background()
	}
	targets := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		targets = p.eligibleIDs()
	}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		auth, ok := p.manager.GetByID(id)
		if !ok {
			return nil, ErrQuotaPollAuthNotFound
		}
		if !p.eligible(auth) {
			return nil, ErrQuotaPollUnsupported
		}
		targets = append(targets, id)
	}
	type waiting struct {
		id        string
		call      *quotaPollCall
		coalesced bool
	}
	pending := make([]waiting, 0, len(targets))
	for _, id := range targets {
		call, coalesced, err := p.acquire(id, p.coalesce)
		if err != nil {
			return nil, err
		}
		pending = append(pending, waiting{id: id, call: call, coalesced: coalesced})
	}
	results := make([]QuotaRefreshResult, 0, len(pending))
	for _, w := range pending {
		result := QuotaRefreshResult{AuthID: w.id, Coalesced: w.coalesced}
		if w.coalesced {
			result.Error = p.QuotaPollStatus(w.id).LastError
		} else {
			select {
			case <-w.call.done:
				result.Error = w.call.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		results = append(results, result)
	}
	return results, nil
}

// QuotaPollStatus returns what the poller knows about one account.
func (p *QuotaPoller) QuotaPollStatus(authID string) QuotaPollStatus {
	if p == nil {
		return QuotaPollStatus{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if account := p.accounts[authID]; account != nil {
		return account.status
	}
	return QuotaPollStatus{}
}

// acquire starts a poll for id unless one is running (it then returns that
// call) or finished within coalesce (it then reports coalesced with no call).
func (p *QuotaPoller) acquire(id string, coalesce time.Duration) (call *quotaPollCall, coalesced bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return nil, false, ErrQuotaPollerStopped
	}
	account := p.accounts[id]
	if account == nil {
		account = &quotaPollAccount{}
		p.accounts[id] = account
	}
	if account.call != nil {
		return account.call, false, nil
	}
	if coalesce > 0 && !account.status.LastPollAt.IsZero() && p.now().Sub(account.status.LastPollAt) < coalesce {
		return nil, true, nil
	}
	call = &quotaPollCall{done: make(chan struct{})}
	account.call = call
	p.wg.Add(1)
	go p.run(id, call)
	return call, false, nil
}

func (p *QuotaPoller) run(id string, call *quotaPollCall) {
	defer p.wg.Done()
	startedAt := p.now()
	err := p.pollOnceRecovered(id, startedAt)
	finishedAt := p.now()

	p.mu.Lock()
	account := p.accounts[id]
	account.call = nil
	switch {
	case err == nil:
		account.status = QuotaPollStatus{LastPollAt: finishedAt, LastSuccessAt: finishedAt}
	case p.ctx.Err() != nil:
		// Shutdown interrupted the poll; that says nothing about the account.
		call.err = ErrQuotaPollerStopped.Error()
	default:
		previouslyFailing := account.status.LastError != ""
		account.status.LastPollAt = finishedAt
		account.status.LastError = quotaPollErrorText(err)
		call.err = account.status.LastError
		entry := log.WithFields(log.Fields{"auth_id": id, "error": account.status.LastError})
		if previouslyFailing {
			entry.Debug("quota poll failed")
		} else {
			entry.Warn("quota poll failed; keeping the last observation")
		}
	}
	p.mu.Unlock()
	close(call.done)
}

// pollOnceRecovered keeps a bug in a probe or in parsing upstream data from
// taking the process down: the poll fails like any other failed poll.
func (p *QuotaPoller) pollOnceRecovered(id string, startedAt time.Time) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			log.WithField("auth_id", id).Errorf("quota poll panicked: %v", recovered)
			err = errors.New("poll failed unexpectedly")
		}
	}()
	// A usage probe is a bounded management read, not model traffic: a hung
	// connection must not hold this account's poll slot indefinitely.
	ctx, cancel := context.WithTimeout(p.ctx, quotaPollTimeout)
	defer cancel()
	return p.pollOnce(ctx, id, startedAt)
}

func (p *QuotaPoller) pollOnce(ctx context.Context, id string, startedAt time.Time) error {
	auth, ok := p.manager.GetByID(id)
	if !ok {
		return errors.New("account no longer exists")
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	probe := p.probes[provider]
	if probe == nil || !p.eligible(auth) {
		return ErrQuotaPollUnsupported
	}
	auth, token, err := p.accessToken(ctx, auth)
	if err != nil {
		return err
	}
	if rt := p.manager.roundTripperFor(auth); rt != nil {
		ctx = context.WithValue(ctx, roundTripperContextKey{}, rt)
		ctx = context.WithValue(ctx, "cliproxy.roundtripper", rt)
	}
	polled, err := probe(ctx, auth, token)
	if err != nil {
		return err
	}
	finishedAt := p.now()
	signals := sanitizePolledQuotaSignals(provider, polled)
	if !hasQuotaWindowSignal(provider, signals) {
		return errors.New("no usage windows in response")
	}
	// A failed poll never reaches this point, so it cannot change quota stops.
	p.manager.applyPolledQuota(ctx, id, signals, startedAt, finishedAt)
	return nil
}

// accessToken returns a usable access token through the existing refresh path:
// the auto-refresh loop normally keeps it fresh, and an expired one gets the same
// refresh a request would trigger.
func (p *QuotaPoller) accessToken(ctx context.Context, auth *Auth) (*Auth, string, error) {
	token := authAccessToken(auth)
	// A token about to expire would be rejected mid-flight; refresh it first.
	if token != "" && auth.HasValidAccessToken(p.now().Add(quotaPollTokenSkew)) {
		return auth, token, nil
	}
	if !authHasRefreshCredential(auth) {
		if token == "" {
			return auth, "", errors.New("no access token")
		}
		return auth, "", errors.New("access token expired")
	}
	refreshed, err := p.manager.refreshAuthForRequest(ctx, auth.ID, "")
	if err != nil || refreshed == nil {
		log.WithFields(log.Fields{"auth_id": auth.ID, "provider": auth.Provider}).Debug("quota poll could not refresh the access token")
		return auth, "", errors.New("token refresh failed")
	}
	if token = authAccessToken(refreshed); token == "" {
		return auth, "", errors.New("no access token")
	}
	return refreshed, token, nil
}

func (p *QuotaPoller) eligible(auth *Auth) bool {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled || IsPluginVirtualAuth(auth) {
		return false
	}
	if p.probes[strings.ToLower(strings.TrimSpace(auth.Provider))] == nil || auth.AuthKind() != AuthKindOAuth {
		return false
	}
	// A terminally unauthorized account cannot be polled or refreshed; the
	// scheduler already treats it as dead.
	return !hasUnauthorizedAuthFailure(auth)
}

func (p *QuotaPoller) eligibleIDs() []string {
	var ids []string
	for _, auth := range p.manager.List() {
		if p.eligible(auth) {
			ids = append(ids, auth.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// forgetMissing drops records of accounts that no longer exist, so churn cannot
// grow the table. Accounts with a poll in flight keep their record.
func (p *QuotaPoller) forgetMissing(live []string) {
	keep := make(map[string]bool, len(live))
	for _, id := range live {
		keep[id] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, account := range p.accounts {
		if !keep[id] && account.call == nil {
			delete(p.accounts, id)
		}
	}
}

func quotaPollErrorText(err error) string {
	text := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(err.Error()))
	if len(text) > maxQuotaPollErrorLength {
		text = text[:maxQuotaPollErrorLength]
	}
	if text == "" {
		return "poll failed"
	}
	return text
}

// sanitizePolledQuotaSignals applies the passive path's header allowlist and value
// checks, so a probe cannot store anything a response header could not.
func sanitizePolledQuotaSignals(provider string, polled map[string]string) map[string]string {
	headers := make(http.Header, len(polled))
	for key, value := range polled {
		headers.Set(key, value)
	}
	return collectQuotaSignals(provider, headers)
}

func hasQuotaWindowSignal(provider string, signals map[string]string) bool {
	for key := range signals {
		lower := strings.ToLower(key)
		for _, spec := range quotaWindowSpecs {
			if spec.provider == provider && spec.key == lower {
				return true
			}
		}
	}
	return false
}

// isPollOwnedQuotaSignal reports whether a poll is authoritative for the signal.
// A poll owns the base rate-limit windows and the flags that describe them. It
// does not own descriptive signals (plan, credits, active limit) or the signals
// of other limits (additional, code-review), which only response headers carry.
func isPollOwnedQuotaSignal(provider, key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "retry-after" {
		return true
	}
	switch provider {
	case "claude":
		return strings.HasPrefix(lower, "anthropic-ratelimit-unified-")
	case "codex":
		return lower == "x-codex-allowed" || lower == "x-codex-limit-reached" ||
			strings.HasPrefix(lower, "x-codex-primary-") || strings.HasPrefix(lower, "x-codex-secondary-")
	}
	return false
}

// mergePolledQuotaSignals applies a poll to the passive snapshot.
//
// The poll REPLACES the signals it owns and PRESERVES the rest. Merging window
// signals would be wrong: the snapshot has one ObservedAt, so a window the poll
// omits (a plan without a weekly limit) would keep an old utilization under a
// fresh timestamp, and a stale Retry-After or limit-reached flag would look
// current. Replacing everything would instead erase plan, credit and
// additional-limit signals that only response headers supply and the dashboard
// shows. Preserved keys carry the new ObservedAt; the router reads only the
// window keys, which are always from this poll.
func mergePolledQuotaSignals(provider string, existing, polled map[string]string) map[string]string {
	merged := make(http.Header, len(existing)+len(polled))
	for key, value := range existing {
		if !isPollOwnedQuotaSignal(provider, key) {
			merged.Set(key, value)
		}
	}
	for key, value := range polled {
		merged.Set(key, value)
	}
	return collectQuotaSignals(provider, merged)
}

// applyPolledQuota records a poll as the account's quota observation. It writes
// only Quota.Signals and Quota.ObservedAt, never the cooldown fields, and drops a
// poll that a newer response-header observation overtook while it was in flight.
func (m *Manager) applyPolledQuota(ctx context.Context, id string, polled map[string]string, startedAt, observedAt time.Time) bool {
	if m == nil || id == "" {
		return false
	}
	releaseMutation := m.lockAuthMutation(id)
	m.mu.Lock()
	auth := m.auths[id]
	provider := ""
	if auth != nil {
		provider = strings.ToLower(strings.TrimSpace(auth.Provider))
	}
	if auth == nil || !ProviderSupportsQuotaObservation(provider) ||
		(!auth.Quota.ObservedAt.IsZero() && auth.Quota.ObservedAt.After(startedAt)) {
		m.mu.Unlock()
		releaseMutation()
		return false
	}
	auth.Quota.Signals = mergePolledQuotaSignals(provider, auth.Quota.Signals, polled)
	auth.Quota.ObservedAt = observedAt
	auth.Generation++
	auth.UpdatedAt = observedAt
	_ = m.persistLocked(ctx, auth)
	snapshot := auth.Clone()
	m.mu.Unlock()
	releaseMutation()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	// Outside every manager lock: the selector reads accounts through List.
	if balanced, ok := m.Selector().(*SessionBalancedSelector); ok {
		balanced.RefreshQuotaStops()
	}
	return true
}

// SetQuotaPoller registers the poller reported in routing snapshots and used by
// the management refresh endpoint.
func (m *Manager) SetQuotaPoller(p *QuotaPoller) {
	if m != nil {
		m.quotaPoller.Store(p)
	}
}

// QuotaPoller returns the registered poller, or nil.
func (m *Manager) QuotaPoller() *QuotaPoller {
	if m == nil {
		return nil
	}
	return m.quotaPoller.Load()
}

// QuotaPollInterval implements quotaPollInfo.
func (m *Manager) QuotaPollInterval() time.Duration { return m.QuotaPoller().Interval() }

// QuotaPollStatus implements quotaPollInfo.
func (m *Manager) QuotaPollStatus(authID string) QuotaPollStatus {
	return m.QuotaPoller().QuotaPollStatus(authID)
}

func formatPollTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
