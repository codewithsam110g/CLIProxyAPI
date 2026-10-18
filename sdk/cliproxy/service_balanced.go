package cliproxy

import (
	"context"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

type balancedUsageSink struct{ manager *coreauth.Manager }

func (p balancedUsageSink) HandleUsage(ctx context.Context, r usage.Record) {
	if router, ok := p.manager.Selector().(*coreauth.SessionBalancedSelector); ok {
		router.ObserveUsage(ctx, r)
	}
}
