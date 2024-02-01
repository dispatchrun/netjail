package netjail_test

import (
	"context"
	"testing"

	"github.com/stealthrocket/netjail"
)

func TestContextRules(t *testing.T) {
	rules := &netjail.Rules{}

	ctx := netjail.ContextWithRules(context.Background(), rules)
	got := netjail.ContextRules(ctx)

	if got != rules {
		t.Errorf("ContextRules(%v) = %v, want %v", ctx, got, rules)
	}
}
