package netjail

import "context"

// ContextRules returns the network access control rules embedded in ctx.
//
// If the context did not contain any rules, nil is returned.
func ContextRules(ctx context.Context) *Rules {
	rules, _ := ctx.Value(networkAccessControlKey{}).(*Rules)
	return rules
}

// ContextWithRules returns a context which embeds the given network access
// control rules.
func ContextWithRules(ctx context.Context, rules *Rules) context.Context {
	return context.WithValue(ctx, networkAccessControlKey{}, rules)
}

type networkAccessControlKey struct{}
