package netjail

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var (
	// ErrDenied is an error returned by a dial function when the address is
	// denied by security rules.
	ErrDenied = errors.New("address not allowed")
)

// DialFunc is a type of function used to establish network connections.
//
// The function matches the signatures of standard functions like
// net.(*Dialer).DialContext or http.(*Transport).DialContext.
type DialFunc func(context.Context, string, string) (net.Conn, error)

// Resolver is an interface used to abstract the name resolver used by
// security rules to convert logical hostnames to IP addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Rules is a set of rules used to determine whether a network address can be
// accessed.
//
// By default, the rules denies all addresses. Rules can be added to open
// networks, and further block subsets of the open address space.
type Rules struct {
	Allow []netip.Prefix
	Block []netip.Prefix
}

// String returns a string representation of the security rules.
func (rules *Rules) String() string {
	return string(rules.AppendTo(nil))
}

// AppendTo appends a string representation of the security rules to the given
// byte slice and returns the resulting slice.
func (rules *Rules) AppendTo(data []byte) []byte {
	if rules != nil {
		data = appendPrefixes(data, "ALLOW ", rules.Allow)
		data = appendPrefixes(data, "BLOCK ", rules.Block)
	}
	return data
}

func appendPrefixes(data []byte, title string, prefixes []netip.Prefix) []byte {
	if len(prefixes) > 0 {
		if len(data) > 0 {
			data = append(data, ',', ' ')
		}
		data = append(data, title...)
		for _, prefix := range prefixes {
			data = prefix.AppendTo(data)
			data = append(data, ' ')
		}
		data = data[:len(data)-1]
	}
	return data
}

// Accept returns true if the given address is allowed by the security rules.
func (rules *Rules) Accept(addr netip.Addr) bool {
	if rules != nil {
		for _, allow := range rules.Allow {
			if allow.Contains(addr) {
				for _, block := range rules.Block {
					if block.Contains(addr) {
						return false
					}
				}
				return true
			}
		}
	}
	return false
}

// DialFunc returns a dial function using the given resolver and dialer to
// establish connections to addresses that are allowed by the security rules.
//
// The resolver is used to convert logical hostnames to IP addreses before
// applying the security rules.
//
// If the resolver is nil, net.DefaultResolver is used.
//
// If the dialer is nil, a new dialer is created with the default options.
func (rules *Rules) DialFunc(rslv Resolver, dial DialFunc) DialFunc {
	if rslv == nil {
		rslv = net.DefaultResolver
	}

	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		dialError := func(err error, addr net.Addr) error {
			return &net.OpError{Op: "dial", Net: network, Addr: addr, Err: err}
		}

		denyError := func(addr netip.Addr) error {
			return dialError(ErrDenied, &net.IPAddr{IP: net.IP(addr.AsSlice())})
		}

		dnsError := func(host string) error {
			return dialError(&net.DNSError{Err: "no such host", Name: host, IsNotFound: true}, nil)
		}

		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, dialError(err, nil)
		}

		if addr, _ := netip.ParseAddr(host); addr.IsValid() {
			if !rules.Accept(addr) {
				return nil, denyError(addr)
			}
			return dial(ctx, network, address)
		}

		addrs, err := rslv.LookupNetIP(ctx, ipnet(network), host)
		if err != nil {
			return nil, dialError(err, nil)
		}
		if len(addrs) == 0 {
			return nil, dnsError(host)
		}

		for _, addr := range addrs {
			if rules.Accept(addr) {
				return dial(ctx, network, net.JoinHostPort(addr.String(), port))
			}
		}

		return nil, denyError(addrs[0])
	}
}

func ipnet(network string) string {
	switch network {
	case "tcp", "udp":
		return "ip"
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	default:
		return network
	}
}

// RulesOf returns the network access control rules embedded in
// ctx.
//
// If the context did not contain any rules, nil is returned.
func RulesOf(ctx context.Context) *Rules {
	rules, _ := ctx.Value(networkAccessControlKey{}).(*Rules)
	return rules
}

// WithRules returns a context which embeds the given network
// access control rules.
func WithRules(ctx context.Context, rules *Rules) context.Context {
	return context.WithValue(ctx, networkAccessControlKey{}, rules)
}

type networkAccessControlKey struct{}
