package netjail_test

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stealthrocket/netjail"
)

func TestRulesString(t *testing.T) {
	tests := []struct {
		scenario string
		rules    netjail.Rules
		expected string
	}{
		{
			scenario: "empty rules",
			rules:    netjail.Rules{},
			expected: "",
		},

		{
			scenario: "rules with allowed prefixes",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("::1/128"),
				},
			},
			expected: "ALLOW 127.0.0.0/8 ::1/128",
		},

		{
			scenario: "rules with blocked prefixes",
			rules: netjail.Rules{
				Block: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("::1/128"),
				},
			},
			expected: "BLOCK 127.0.0.0/8 ::1/128",
		},

		{
			scenario: "rules with allowed and blocked prefixes",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
					netip.MustParsePrefix("::/0"),
				},
				Block: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("::1/128"),
				},
			},
			expected: "ALLOW 0.0.0.0/0 ::/0, BLOCK 127.0.0.0/8 ::1/128",
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			if test.rules.String() != test.expected {
				t.Errorf("expected %v, got %v", test.expected, test.rules.String())
			}
		})
	}
}

func TestRulesAccept(t *testing.T) {
	tests := []struct {
		scenario string
		rules    netjail.Rules
		addr     netip.Addr
		allow    bool
	}{
		{
			scenario: "the default rules denies all addresses",
			rules:    netjail.Rules{},
			addr:     netip.MustParseAddr("127.0.0.1"),
			allow:    false,
		},

		{
			scenario: "the rules passes if the address is allowed",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			addr:  netip.MustParseAddr("10.0.1.2"),
			allow: true,
		},

		{
			scenario: "the rules fails if the address is blocked",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
				Block: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			addr:  netip.MustParseAddr("10.0.1.2"),
			allow: false,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			if test.rules.Accept(test.addr) != test.allow {
				t.Errorf("expected %v to contain %v", test.rules, test.addr)
			}
		})
	}
}

func TestRulesDialFunc(t *testing.T) {
	tests := []struct {
		scenario string
		rules    netjail.Rules
		network  string
		address  string
		rslvIPs  []netip.Addr
		rslvErr  error
		err      error
	}{
		{
			scenario: "the dial function passes if the address is allowed",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			network: "tcp",
			address: "10.0.1.2:1234",
			err:     nil,
		},

		{
			scenario: "the dial function fails if the address is blocked",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
				Block: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			network: "tcp",
			address: "10.0.1.2:1234",
			err:     &net.OpError{Op: "dial", Net: "tcp", Addr: &net.IPAddr{IP: net.IP{10, 0, 1, 2}}, Err: netjail.ErrDenied},
		},

		{
			scenario: "the dial function passes if the resolved address is allowed",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			network: "tcp",
			address: "hostname:1234",
			rslvIPs: []netip.Addr{netip.MustParseAddr("10.0.1.2")},
			err:     nil,
		},

		{
			scenario: "the dial function fails if the resolved address is blocked",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
				Block: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			network: "tcp",
			address: "hostname:1234",
			rslvIPs: []netip.Addr{netip.MustParseAddr("10.0.1.2")},
			err:     &net.OpError{Op: "dial", Net: "tcp", Addr: &net.IPAddr{IP: net.IP{10, 0, 1, 2}}, Err: netjail.ErrDenied},
		},

		{
			scenario: "the dial function fails if the address is invalid",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			network: "tcp",
			address: "hostname",
			err:     &net.OpError{Op: "dial", Net: "tcp", Err: &net.AddrError{Err: "missing port in address", Addr: "hostname"}},
		},

		{
			scenario: "the dial function fails if the resolver returns an error",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			network: "tcp",
			address: "hostname:1234",
			rslvErr: &net.DNSError{Err: "no such host", Name: "hostname", IsNotFound: true},
			err:     &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "hostname", IsNotFound: true}},
		},

		{
			scenario: "the dial function fails if the resolver returns no addresses",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix("127.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/16"),
				},
			},
			network: "tcp",
			address: "hostname:1234",
			err:     &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "hostname", IsNotFound: true}},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			rslv := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				return test.rslvIPs, test.rslvErr
			})

			dial := test.rules.DialFunc(rslv, func(context.Context, string, string) (net.Conn, error) {
				return testConn{}, nil
			})

			_, err := dial(context.Background(), test.network, test.address)
			if !reflect.DeepEqual(err, test.err) {
				t.Errorf("expected error %v, got %v", test.err, err)
			}
		})
	}
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (fn resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return fn(ctx, network, host)
}

type testConn struct{}

func (testConn) Read([]byte) (int, error)         { return 0, nil }
func (testConn) Write([]byte) (int, error)        { return 0, nil }
func (testConn) Close() error                     { return nil }
func (testConn) LocalAddr() net.Addr              { return nil }
func (testConn) RemoteAddr() net.Addr             { return nil }
func (testConn) SetDeadline(time.Time) error      { return nil }
func (testConn) SetReadDeadline(time.Time) error  { return nil }
func (testConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkRulesAllowIPv4(b *testing.B) {
	rules := netjail.Rules{
		Allow: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
		},
	}

	addr := netip.MustParseAddr("127.0.0.1")

	for i := 0; i < b.N; i++ {
		rules.Accept(addr)
	}
}

func BenchmarkRulesAllowIPv6(b *testing.B) {
	rules := netjail.Rules{
		Allow: []netip.Prefix{
			netip.MustParsePrefix("::/128"),
		},
	}

	addr := netip.MustParseAddr("::1")

	for i := 0; i < b.N; i++ {
		rules.Accept(addr)
	}
}
