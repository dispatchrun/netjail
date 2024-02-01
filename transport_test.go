package netjail_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stealthrocket/netjail"
)

func TestTransport(t *testing.T) {
	const (
		url1 = "http://server1.local"
		url2 = "http://server2.local"

		addr1 = "127.0.0.1"
		addr2 = "10.0.1.2"

		cidr1 = "127.0.0.0/8"
		cidr2 = "10.0.0.0/16"
		cidr3 = "0.0.0.0/0"
	)

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server2.Close()

	error1 := &url.Error{
		Op:  "Get",
		URL: url1,
		Err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.IPAddr{IP: net.IP{127, 0, 0, 1}}, Err: netjail.ErrDenied},
	}

	error2 := &url.Error{
		Op:  "Get",
		URL: url2,
		Err: &net.OpError{Op: "dial", Net: "tcp", Addr: &net.IPAddr{IP: net.IP{10, 0, 1, 2}}, Err: netjail.ErrDenied},
	}

	tests := []struct {
		scenario string
		rules    netjail.Rules
		error1   error
		error2   error
	}{
		{
			scenario: "the default rules denies all addresses",
			rules:    netjail.Rules{},
			error1:   error1,
			error2:   error2,
		},

		{
			scenario: "requests to server 1 are allowed when the rules allow it",
			rules: netjail.Rules{
				Allow: []netip.Prefix{netip.MustParsePrefix(cidr1)},
			},
			error1: nil,
			error2: error2,
		},

		{
			scenario: "requests to server 2 are allowed when the rules allow it",
			rules: netjail.Rules{
				Allow: []netip.Prefix{netip.MustParsePrefix(cidr2)},
			},
			error1: error1,
			error2: nil,
		},

		{
			scenario: "requests to both servers are allowed when the rules allow it",
			rules: netjail.Rules{
				Allow: []netip.Prefix{
					netip.MustParsePrefix(cidr1),
					netip.MustParsePrefix(cidr2),
				},
			},
			error1: nil,
			error2: nil,
		},

		{
			scenario: "requests to server 1 are denied when the rules block it",
			rules: netjail.Rules{
				Allow: []netip.Prefix{netip.MustParsePrefix(cidr3)},
				Block: []netip.Prefix{netip.MustParsePrefix(cidr1)},
			},
			error1: error1,
			error2: nil,
		},

		{
			scenario: "requests to server 2 are denied when the rules block it",
			rules: netjail.Rules{
				Allow: []netip.Prefix{netip.MustParsePrefix(cidr3)},
				Block: []netip.Prefix{netip.MustParsePrefix(cidr2)},
			},
			error1: nil,
			error2: error2,
		},
	}

	dial := new(net.Dialer).DialContext

	mutex := sync.Mutex{}
	conns := []*connTrackingCloseCall{}

	transport := &netjail.Transport{
		New: func() *http.Transport {
			return &http.Transport{
				DialContext: func(ctx context.Context, network, address string) (c net.Conn, err error) {
					addr, _, _ := net.SplitHostPort(address)
					switch addr {
					case addr1:
						c, err = dial(ctx, network, server1.URL[7:])
					case addr2:
						c, err = dial(ctx, network, server2.URL[7:])
					default:
						return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("unknown address: %s", address)}
					}
					if err != nil {
						return nil, err
					}
					conn := &connTrackingCloseCall{Conn: c}
					mutex.Lock()
					conns = append(conns, conn)
					mutex.Unlock()
					return conn, nil
				},
			}
		},
		Resolver: resolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			switch host {
			case url1[7:]:
				return []netip.Addr{netip.MustParseAddr(addr1)}, nil
			case url2[7:]:
				return []netip.Addr{netip.MustParseAddr(addr2)}, nil
			default:
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
		}),
	}

	defer func() {
		transport.CloseIdleConnections()

		mutex.Lock()
		defer mutex.Unlock()

		for _, conn := range conns {
			if !conn.closed.Load() {
				t.Errorf("expected connection to be closed but %s was not", conn.RemoteAddr())
			}
		}
	}()

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client := &http.Client{Transport: transport}

			ctx := netjail.ContextWithRules(context.Background(), &test.rules)
			req1, _ := http.NewRequestWithContext(ctx, http.MethodGet, url1, nil)
			req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, url2, nil)

			if r, err := client.Do(req1); !reflect.DeepEqual(err, test.error1) {
				t.Errorf("expected error %v, got %v", test.error1, err)
			} else if r != nil {
				r.Body.Close()
			}

			if r, err := client.Do(req2); !reflect.DeepEqual(err, test.error2) {
				t.Errorf("expected error %v, got %v", test.error2, err)
			} else if r != nil {
				r.Body.Close()
			}
		})
	}
}

type connTrackingCloseCall struct {
	net.Conn
	closed atomic.Bool
}

func (c *connTrackingCloseCall) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}
