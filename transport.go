package netjail

import (
	"container/list"
	"context"
	"crypto/sha256"
	"net"
	"net/http"
	"sync"
)

// Transport is a type similar to http.Transport, but which applies rules for
// network access control embedded in the context of requests it serves.
//
// Requests that don't include network access control rules are always denied.
//
// Requests that are denied fail with the error ErrDenied.
//
// The implementation of this http transport uses http.Transport instances
// rather than http.RoundTripper. This design decision helps to limit the
// potential edge cases that may arise if applications are allowed to inject
// arbitrary http.RoundTripper instances into the transport. Since the purpose
// of this transport is to apply security controls, we want to optimize for
// safety, at the expense of composability in this case. Applications that need
// a more flexible integration can use the Rules type directly, by wrapping the
// dialers to implement network access controls.
type Transport struct {
	// A function used to create http transports for each network access control
	// configuration.
	//
	// The function must create a new http.Transport instance, and return it.
	// A panic is triggered if the function returns nil, or if it returns the
	// same http.Transport more than once.
	//
	// The returned http.Transport cannot have DialTLS or DialTLSContext set,
	// or a panic is triggered. This is due to network access controls having to
	// be applied before the TLS handshake on the IP addresses resolved from the
	// hostname in the request, but DialTLS and DialTSLContext need to receive
	// the hostname to validate the server certificate, which couples the
	// function to name resolution.
	//
	// A simple implementation of this function is to close the default http
	// transport:
	//
	//	New: func() *http.Transport {
	//		return http.DefaultTransport.(*http.Transport).Clone()
	//	}
	//
	// The function might be invoked concurrently from multiple goroutines.
	New func() *http.Transport

	// The resolver used to convert logical hostnames to IP addresses before
	// checking network access controls.
	//
	// If nil, the default resolver is used.
	Resolver Resolver

	// Maximum number of idle transports to retain. If the limit is reached,
	// the least recently used transport is evicted, and CloseIdleConnections
	// called.
	//
	// Default to 256.
	MaxIdleTransports int

	// This value holds the map of network access control rule ids to http
	// transports.
	//
	// At this time, the map never shrinks, which means that we must be careful
	// not to accept unvalidated input in the network access controls
	// configuration.
	transports map[[sha256.Size]byte]*list.Element

	// Keep track of the http.Transport instances created by the New function
	// to ensure that it does not return the same value twice. This is important
	// to guarantee secure isolation between different network access controls.
	instances map[*http.Transport]struct{}

	// LRU list of network access control rule ids to evict unused transports.
	lru list.List

	// Mutex used to synchronize access to the maps of transports.
	mutex sync.Mutex
}

type jailedTransport struct {
	rulesID   [sha256.Size]byte
	transport *http.Transport
}

func (t *Transport) CloseIdleConnections() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, elem := range t.transports {
		elem.Value.(*jailedTransport).transport.CloseIdleConnections()
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.grabTransport(ContextRules(req.Context())).RoundTrip(req)
}

func (t *Transport) grabTransport(rules *Rules) *http.Transport {
	rulesID := sha256.Sum256(rules.AppendTo(make([]byte, 0, 512)))

	var evicted *http.Transport
	t.mutex.Lock()
	defer func() {
		t.mutex.Unlock()
		if evicted != nil { // do without holding the lock
			evicted.CloseIdleConnections()
		}
	}()

	elem := t.transports[rulesID]
	if elem != nil {
		t.lru.MoveToFront(elem)
		return elem.Value.(*jailedTransport).transport
	}

	if t.transports == nil {
		t.transports = make(map[[sha256.Size]byte]*list.Element)
	}
	if t.instances == nil {
		t.instances = make(map[*http.Transport]struct{})
	}

	transport := t.newTransport(rules)
	if _, exists := t.instances[transport]; exists {
		panic("netjail: transport constructor returned the same transport more than once")
	}

	elem = t.lru.PushFront(&jailedTransport{
		rulesID:   rulesID,
		transport: transport,
	})

	t.transports[rulesID] = elem
	t.instances[transport] = struct{}{}

	if len(t.transports) > t.maxIdleTransports() {
		e := t.lru.Remove(t.lru.Back()).(*jailedTransport)
		evicted = e.transport
		delete(t.transports, e.rulesID)
		delete(t.instances, e.transport)
	}

	return transport
}

func (t *Transport) newTransport(rules *Rules) *http.Transport {
	transport := t.New()

	// Don't accept the default transport, this could result in reusing
	// connections that were established before the network access control
	// rules were applied.
	if t, ok := http.DefaultTransport.(*http.Transport); ok && t == transport {
		panic("netjail: transport returned by New is the default transport")
	}

	// Extract the dial function used by the transport so we can wrap it
	// with the network access control check.
	dialContext := transport.DialContext
	if dialContext == nil {
		if transport.Dial == nil { //nolint
			dialContext = new(net.Dialer).DialContext
		} else {
			dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return transport.Dial(network, address) //nolint
			}
		}
	}

	transport.Dial = nil //nolint
	transport.DialContext = rules.DialFunc(t.Resolver, dialContext)
	// TODO: support TLS dialers; the TLS dialer needs to know the hostname that
	// the request is being sent to, which the dial function returned by
	// (*Rules).DialFunc masks.
	//
	// We will need to add a (*Rules).DialTLSFunc method which combines both the
	// network access control check and the TLS handshake.
	if transport.DialTLS != nil { //nolint
		panic("netjail: transport returned by New has DialTLS set")
	}
	if transport.DialTLSContext != nil {
		panic("netjail: transport returned by New has DialTLSContext set")
	}
	return transport
}

func (t *Transport) maxIdleTransports() int {
	if t.MaxIdleTransports > 0 {
		return t.MaxIdleTransports
	}
	return 256
}
