package netjail_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"

	"github.com/stealthrocket/netjail"
)

func ExampleTransport() {
	// This rule set only allows connecting to a private IPv4 network.
	ctx := netjail.ContextWithRules(context.Background(),
		&netjail.Rules{
			Allow: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
			},
		},
	)

	client := &http.Client{
		Transport: &netjail.Transport{
			New: func() *http.Transport {
				return http.DefaultTransport.(*http.Transport).Clone()
			},
		},
	}

	r, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/", nil)
	if err != nil {
		log.Fatal(err)
	}

	if r, err := client.Do(r); err != nil {
		if !errors.Is(err, netjail.ErrDenied) {
			log.Fatal(err)
		} else {
			fmt.Println("Access Denied")
		}
	} else {
		r.Body.Close()
		fmt.Println("Access Granted")
	}

	// Output:
	// Access Denied
}
