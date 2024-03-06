# netjail

[![Build](https://github.com/stealthrocket/netjail/actions/workflows/test.yml/badge.svg)](https://github.com/stealthrocket/netjail/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/stealthrocket/netjail)](https://goreportcard.com/report/github.com/stealthrocket/netjail)
[![Go Reference](https://pkg.go.dev/badge/github.com/stealthrocket/netjail.svg)](https://pkg.go.dev/github.com/stealthrocket/netjail)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Go library providing network access controls for dial functions and http transports

## Motivation

Modern production systems are becoming increasingly complex, and often need to
perform actions that are controlled by user input. For example, users may be
given the option to define a Webhook URL to send data to, sometimes as part of
a larger workflow. Applications that give users the ability to control network
requests are exposed to the security risks of seeing those functionalities
exploited to perform unintended actions. Attackers can use these features to
forge network requests to internal systems, either to access private information
or perform actions they should not be permitted to.

Classic network access controls are effective measures to lock down access to
protected systems; however, they are not enough.

Consider the case of deploying an application as an AWS Lambda Function. Lambda
offers very strong isolation guarantees thanks to Firecracker,
and the execution model guaranteeing that each instance of the function serves
at most one concurrent invocation. However, the protocol used by AWS Lambda to
receive function invocations uses a *long-poll* http request to a localhost
endpoint. Security groups implemented by the network cannot prevent the program
from connecting to the loopback interface, and a malicious input could forge
requests to the local endpoint that the program was not supposed to make.

Lambda is one example, but there are many others, like an application invoking
itself on unprotected internal endpoints, or sending requests to sidecar
containers. Programs that have the ability to open connections to addresses
extracted from user input must implement protections that the network layer
cannot provide, which is what this package solves for.

## Installation

This package is a library, it is intended to be used as a dependency in another
application:
```
go get github.com/stealthrocket/netjail
```

## Usage

The library covers tow main use cases: controlling network access at the HTTP
and TCP layers.

Programs can import the package with:
```go
import "github.com/stealthrocket/netjail"
```

### Declaring rules for network access controls

Programs configure the set of networks that the application can connect to by
declaring lists of **allowed** and **blocked** network ranges. An empty rule set
denies access to all networks. The list of allowed prefixes opens access to
networks, and subnets can be restricted further by the list of blocked prefixes.

This example shows how to declare rules that allow connecting to all networks
except loopback interfaces:
```go
allIPv4 := netip.MustParsePrefix("0.0.0.0/0")
allIPv6 := netip.MustParsePrefix("::/0")

localhostIPv4 := netip.MustParsePrefix("127.0.0.0/8")
localhostIPv6 := netip.MustParsePrefix("::1/128")

rules := &netjail.Rules{
    Allow: []netip.Prefix{
        allIPv4,
        allIPv6,
    },
    Block: []netip.Prefix{
        localhostIPv4,
        localhostIPv6,
    },
}
```

Network access controls often need to be propagated through the call stack of an
application, which can be done by embedding the rules in a
[`context.Context`](https://pkg.go.dev/context#Context) using this function:
```go
ctx = netjail.ContextWithRules(ctx, rules)
```
The rules can later be retrieved by this function:
```go
rules := netjail.ContextRules(ctx)
```
If the context does not contain any rules, the returned value is `nil`, which
behaves like an empty rule set, and denies all network access. This is critical
to **fail closed** in the presence of application misconfiguration or errors.

### Network access controls for HTTP transports

The package provides an implementation of
[`http.RoundTripper`][httpRoundTripper] that extracts the set of network access
control rules from the context of an [`http.Request`][httpRequest], and applies
the rules to the connection used to serve the request.

The HTTP transport works by dynamically creating instances of
[`http.Transport`][httpTransport], and overriding the dial function to apply
network access controls.

The following examples shows how to construct a secured client that applies a
set of rules to the requests it serves:
```go
secureClient := &http.Client{
    Transport: &netjail.Transport{
        New: func() *http.Transport{
            // We must return a different instance each time the
            // function is called, the transport would otherwise
            // panic if it sees the same value more than once.
            return http.DefaultTransport.(*http.Transport).Clone()
        },
    },
}

...

// The context used to construct the request contains the network access
// control rules that will be applied when passed to the client.
ctx = netjail.ContextWithRules(ctx, &netjail.Rules{
    ...
})

req, err := http.NewRequestWithContext(ctx, "GET", userProvidedURL, nil)
...

res, err := secureClient.Do(req)
if err != nil {
    if errors.Is(err, netjail.ErrDenied) {
        // The request was intended for a forbidden address
        ...
    }
    ...
}
```

[httpRoundTripper]: https://pkg.go.dev/net/http#RoundTripper
[httpRequest]:      https://pkg.go.dev/net/http#Request.Context
[httpTransport]:    https://pkg.go.dev/net/http#Transport

### Network access controls for TCP connections

While most applications use HTTP or protocols that are based on HTTP, some may
need to apply network access controls to clients of other protocols
(e.g., MySQL, Redis, Kafka, etc...).

Libraries that provide clients for these protocols will often allow configuring
a dial function to customize how network connections are opened. This dial
function is the bottom-most hook that the `netjail` package can integrate with
to apply security rules to any client.

The [`netjail.(*Rules).DialFunc`][dialFunc] method is the low-level wrapper that
decorates dial functions to apply network access controls defined in the
originating rules.

[dialFunc]: https://pkg.go.dev/github.com/stealthrocket/netjail#Rules.DialFunc

## Security Considerations

### Protection against DNS rebinding attacks

DNS rebinding attacks occur when an attacker attempts to forge the DNS responses
received by an application, to route connections to addresses of their choosing.
For example, they could cause the DNS resolution for *example.com* to resolve to
*127.0.0.1*, resulting in the application unknowningly connecting to localhost
instead of a remote server.

To prevent these types of attacks, the `netjail` package takes over the entire
connection process. It first resolves hostnames to a set of network addresses,
then validates those addresses against the allow and block lists, and only opens
connection to an address that passed the checks. With this process, there is no
risk of confusion between the validation and connection phases, effectively
protecting the application against DNS rebinding attacks that would attempt to
bypass network access controls.

### Protection against software defects and supplychain attacks

Software security threats come in many forms, each dependency of a program can
become the target of an attacker, and beyond that, even the process by which the
software is built and delivered can become the target of attackers. Producing
secure software requires the combination of multiple mitigation strategies to
defend against the variety of risks that the system is exposed to.

To limit exposure to those risks, the `netjail` package is designed to have no
dependencies besides the Go standard library, and will remain dependency-free.
The package has a well-defined scope, if new features are added, it will always
be preferable to bring the code *in-house* than take a dependency on a third
party.

We used design decisions that reduce the risk of seeing security exploits arise
in buggy software. We limit the use of interface types, because abstractions
make it more difficult to validate how the software will behave when components
are replaced at run time. The use of concrete types offer stronger guarantees,
and reduce the scope that tests need to cover. In addition, the library applies
extensive validations against the inputs that it receives, and always defaults
to **failing closed** or **failing loud** (e.g., blocking network connections,
panicking in the presence of invalid state).
