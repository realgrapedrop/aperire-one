package main

import (
	"bufio"
	"os"
	"strings"
)

// interfaceSource values match the JSON contract. Kept as typed constants to
// avoid stringly-typed bugs at the push site.
const (
	sourceDefaultRoute = "default_route"
	sourceConfig       = "config"
	sourceFallbackSum  = "fallback_sum"
)

// resolveInterface returns the primary interface name and how it was chosen.
// The order matches docs/network-metrics-collection.md §NIC auto-discovery.
func resolveInterface(configOverride string) (name, source string) {
	if configOverride != "" && configOverride != "auto" {
		return configOverride, sourceConfig
	}
	if nic := defaultRouteIPv4(); nic != "" {
		return nic, sourceDefaultRoute
	}
	if nic := defaultRouteIPv6(); nic != "" {
		return nic, sourceDefaultRoute
	}
	return "", sourceFallbackSum
}

// defaultRouteIPv4 parses /proc/net/route and returns the interface carrying
// the 0.0.0.0/0 default route. Empty string on absence or parse failure.
//
// Format (tab-separated, header on line 1):
//   Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
//   eth0  00000000    ...
func defaultRouteIPv4() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// defaultRouteIPv6 parses /proc/net/ipv6_route. Format differs from IPv4: one
// line per route, space-separated, destination is a 32-char hex address
// followed by a 2-char hex prefix length. "All zeros + /0" → default route.
func defaultRouteIPv6() string {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		// fields[0] = destination (32 hex chars)
		// fields[1] = destination prefix length (2 hex chars)
		// fields[9] = interface name
		if fields[0] == "00000000000000000000000000000000" && fields[1] == "00" {
			return fields[9]
		}
	}
	return ""
}

// nonVirtualInterfaces returns the set of interface names that look like real
// NICs for the fallback_sum path. Skip patterns match docs.
func isVirtualInterface(name string) bool {
	switch {
	case name == "lo":
		return true
	case strings.HasPrefix(name, "docker"):
		return true
	case strings.HasPrefix(name, "veth"):
		return true
	case strings.HasPrefix(name, "br-"):
		return true
	case strings.HasPrefix(name, "virbr"):
		return true
	case strings.HasPrefix(name, "tun"):
		return true
	case strings.HasPrefix(name, "tap"):
		return true
	case strings.HasPrefix(name, "wg"):
		return true
	case strings.HasPrefix(name, "cni"):
		return true
	}
	return false
}
