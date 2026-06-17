// Package net provides DNS resolution, IP utilities, and host fingerprinting
// used across attack methods and the console tool.
package net

import (
	"context"
	"fmt"
	gonet "net"
	"strings"
	"time"
)

// ResolveHost resolves a hostname to its first IPv4 address.
// Returns the original string unchanged if it is already an IP.
func ResolveHost(host string) (string, error) {
	if gonet.ParseIP(host) != nil {
		return host, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := gonet.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	// Prefer IPv4
	for _, a := range addrs {
		if gonet.ParseIP(a).To4() != nil {
			return a, nil
		}
	}
	return addrs[0], nil
}

// StripURL removes scheme and path, returning only host:port or host.
func StripURL(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.SplitN(s, "/", 2)[0]
}

// SplitHostPort splits a host:port string, defaulting port to 80.
func SplitHostPort(hostport string) (host string, port int, err error) {
	h, p, e := gonet.SplitHostPort(hostport)
	if e != nil {
		return hostport, 80, nil
	}
	_, err = fmt.Sscanf(p, "%d", &port)
	return h, port, err
}

// GetLocalIP returns the machine's primary outbound IP.
func GetLocalIP() (string, error) {
	conn, err := gonet.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*gonet.UDPAddr).IP.String(), nil
}

// IsPrivateIP returns true for RFC-1918 / loopback addresses.
func IsPrivateIP(ip string) bool {
	parsed := gonet.ParseIP(ip)
	if parsed == nil {
		return false
	}
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
	}
	for _, cidr := range private {
		_, net, _ := gonet.ParseCIDR(cidr)
		if net != nil && net.Contains(parsed) {
			return true
		}
	}
	return false
}

// LookupSRV wraps net.LookupSRV with a timeout.
func LookupSRV(service, proto, host string) ([]*gonet.SRV, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, addrs, err := gonet.DefaultResolver.LookupSRV(ctx, service, proto, host)
	return addrs, err
}
