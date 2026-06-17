// Package utils provides shared low-level helpers used across all packages.
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
)

// RandStr returns a random alphanumeric string of length n.
func RandStr(n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[mrand.Intn(len(charset))]
	}
	return string(b)
}

// RandBytes returns n random bytes.
func RandBytes(n int) []byte {
	b := make([]byte, n)
	mrand.Read(b)
	return b
}

// RandIPv4 returns a random public IPv4 address string.
func RandIPv4() string {
	for {
		ip := net.IPv4(
			byte(mrand.Intn(223)+1),
			byte(mrand.Intn(256)),
			byte(mrand.Intn(256)),
			byte(mrand.Intn(254)+1),
		)
		if !isPrivate(ip) {
			return ip.String()
		}
	}
}

// RandPort returns a random high port (1024–65535).
func RandPort() uint16 {
	return uint16(1024 + mrand.Intn(64511))
}

// RandInt returns a random integer in [min, max].
func RandInt(min, max int) int {
	if max <= min {
		return min
	}
	return min + mrand.Intn(max-min+1)
}

// RandChoice returns a random element from slice s.
func RandChoice[T any](s []T) T {
	return s[mrand.Intn(len(s))]
}

// UUID4 returns a random UUID v4 string.
func UUID4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// RandHex returns a random hex string of n bytes (2n chars).
func RandHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// RandSteamID returns a random Steam64 ID in the valid range.
func RandSteamID() int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(2038034271))
	return 76561197960265728 + n.Int64()
}

func isPrivate(ip net.IP) bool {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "100.64.0.0/10",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil && block.Contains(ip) {
			return true
		}
	}
	return false
}
