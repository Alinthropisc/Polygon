package tools

import (
	"fmt"
	"math"
	"net"
)

// HumanBytes formats a byte count into a human-readable string.
func HumanBytes(i int64) string {
	if i <= 0 {
		return "-- B"
	}
	suffixes := []string{"B", "kB", "MB", "GB", "TB", "PB"}
	exp := int(math.Log(float64(i)) / math.Log(1000))
	if exp >= len(suffixes) {
		exp = len(suffixes) - 1
	}
	val := float64(i) / math.Pow(1000, float64(exp))
	return fmt.Sprintf("%.2f %s", val, suffixes[exp])
}

// HumanFormat formats a large integer with k/m/g suffixes.
func HumanFormat(n int64) string {
	suffixes := []string{"", "k", "m", "g", "t", "p"}
	if n <= 999 {
		return fmt.Sprintf("%d", n)
	}
	exp := 0
	for exp < len(suffixes)-1 && math.Abs(float64(n)/math.Pow(1000, float64(exp+1))) >= 1 {
		exp++
	}
	return fmt.Sprintf("%.2f%s", float64(n)/math.Pow(1000, float64(exp)), suffixes[exp])
}

// LocalIP returns the machine's outbound IP address.
func LocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// CheckRawSocket returns true if the process can open a raw TCP socket.
func CheckRawSocket() bool {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
