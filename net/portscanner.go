package net

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// ScanResult holds the result for a single port.
type ScanResult struct {
	Port   int
	Open   bool
	Banner string
}

// ScanPorts scans the given ports on host concurrently.
// workers controls parallelism; timeout is per-port dial timeout.
func ScanPorts(ctx context.Context, host string, ports []int, workers int, timeout time.Duration) []ScanResult {
	work := make(chan int, len(ports))
	for _, p := range ports {
		work <- p
	}
	close(work)

	var mu sync.Mutex
	var results []ScanResult
	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			for port := range work {
				select {
				case <-ctx.Done():
					return
				default:
				}
				r := probePort(host, port, timeout)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	return results
}

// CommonPorts is the list of ports scanned by default.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
	993, 995, 1433, 1521, 2082, 2083, 2086, 2087, 2095, 2096,
	3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017,
}

func probePort(host string, port int, timeout time.Duration) ScanResult {
	addr := net.JoinHostPort(host, itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ScanResult{Port: port, Open: false}
	}
	defer conn.Close()

	// Attempt banner grab (100ms read window)
	banner := ""
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner = string(buf[:n])
	}

	return ScanResult{Port: port, Open: true, Banner: banner}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 5)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
