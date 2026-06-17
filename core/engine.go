// Package core is the central orchestrator: it creates attack workers,
// manages their lifecycle via context, and exposes a unified Engine API.
package core

import (
	"context"
	"log"
	"sync"
	"time"

	"Polygon/proxy"
	"Polygon/stats"
	"Polygon/tools"
)

// WorkerFunc is a function that runs until ctx is cancelled.
type WorkerFunc func(ctx context.Context)

// Engine coordinates goroutine pools for flood attacks.
type Engine struct {
	mu      sync.Mutex
	workers []context.CancelFunc
	cfg     engineConfig
}

// Spawn starts n goroutines running fn, all sharing a child of ctx.
func (e *Engine) Spawn(ctx context.Context, n int, fn WorkerFunc) context.CancelFunc {
	child, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	e.workers = append(e.workers, cancel)
	e.mu.Unlock()
	for i := 0; i < n; i++ {
		go fn(child)
	}
	return cancel
}

// StopAll cancels every worker spawned by this engine.
func (e *Engine) StopAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, cancel := range e.workers {
		cancel()
	}
	e.workers = nil
}

// Layer4Config holds parameters for a Layer 4 flood.
type Layer4Config struct {
	Target     string
	Port       uint16
	Method     string
	Refs       []string
	Proxies    []proxy.Proxy
	ProtocolID int
	Threads    int
	Duration   time.Duration
}

// Layer7Config holds parameters for a Layer 7 flood.
type Layer7Config struct {
	TargetURL  string
	Host       string
	Method     string
	RPC        int
	UserAgents []string
	Referers   []string
	Proxies    []proxy.Proxy
	Threads    int
	Duration   time.Duration
}

func statsLoop(ctx context.Context, target, method string, totalSec int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			reqs, bytes := stats.Snapshot()
			log.Printf("[done] %s | %s | total PPS=%s BPS=%s",
				target, method,
				tools.HumanFormat(reqs), tools.HumanBytes(bytes))
			return
		case <-ticker.C:
			reqs, bytes := stats.Snapshot()
			stats.Reset()
			elapsed := int(time.Since(start).Seconds())
			pct := 0
			if totalSec > 0 {
				pct = elapsed * 100 / totalSec
			}
			log.Printf("[%d%%] target=%s method=%s pps=%s bps=%s",
				pct, target, method,
				tools.HumanFormat(reqs), tools.HumanBytes(bytes))
		}
	}
}
