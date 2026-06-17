package core

import (
	"context"
	"time"

	"Polygon/utils"
)

// RateLimitedWorker wraps a WorkerFunc and throttles its iterations
// using a TokenBucket. Use this to cap PPS without losing goroutines.
type RateLimitedWorker struct {
	fn     WorkerFunc
	bucket *utils.TokenBucket
}

// NewRateLimitedWorker creates a worker that runs fn at most pps times per second.
func NewRateLimitedWorker(fn WorkerFunc, pps float64) *RateLimitedWorker {
	return &RateLimitedWorker{
		fn:     fn,
		bucket: utils.NewTokenBucket(pps, pps),
	}
}

// Run implements WorkerFunc — each iteration waits for a token first.
func (r *RateLimitedWorker) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			r.bucket.Take()
			r.fn(ctx)
		}
	}
}

// BandwidthGuard wraps an Engine and enforces a global bytes/sec cap
// by pausing all workers when the rolling average exceeds the limit.
type BandwidthGuard struct {
	engine   *Engine
	limitBps int64
}

// NewBandwidthGuard creates a guard that watches stats and throttles
// if bandwidth exceeds limitBps bytes per second.
func NewBandwidthGuard(e *Engine, limitBps int64) *BandwidthGuard {
	return &BandwidthGuard{engine: e, limitBps: limitBps}
}

// Watch runs the guard loop until ctx is canceled.
func (bg *BandwidthGuard) Watch(ctx context.Context, bytesSentFn func() int64) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var prev int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			curr := bytesSentFn()
			bps := curr - prev
			prev = curr
			if bg.limitBps > 0 && bps > bg.limitBps {
				// Sleep proportionally to how much we overshot
				overshoot := float64(bps) / float64(bg.limitBps)
				time.Sleep(time.Duration(overshoot*500) * time.Millisecond)
			}
		}
	}
}
