package core

import (
	"context"
	"log"
	"time"
)

// WaveConfig defines one wave in a multi-phase attack schedule.
type WaveConfig struct {
	Name     string
	Threads  int
	Duration time.Duration
	// Pause between this wave and the next.
	CoolDown time.Duration
}

// WaveScheduler runs waves sequentially, scaling goroutine count up/down.
// This creates a realistic stress pattern and avoids predictable traffic shapes.
type WaveScheduler struct {
	engine *Engine
	waves  []WaveConfig
}

// NewWaveScheduler creates a scheduler with the given wave sequence.
func NewWaveScheduler(e *Engine, waves []WaveConfig) *WaveScheduler {
	return &WaveScheduler{engine: e, waves: waves}
}

// Run executes all waves in order until ctx is canceled.
func (ws *WaveScheduler) Run(ctx context.Context, fn WorkerFunc) {
	for i, wave := range ws.waves {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("[wave %d/%d] %s — %d threads for %s",
			i+1, len(ws.waves), wave.Name, wave.Threads, wave.Duration)

		waveCtx, cancel := context.WithTimeout(ctx, wave.Duration)
		ws.engine.Spawn(waveCtx, wave.Threads, fn)
		<-waveCtx.Done()
		cancel()

		if wave.CoolDown > 0 {
			log.Printf("[wave %d/%d] cooldown %s", i+1, len(ws.waves), wave.CoolDown)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wave.CoolDown):
			}
		}
	}
	log.Println("[scheduler] all waves complete")
}

// SlowStartWaves builds a slow-start → peak → cooldown wave sequence.
// steps: how many ramp-up steps; peakThreads: max goroutines; duration: total time.
func SlowStartWaves(peakThreads, steps int, duration time.Duration) []WaveConfig {
	waves := make([]WaveConfig, 0, steps+2)
	stepDur := duration / time.Duration(steps+2)

	// Ramp up
	for i := 1; i <= steps; i++ {
		t := peakThreads * i / steps
		waves = append(waves, WaveConfig{
			Name:     "ramp-up",
			Threads:  t,
			Duration: stepDur,
		})
	}
	// Peak
	waves = append(waves, WaveConfig{
		Name:     "peak",
		Threads:  peakThreads,
		Duration: stepDur,
		CoolDown: stepDur / 4,
	})
	return waves
}
