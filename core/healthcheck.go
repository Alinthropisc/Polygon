package core

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"time"
)

// TargetStatus represents whether the target is up or down.
type TargetStatus int

const (
	StatusUnknown TargetStatus = iota
	StatusUp
	StatusDown
)

// HealthChecker polls a target URL and reports when it goes down.
type HealthChecker struct {
	URL      string
	Interval time.Duration
	Timeout  time.Duration

	// OnDown is called when the target transitions to down.
	OnDown func()
	// OnUp is called when the target recovers.
	OnUp func()

	client *http.Client
	last   TargetStatus
}

// NewHealthChecker creates a checker with sensible defaults.
func NewHealthChecker(url string) *HealthChecker {
	return &HealthChecker{
		URL:      url,
		Interval: 3 * time.Second,
		Timeout:  4 * time.Second,
		OnDown:   func() { log.Printf("[healthcheck] TARGET DOWN: %s", url) },
		OnUp:     func() { log.Printf("[healthcheck] TARGET RECOVERED: %s", url) },
		client: &http.Client{
			Timeout: 4 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// Run starts polling until ctx is cancelled. Logs status transitions.
func (hc *HealthChecker) Run(ctx context.Context) {
	ticker := time.NewTicker(hc.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status := hc.probe()
			if status != hc.last {
				if status == StatusDown && hc.OnDown != nil {
					hc.OnDown()
				} else if status == StatusUp && hc.last == StatusDown && hc.OnUp != nil {
					hc.OnUp()
				}
				hc.last = status
			}
		}
	}
}

// IsDown returns true if the last probe failed.
func (hc *HealthChecker) IsDown() bool { return hc.last == StatusDown }

func (hc *HealthChecker) probe() TargetStatus {
	req, err := http.NewRequest("HEAD", hc.URL, nil)
	if err != nil {
		return StatusDown
	}
	resp, err := hc.client.Do(req)
	if err != nil {
		return StatusDown
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return StatusDown
	}
	return StatusUp
}
