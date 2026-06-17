package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"Polygon/config"
)

// DownloadFromConfig fetches proxies from all providers whose type matches
// proxyType (0 = all types).
func DownloadFromConfig(cfg *config.Config, proxyType int) []Proxy {
	providers := cfg.ProxyProviders
	if proxyType != 0 {
		var filtered []config.ProxyProvider
		for _, p := range providers {
			if p.Type == proxyType {
				filtered = append(filtered, p)
			}
		}
		providers = filtered
	}

	log.Printf("Downloading proxies from %d providers", len(providers))

	var mu sync.Mutex
	var result []Proxy
	var wg sync.WaitGroup

	for _, p := range providers {
		wg.Add(1)
		go func(prov config.ProxyProvider) {
			defer wg.Done()
			proxies, err := downloadProvider(prov)
			if err != nil {
				log.Printf("Provider %s error: %v", prov.URL, err)
				return
			}
			mu.Lock()
			result = append(result, proxies...)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return result
}

func downloadProvider(prov config.ProxyProvider) ([]Proxy, error) {
	pt := Type(prov.Type)
	client := &http.Client{Timeout: time.Duration(prov.Timeout) * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), "GET", prov.URL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", resp.StatusCode, prov.URL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var proxies []Proxy
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		if p, ok := ParseLine(sc.Text(), pt); ok {
			proxies = append(proxies, p)
		}
	}
	return proxies, nil
}

// Check verifies a proxy is reachable by making a GET to testURL.
func Check(p Proxy, testURL string, timeout time.Duration) bool {
	transport := p.HTTPTransport()
	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(context.Background(), "GET", testURL, http.NoBody)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}

// CheckAll filters a proxy slice down to working ones.
func CheckAll(proxies []Proxy, testURL string, timeout time.Duration, workers int) []Proxy {
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var alive []Proxy
	var wg sync.WaitGroup

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(px Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			if Check(px, testURL, timeout) {
				mu.Lock()
				alive = append(alive, px)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return alive
}
