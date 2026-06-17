// Package net — WAF/CDN fingerprinting from HTTP response headers.
package net

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

// Provider represents a detected CDN or WAF vendor.
type Provider string

const (
	ProviderNone         Provider = "none"
	ProviderCloudflare   Provider = "cloudflare"
	ProviderOVH          Provider = "ovh"
	ProviderDDoSGuard    Provider = "ddos-guard"
	ProviderArvanCloud   Provider = "arvancloud"
	ProviderGoogleShield Provider = "google-shield"
	ProviderAkamai       Provider = "akamai"
	ProviderFastly       Provider = "fastly"
	ProviderIncapsula    Provider = "incapsula"
	ProviderNginx        Provider = "nginx"
	ProviderApache       Provider = "apache"
)

// FingerprintResult holds the detected provider and the recommended method.
type FingerprintResult struct {
	Provider          Provider
	RecommendedMethod string
	Headers           map[string]string
	StatusCode        int
}

var client = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	},
	// Do not follow redirects — we want the raw response headers.
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Fingerprint probes url and returns the detected provider + recommended attack method.
func Fingerprint(url string) FingerprintResult {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return FingerprintResult{Provider: ProviderNone}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")

	resp, err := client.Do(req)
	if err != nil {
		return FingerprintResult{Provider: ProviderNone}
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}

	provider := detectProvider(headers)
	method := recommendMethod(provider)

	return FingerprintResult{
		Provider:          provider,
		RecommendedMethod: method,
		Headers:           headers,
		StatusCode:        resp.StatusCode,
	}
}

func detectProvider(h map[string]string) Provider {
	server := strings.ToLower(h["server"])
	via := strings.ToLower(h["via"])
	xPowered := strings.ToLower(h["x-powered-by"])

	switch {
	case h["cf-ray"] != "" || strings.Contains(server, "cloudflare"):
		return ProviderCloudflare
	case h["x-ddos-guard"] != "" || strings.Contains(server, "ddos-guard"):
		return ProviderDDoSGuard
	case h["x-arvan-cache"] != "" || strings.Contains(xPowered, "arvancloud"):
		return ProviderArvanCloud
	case strings.Contains(via, "google") || h["x-goog-cache-status"] != "":
		return ProviderGoogleShield
	case strings.Contains(server, "akamai") || h["x-check-cacheable"] != "":
		return ProviderAkamai
	case strings.Contains(server, "fastly") || h["x-served-by"] != "":
		return ProviderFastly
	case h["x-iinfo"] != "" || strings.Contains(server, "incapsula"):
		return ProviderIncapsula
	case h["x-ovh-token"] != "" || strings.Contains(via, "ovh"):
		return ProviderOVH
	case strings.Contains(server, "nginx"):
		return ProviderNginx
	case strings.Contains(server, "apache"):
		return ProviderApache
	default:
		return ProviderNone
	}
}

func recommendMethod(p Provider) string {
	switch p {
	case ProviderCloudflare:
		return "CFB"
	case ProviderDDoSGuard:
		return "DGB"
	case ProviderArvanCloud:
		return "AVB"
	case ProviderGoogleShield:
		return "GSB"
	case ProviderOVH:
		return "OVH"
	case ProviderAkamai, ProviderFastly, ProviderIncapsula:
		return "BYPASS"
	case ProviderApache:
		return "APACHE"
	default:
		return "GET"
	}
}
