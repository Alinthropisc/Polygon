package proto

import (
	"fmt"
	"strings"
)

// HTTPVersion constants.
const (
	HTTP10 = "1.0"
	HTTP11 = "1.1"
)

// Header is a simple ordered key-value pair for HTTP headers.
type Header struct{ Key, Value string }

// RequestBuilder builds raw HTTP/1.x request bytes without the net/http overhead.
type RequestBuilder struct {
	method  string
	path    string
	version string
	headers []Header
	body    []byte
}

// NewRequest creates a RequestBuilder for the given method and path.
func NewRequest(method, path, version string) *RequestBuilder {
	return &RequestBuilder{
		method:  method,
		path:    path,
		version: version,
	}
}

// Header appends a header key-value pair.
func (r *RequestBuilder) Header(key, value string) *RequestBuilder {
	r.headers = append(r.headers, Header{key, value})
	return r
}

// Body sets the request body and automatically adds Content-Length.
func (r *RequestBuilder) Body(b []byte) *RequestBuilder {
	r.body = b
	return r.Header("Content-Length", fmt.Sprintf("%d", len(b)))
}

// Build serializes the request to bytes ready to be sent over a raw socket.
func (r *RequestBuilder) Build() []byte {
	var sb strings.Builder
	sb.WriteString(r.method)
	sb.WriteByte(' ')
	sb.WriteString(r.path)
	sb.WriteString(" HTTP/")
	sb.WriteString(r.version)
	sb.WriteString("\r\n")

	for _, h := range r.headers {
		sb.WriteString(h.Key)
		sb.WriteString(": ")
		sb.WriteString(h.Value)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")

	out := []byte(sb.String())
	if len(r.body) > 0 {
		out = append(out, r.body...)
	}
	return out
}

// BrowserHeaders returns a realistic browser header preset.
func BrowserHeaders(host, ua, referer string) []Header {
	return []Header{
		{"Host", host},
		{"User-Agent", ua},
		{"Referrer", referer},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Cache-Control", "max-age=0"},
		{"Connection", "keep-alive"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"Pragma", "no-cache"},
		{"Upgrade-Insecure-Requests", "1"},
	}
}

// SpoofHeaders returns IP-spoof headers for a given spoofed IP.
func SpoofHeaders(spoofIP, host string) []Header {
	return []Header{
		{"X-Forwarded-Proto", "Http"},
		{"X-Forwarded-Host", host + ", 1.1.1.1"},
		{"Via", spoofIP},
		{"Client-IP", spoofIP},
		{"X-Forwarded-For", spoofIP},
		{"Real-IP", spoofIP},
	}
}
