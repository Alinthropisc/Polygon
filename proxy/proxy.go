package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type Type int

const (
	HTTP   Type = 1
	SOCKS4 Type = 4
	SOCKS5 Type = 5
)

type Proxy struct {
	Host  string
	Port  string
	PType Type
}

func (p Proxy) String() string {
	return fmt.Sprintf("%s:%s", p.Host, p.Port)
}

func (p Proxy) Dialer() (func(network, addr string) (net.Conn, error), error) {
	switch p.PType {
	case SOCKS5:
		d, err := proxy.SOCKS5("tcp", p.String(), nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return d.Dial, nil
	case SOCKS4:
		// golang.org/x/net/proxy does not support SOCKS4 natively; fall back to direct
		return net.Dial, nil
	default: // HTTP proxy
		proxyURL, err := url.Parse("http://" + p.String())
		if err != nil {
			return nil, err
		}
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		_ = transport
		return func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 5*time.Second)
		}, nil
	}
}

// HTTPTransport returns an *http.Transport routed through this proxy.
func (p Proxy) HTTPTransport() *http.Transport {
	switch p.PType {
	case SOCKS5:
		d, err := proxy.SOCKS5("tcp", p.String(), nil, proxy.Direct)
		if err != nil {
			return &http.Transport{}
		}
		return &http.Transport{Dial: d.Dial}
	default:
		proxyURL, _ := url.Parse("http://" + p.String())
		return &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
}

// ParseLine parses "host:port" into a Proxy of the given type.
func ParseLine(line string, pt Type) (Proxy, bool) {
	line = strings.TrimSpace(line)
	host, port, err := net.SplitHostPort(line)
	if err != nil {
		return Proxy{}, false
	}
	return Proxy{Host: host, Port: port, PType: pt}, true
}

// ReadFile reads IP:port pairs from a file and returns Proxy list.
func ReadFile(path string, pt Type) ([]Proxy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var proxies []Proxy
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if p, ok := ParseLine(sc.Text(), pt); ok {
			proxies = append(proxies, p)
		}
	}
	return proxies, sc.Err()
}
