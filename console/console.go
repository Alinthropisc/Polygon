// Package console implements the interactive TOOLS console (INFO, PING, CHECK, DSTAT, TSSRV).
package console

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"Polygon/tools"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
)

func Run() {
	hostname, _ := os.Hostname()
	prompt := hostname + "@Polygon:~# "
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print(prompt)
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "HELP":
			fmt.Println("Tools: INFO, TSSRV, CFIP, DNS, PING, CHECK, DSTAT")
			fmt.Println("Commands: HELP, CLEAR, EXIT")
		case "CLEAR":
			fmt.Print("\033c")
		case "E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE":
			return
		case "DSTAT":
			runDStat()
		case "INFO":
			runInfo(prompt)
		case "CHECK":
			runCheck(prompt)
		case "PING":
			runPing(prompt)
		case "TSSRV":
			runTSSRV(prompt)
		case "CFIP", "DNS":
			fmt.Println("Soon")
		default:
			fmt.Printf("%s: command not found\n", cmd)
		}
	}
}

func runDStat() {
	fmt.Println("Press Ctrl+C to stop...")
	prev, _ := psnet.IOCounters(false)
	for {
		time.Sleep(time.Second)
		curr, err := psnet.IOCounters(false)
		if err != nil || len(curr) == 0 || len(prev) == 0 {
			continue
		}
		cpuPct, _ := cpu.Percent(0, false)
		vmem, _ := mem.VirtualMemory()

		s := curr[0].BytesSent - prev[0].BytesSent
		r := curr[0].BytesRecv - prev[0].BytesRecv
		ps := curr[0].PacketsSent - prev[0].PacketsSent
		pr := curr[0].PacketsRecv - prev[0].PacketsRecv

		fmt.Printf("Bytes Sent: %s | Received: %s | Packets: ↑%s ↓%s | CPU: %.1f%% | Mem: %.1f%%\n",
			tools.HumanBytes(int64(s)), tools.HumanBytes(int64(r)),
			tools.HumanFormat(int64(ps)), tools.HumanFormat(int64(pr)),
			cpuPct[0], vmem.UsedPercent)
		prev = curr
	}
}

func runInfo(prompt string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(prompt + "give-me-ipaddress# ")
		if !scanner.Scan() {
			return
		}
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		if strings.EqualFold(domain, "BACK") {
			return
		}
		if strings.EqualFold(domain, "CLEAR") {
			fmt.Print("\033c")
			continue
		}
		if strings.EqualFold(domain, "EXIT") || strings.EqualFold(domain, "QUIT") {
			os.Exit(0)
		}
		domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
		if idx := strings.Index(domain, "/"); idx != -1 {
			domain = domain[:idx]
		}

		info, err := ipWhois(domain)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		fmt.Printf("Country: %s\nCity: %s\nOrg: %s\nISP: %s\nRegion: %s\n",
			info["country"], info["city"], info["org"], info["isp"], info["region"])
	}
}

func runCheck(prompt string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(prompt + "give-me-url# ")
		if !scanner.Scan() {
			return
		}
		target := strings.TrimSpace(scanner.Text())
		if target == "" {
			continue
		}
		if strings.EqualFold(target, "BACK") {
			return
		}
		if strings.EqualFold(target, "CLEAR") {
			fmt.Print("\033c")
			continue
		}
		client := &http.Client{Timeout: 20 * time.Second}
		req, err := http.NewRequestWithContext(context.Background(), "GET", target, http.NoBody)
		if err != nil {
			fmt.Println("status: OFFLINE (", err, ")")
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("status: OFFLINE (", err, ")")
			continue
		}
		resp.Body.Close()
		status := "ONLINE"
		if resp.StatusCode > 500 {
			status = "OFFLINE"
		}
		fmt.Printf("status_code: %d\nstatus: %s\n", resp.StatusCode, status)
	}
}

func runPing(prompt string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(prompt + "give-me-host# ")
		if !scanner.Scan() {
			return
		}
		host := strings.TrimSpace(scanner.Text())
		if host == "" {
			continue
		}
		if strings.EqualFold(host, "BACK") {
			return
		}
		host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}

		pingHost(host)
	}
}

func pingHost(host string) {
	sent := 5
	received := 0
	var total time.Duration

	for i := 0; i < sent; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", host+":80", 2*time.Second)
		rtt := time.Since(start)
		if err == nil {
			conn.Close()
			received++
			total += rtt
		}
		time.Sleep(200 * time.Millisecond)
	}

	avgMs := int64(0)
	if received > 0 {
		avgMs = int64(total.Milliseconds()) / int64(received)
	}
	status := "OFFLINE"
	if received > 0 {
		status = "ONLINE"
	}
	fmt.Printf("Address: %s\nPing: %dms\nAccepted Packets: %d/%d\nStatus: %s\n",
		host, avgMs, received, sent, status)
}

func runTSSRV(prompt string) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(prompt + "give-me-domain# ")
		if !scanner.Scan() {
			return
		}
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		if strings.EqualFold(domain, "BACK") {
			return
		}
		domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
		if idx := strings.Index(domain, "/"); idx != -1 {
			domain = domain[:idx]
		}

		for _, rec := range []string{"_tsdns._tcp.", "_ts3._udp."} {
			_, addrs, err := net.LookupSRV("", "", rec+domain)
			if err != nil || len(addrs) == 0 {
				fmt.Printf("%s: Not found\n", rec)
				continue
			}
			fmt.Printf("%s: %s:%d\n", rec, strings.TrimSuffix(addrs[0].Target, "."), addrs[0].Port)
		}
	}
}

func ipWhois(domain string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://ipwhois.app/json/"+domain+"/", http.NoBody)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}
