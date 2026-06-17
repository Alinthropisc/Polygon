package net

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSInfo holds the TLS fingerprint of a remote server.
type TLSInfo struct {
	Version     string
	CipherSuite string
	CommonName  string
	Issuer      string
	SANs        []string
	Expired     bool
	SelfSigned  bool
}

// FingerprintTLS connects to host:port and returns TLS certificate + cipher info.
func FingerprintTLS(host string, port int) (*TLSInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned")
	}
	leaf := certs[0]

	info := &TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		CommonName:  leaf.Subject.CommonName,
		Issuer:      leaf.Issuer.CommonName,
		SANs:        leaf.DNSNames,
		Expired:     time.Now().After(leaf.NotAfter),
		SelfSigned:  leaf.Subject.String() == leaf.Issuer.String(),
	}
	return info, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// String returns a human-readable summary of TLS info.
func (t *TLSInfo) String() string {
	flags := []string{}
	if t.Expired {
		flags = append(flags, "EXPIRED")
	}
	if t.SelfSigned {
		flags = append(flags, "self-signed")
	}
	flagStr := ""
	if len(flags) > 0 {
		flagStr = " [" + strings.Join(flags, ", ") + "]"
	}
	return fmt.Sprintf("%s | %s | CN=%s | Issuer=%s | SANs=%v%s",
		t.Version, t.CipherSuite, t.CommonName, t.Issuer, t.SANs, flagStr)
}
