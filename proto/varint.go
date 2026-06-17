// Package proto provides low-level binary protocol helpers shared across
// multiple attack methods (Minecraft VarInt, UDP frame builders, etc.).
package proto

import "encoding/binary"

// AppendVarint appends a Minecraft-style variable-length integer to b.
func AppendVarint(b []byte, v int) []byte {
	for {
		part := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			part |= 0x80
		}
		b = append(b, part)
		if v == 0 {
			break
		}
	}
	return b
}

// Varint encodes v as a Minecraft variable-length integer.
func Varint(v int) []byte {
	return AppendVarint(nil, v)
}

// WithLength prepends a varint length prefix to payload — the standard
// Minecraft packet framing.
func WithLength(payload []byte) []byte {
	prefix := Varint(len(payload))
	return append(prefix, payload...)
}

// BigEndianU16 encodes n as two big-endian bytes.
func BigEndianU16(n uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, n)
	return b
}

// BigEndianU32 encodes n as four big-endian bytes.
func BigEndianU32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// BigEndianU64 encodes n as eight big-endian bytes.
func BigEndianU64(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

// LittleEndianU16 encodes n as two little-endian bytes.
func LittleEndianU16(n uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)
	return b
}

// Concat concatenates byte slices without intermediate allocations.
func Concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// UDPFrame builds a length-prefixed (2-byte big-endian) UDP frame.
func UDPFrame(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(out, uint16(len(payload)))
	copy(out[2:], payload)
	return out
}
