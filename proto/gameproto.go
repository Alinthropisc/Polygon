// Package proto — game server protocol payloads extracted from layer4 into one place.
package proto

// VSEQuery is the Valve Source Engine status query payload.
var VSEQuery = []byte("\xff\xff\xff\xffTSource Engine Query\x00")

// TS3StatusPing is the TeamSpeak 3 status ping payload.
var TS3StatusPing = []byte("\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02")

// FiveMGetInfo is the FiveM server info query payload.
var FiveMGetInfo = []byte("\xff\xff\xff\xffgetinfo xxx\x00\x00\x00")

// MCPEPing is the Minecraft PE (Bedrock) status ping payload.
var MCPEPing = []byte(
	"\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70" +
		"\x20\x6d\x79\x20\x6f\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70" +
		"\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20\x69\x73\x20\x6d\x79" +
		"\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c\x73",
)

// MinecraftVarint encodes v as a Minecraft VarInt (same as proto.Varint).
func MinecraftVarint(v int) []byte { return Varint(v) }

// MinecraftPacket frames payload with a VarInt length prefix.
func MinecraftPacket(payload ...[]byte) []byte {
	return WithLength(Concat(payload...))
}

// MinecraftHandshake builds a Minecraft handshake packet.
func MinecraftHandshake(host string, port uint16, protocolID, state int) []byte {
	return MinecraftPacket(
		Varint(0x00),
		Varint(protocolID),
		WithLength([]byte(host)),
		BigEndianU16(port),
		Varint(state),
	)
}

// MinecraftHandshakeForwarded builds a BungeeCord-forwarded handshake.
func MinecraftHandshakeForwarded(host string, port uint16, protocolID, state int, fwdIP, uuid string) []byte {
	return MinecraftPacket(
		Varint(0x00),
		Varint(protocolID),
		WithLength(Concat([]byte(host), []byte("\x00"), []byte(fwdIP), []byte("\x00"), []byte(uuid))),
		BigEndianU16(port),
		Varint(state),
	)
}

// MinecraftLogin builds a login-start packet.
func MinecraftLogin(protocol int, username string) []byte {
	id := 0x00
	if protocol >= 385 && protocol < 391 {
		id = 0x01
	}
	return MinecraftPacket(Varint(id), WithLength([]byte(username)))
}

// MinecraftChat builds a chat message packet.
func MinecraftChat(protocol int, message string) []byte {
	var id int
	switch {
	case protocol >= 755:
		id = 0x03
	case protocol >= 464:
		id = 0x03
	case protocol >= 343:
		id = 0x01
	case protocol >= 318:
		id = 0x03
	case protocol >= 107:
		id = 0x02
	default:
		id = 0x01
	}
	return MinecraftPacket(Varint(id), WithLength([]byte(message)))
}

// MinecraftPing is the status ping packet (packet ID 0x00, no payload).
var MinecraftPing = WithLength([]byte{0x00})
