package crypto

import "github.com/lucas-clemente/quic-go/internal/protocol"

// Sealer seals a packet
type Sealer interface {
	Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte
	Overhead() int
}

// Opener opens a packet
// Only used for IETF QUIC.
type Opener interface {
	Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error)
}

// An AEAD implements QUIC's authenticated encryption and associated data
type AEAD interface {
	Opener
	Sealer
}
