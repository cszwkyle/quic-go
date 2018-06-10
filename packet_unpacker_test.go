package quic

import (
	"bytes"

	"github.com/golang/mock/gomock"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Packet Unpacker (for gQUIC)", func() {
	var (
		unpacker *packetUnpackerGQUIC
		hdr      *wire.Header
		aead     *MockGQUICAEAD
	)

	BeforeEach(func() {
		aead = NewMockGQUICAEAD(mockCtrl)
		hdr = &wire.Header{
			PacketNumber:    10,
			PacketNumberLen: 1,
			ParsedLen:       3,
		}
		unpacker = newPacketUnpackerGQUIC(aead, versionGQUICFrames).(*packetUnpackerGQUIC)
	})

	It("errors if the packet doesn't contain any payload", func() {
		aead.EXPECT().Open(gomock.Any(), []byte("bar"), hdr.PacketNumber, []byte("foo")).Return([]byte{}, protocol.EncryptionForwardSecure, nil)
		_, err := unpacker.Unpack(hdr, []byte("foobar"))
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("saves the encryption level", func() {
		aead.EXPECT().Open(gomock.Any(), gomock.Any(), hdr.PacketNumber, gomock.Any()).Return([]byte{0}, protocol.EncryptionSecure, nil)
		packet, err := unpacker.Unpack(hdr, []byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionSecure))
	})

	It("unpacks the frames", func() {
		buf := &bytes.Buffer{}
		(&wire.PingFrame{}).Write(buf, versionGQUICFrames)
		(&wire.BlockedFrame{}).Write(buf, versionGQUICFrames)
		aead.EXPECT().Open(gomock.Any(), gomock.Any(), hdr.PacketNumber, gomock.Any()).Return(buf.Bytes(), protocol.EncryptionForwardSecure, nil)
		packet, err := unpacker.Unpack(hdr, []byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{&wire.PingFrame{}, &wire.BlockedFrame{}}))
	})
})

var _ = Describe("Packet Unpacker (for IETF QUIC)", func() {
	var (
		unpacker *packetUnpacker
		hdr      *wire.Header
		aead     *MockQuicAEAD
	)

	BeforeEach(func() {
		aead = NewMockQuicAEAD(mockCtrl)
		hdr = &wire.Header{
			PacketNumber:    10,
			PacketNumberLen: 1,
			ParsedLen:       3,
		}
		unpacker = newPacketUnpacker(aead, versionIETFFrames).(*packetUnpacker)
	})

	It("errors if the packet doesn't contain any payload", func() {
		data := []byte("foo")
		aead.EXPECT().Open1RTT(gomock.Any(), []byte{}, hdr.PacketNumber, []byte("foo")).Return([]byte{}, nil)
		_, err := unpacker.Unpack(hdr, data)
		Expect(err).To(MatchError(qerr.MissingPayload))
	})

	It("opens handshake packets", func() {
		hdr.IsLongHeader = true
		aead.EXPECT().OpenHandshake(gomock.Any(), []byte("bar"), hdr.PacketNumber, []byte("foo")).Return([]byte{0}, nil)
		packet, err := unpacker.Unpack(hdr, []byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.encryptionLevel).To(Equal(protocol.EncryptionUnencrypted))
	})

	It("unpacks the frames", func() {
		buf := &bytes.Buffer{}
		(&wire.PingFrame{}).Write(buf, versionIETFFrames)
		(&wire.BlockedFrame{}).Write(buf, versionIETFFrames)
		aead.EXPECT().Open1RTT(gomock.Any(), gomock.Any(), hdr.PacketNumber, gomock.Any()).Return(buf.Bytes(), nil)
		packet, err := unpacker.Unpack(hdr, []byte("foobar"))
		Expect(err).ToNot(HaveOccurred())
		Expect(packet.frames).To(Equal([]wire.Frame{&wire.PingFrame{}, &wire.BlockedFrame{}}))
	})
})
