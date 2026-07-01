package chvdtunnel

import (
	"context"
	"encoding/gob"
	"io"
)

// UDPPacket is a gob-encodable UDP datagram.
type UDPPacket struct {
	Src     string
	Payload []byte
}

func init() {
	gob.Register(&UDPPacket{})
}

// udpChannel encodes/decodes udp payloads over a stream
type udpChannel struct {
	r *gob.Decoder
	w *gob.Encoder
	c io.Closer
}

func (o *udpChannel) encode(src string, b []byte) error {
	return o.w.Encode(UDPPacket{
		Src:     src,
		Payload: b,
	})
}

func (o *udpChannel) decode(p *UDPPacket) error {
	return o.r.Decode(p)
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
