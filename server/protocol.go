package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Frame types
const (
	FrameConnect    byte = 0x01
	FrameData       byte = 0x02
	FrameDisconnect byte = 0x03
	FrameAck        byte = 0x04
)

// Frame header size: 1 (type) + 2 (channel_id) + 2 (payload_length)
const frameHeaderSize = 5

// MaxPayloadSize limits individual frame payload.
const MaxPayloadSize = 32 * 1024

// Frame represents a protocol frame.
type Frame struct {
	Type      byte
	ChannelID uint16
	Payload   []byte
}

// EncodeFrame serialises a Frame into bytes.
func EncodeFrame(f Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d > %d", len(f.Payload), MaxPayloadSize)
	}
	buf := make([]byte, frameHeaderSize+len(f.Payload))
	buf[0] = f.Type
	binary.BigEndian.PutUint16(buf[1:3], f.ChannelID)
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(f.Payload)))
	copy(buf[5:], f.Payload)
	return buf, nil
}

// DecodeFrame deserialises bytes into a Frame.
func DecodeFrame(data []byte) (Frame, error) {
	if len(data) < frameHeaderSize {
		return Frame{}, errors.New("frame too short")
	}
	f := Frame{
		Type:      data[0],
		ChannelID: binary.BigEndian.Uint16(data[1:3]),
	}
	payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
	if payloadLen > MaxPayloadSize {
		return Frame{}, fmt.Errorf("payload length %d exceeds max %d", payloadLen, MaxPayloadSize)
	}
	if len(data) < frameHeaderSize+payloadLen {
		return Frame{}, fmt.Errorf("frame truncated: need %d, got %d", frameHeaderSize+payloadLen, len(data))
	}
	f.Payload = make([]byte, payloadLen)
	copy(f.Payload, data[frameHeaderSize:frameHeaderSize+payloadLen])
	return f, nil
}

// DecodeFrames decodes multiple concatenated frames from a byte slice.
func DecodeFrames(data []byte) ([]Frame, error) {
	var frames []Frame
	offset := 0
	for offset < len(data) {
		if len(data)-offset < frameHeaderSize {
			return nil, errors.New("trailing bytes too short for frame header")
		}
		payloadLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		frameLen := frameHeaderSize + payloadLen
		if offset+frameLen > len(data) {
			return nil, errors.New("frame extends past data boundary")
		}
		f, err := DecodeFrame(data[offset : offset+frameLen])
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
		offset += frameLen
	}
	return frames, nil
}
