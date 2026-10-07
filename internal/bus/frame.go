// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package bus connects CertCenter to the ServerAgent control plane as
// service:certcenter, exposing its API over the bus and accepting config
// pushes from the config center.
package bus

import (
	"encoding/binary"
	"fmt"
	"time"
)

// The wire format is ServerAgent's, not ours: every field below is an
// external contract and must not be "improved".
//
// Header, exactly 30 bytes:
//
//	offset  size  field
//	     0     1  version      1 = JSON payload, 2 = msgpack
//	     1     1  type         see the Frame* constants
//	     2    16  uuid         raw bytes
//	    18     8  timestamp    int64 Unix seconds, big endian
//	    26     4  payloadLen   uint32, big endian
const (
	HeaderLen = 30

	// ProtocolJSON and ProtocolMsgpack are the payload encodings. This
	// service always emits msgpack.
	ProtocolJSON    = 1
	ProtocolMsgpack = 2

	FrameRequest   = 1
	FrameResponse  = 2
	FrameEvent     = 3
	FrameHeartbeat = 4
	FramePush      = 5
)

// Frame is one bus message.
type Frame struct {
	Version   byte
	Type      byte
	UUID      [16]byte
	Timestamp int64
	Payload   []byte
}

// Encode serialises the frame.
func (f Frame) Encode() []byte {
	out := make([]byte, HeaderLen+len(f.Payload))
	out[0] = f.Version
	out[1] = f.Type
	copy(out[2:18], f.UUID[:])
	binary.BigEndian.PutUint64(out[18:26], uint64(f.Timestamp))
	binary.BigEndian.PutUint32(out[26:30], uint32(len(f.Payload)))
	copy(out[HeaderLen:], f.Payload)
	return out
}

// ParseFrame decodes a frame.
//
// A frame whose declared payload length exceeds what arrived is rejected
// rather than truncated: acting on a partial payload would be worse than
// dropping the message.
func ParseFrame(data []byte) (Frame, error) {
	if len(data) < HeaderLen {
		return Frame{}, fmt.Errorf("frame is %d bytes, shorter than the %d-byte header",
			len(data), HeaderLen)
	}
	var f Frame
	f.Version = data[0]
	f.Type = data[1]
	copy(f.UUID[:], data[2:18])
	f.Timestamp = int64(binary.BigEndian.Uint64(data[18:26]))

	payloadLen := int(binary.BigEndian.Uint32(data[26:30]))
	if len(data) < HeaderLen+payloadLen {
		return Frame{}, fmt.Errorf("frame declares a %d-byte payload but only %d bytes follow the header",
			payloadLen, len(data)-HeaderLen)
	}
	f.Payload = data[HeaderLen : HeaderLen+payloadLen]
	return f, nil
}

// newFrame builds an outgoing frame with the current time.
func newFrame(frameType byte, uuid [16]byte, payload []byte, now time.Time) Frame {
	return Frame{
		Version:   ProtocolMsgpack,
		Type:      frameType,
		UUID:      uuid,
		Timestamp: now.Unix(),
		Payload:   payload,
	}
}
