// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

// 帧格式是 ServerAgent 的外部契约。这个黄金测试锁住确切的字节布局：
// 改动它就是改动线上协议，必须是有意为之。
func TestFrameGoldenBytes(t *testing.T) {
	var uuid [16]byte
	copy(uuid[:], []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	})
	f := Frame{
		Version:   ProtocolMsgpack,
		Type:      FrameRequest,
		UUID:      uuid,
		Timestamp: 1700000000,
		Payload:   []byte{0xde, 0xad, 0xbe, 0xef},
	}

	got := hex.EncodeToString(f.Encode())
	want := "02" + // version 2 (msgpack)
		"01" + // type 1 (request)
		"0102030405060708090a0b0c0d0e0f10" + // uuid
		"000000006553f100" + // timestamp 1700000000, big endian
		"00000004" + // payload length 4, big endian
		"deadbeef"
	if got != want {
		t.Errorf("encoded frame =\n  %s\nwant\n  %s", got, want)
	}
	if len(f.Encode()) != HeaderLen+4 {
		t.Errorf("frame length = %d, want %d", len(f.Encode()), HeaderLen+4)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var uuid [16]byte
	for i := range uuid {
		uuid[i] = byte(i)
	}
	tests := []struct {
		name    string
		payload []byte
	}{
		{"有载荷", []byte("hello bus")},
		{"空载荷（心跳）", nil},
		{"大载荷", bytes.Repeat([]byte("x"), 100_000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := newFrame(FrameResponse, uuid, tt.payload, time.Unix(1700000000, 0))
			parsed, err := ParseFrame(original.Encode())
			if err != nil {
				t.Fatalf("ParseFrame() = %v", err)
			}
			if parsed.Version != ProtocolMsgpack {
				t.Errorf("Version = %d, want %d", parsed.Version, ProtocolMsgpack)
			}
			if parsed.Type != FrameResponse {
				t.Errorf("Type = %d", parsed.Type)
			}
			if parsed.UUID != uuid {
				t.Errorf("UUID = %x, want %x", parsed.UUID, uuid)
			}
			if parsed.Timestamp != 1700000000 {
				t.Errorf("Timestamp = %d", parsed.Timestamp)
			}
			if !bytes.Equal(parsed.Payload, tt.payload) {
				t.Errorf("Payload = %q, want %q", parsed.Payload, tt.payload)
			}
		})
	}
}

func TestParseFrameRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"空输入", nil},
		{"短于帧头", make([]byte, HeaderLen-1)},
		{"声明的载荷长度超过实际数据", func() []byte {
			f := Frame{Version: 2, Type: 1, Timestamp: 1, Payload: []byte("abc")}
			encoded := f.Encode()
			// 谎报载荷有 999 字节。
			encoded[26], encoded[27], encoded[28], encoded[29] = 0, 0, 0x03, 0xe7
			return encoded
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseFrame(tt.data); err == nil {
				t.Error("ParseFrame = nil error, want rejection")
			}
		})
	}
}

func TestParseFrameIgnoresTrailingBytes(t *testing.T) {
	// 一个 WebSocket 消息里可能带着多余数据；按声明长度取载荷即可。
	f := Frame{Version: 2, Type: FrameEvent, Timestamp: 5, Payload: []byte("abc")}
	encoded := append(f.Encode(), []byte("trailing junk")...)

	parsed, err := ParseFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Payload) != "abc" {
		t.Errorf("Payload = %q, want %q", parsed.Payload, "abc")
	}
}

func TestHeaderLenIsThirty(t *testing.T) {
	// 帧头长度写死在协议里；改了就是不兼容。
	if HeaderLen != 30 {
		t.Errorf("HeaderLen = %d, want 30", HeaderLen)
	}
}
