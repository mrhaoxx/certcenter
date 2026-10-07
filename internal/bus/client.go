// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/mrhaoxx/certcenter/internal/config"
)

const (
	// ConfigTopic is what the config center publishes on when this
	// service's configuration changes.
	ConfigTopic = "config:watch:certcenter"

	bootstrapTimeout = 10 * time.Second
	reconnectDelay   = 5 * time.Second
	configRPCTimeout = 10 * time.Second
)

// Conn is the subset of a WebSocket the client uses, so the protocol can
// be tested without a server.
type Conn interface {
	ReadMessage() (messageType int, data []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
}

// Client speaks the ServerAgent bus protocol.
type Client struct {
	Config *config.BusConfig
	// Dispatch handles one RPC and returns the result to encode.
	Dispatch func(ctx context.Context, method string, params json.RawMessage) (any, error)
	// Dial opens a connection; swapped in tests.
	Dial func(ctx context.Context, url string) (Conn, error)
	// ApplyConfig receives a freshly resolved TOML document.
	ApplyConfig func(resolvedTOML string) error
	// FetchConfig resolves the current configuration; swapped in tests.
	FetchConfig func(ctx context.Context) (string, error)
}

func dialWS(ctx context.Context, url string) (Conn, error) {
	dialer := websocket.Dialer{HandshakeTimeout: bootstrapTimeout}
	conn, _, err := dialer.DialContext(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) dial(ctx context.Context, url string) (Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, url)
	}
	return dialWS(ctx, url)
}

// Run connects and serves until the context is cancelled, reconnecting
// after a drop.
func (c *Client) Run(ctx context.Context) {
	for {
		if err := c.serve(ctx); err != nil {
			slog.Warn("bus connection ended", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectDelay):
		}
	}
}

// bootstrapRequest is the JSON handshake that identifies this service.
type bootstrapRequest struct {
	Bootstrap string            `json:"bootstrap"`
	ServiceID string            `json:"service_id"`
	Token     string            `json:"token"`
	Labels    map[string]string `json:"labels"`
	Methods   []string          `json:"methods"`
}

type bootstrapResponse struct {
	Bootstrap string `json:"bootstrap"`
	Reason    string `json:"reason"`
}

// subscribeEvent asks the control plane for config pushes.
type subscribeEvent struct {
	Type   string   `json:"type"`
	Topics []string `json:"topics"`
}

// topicPush is what arrives on a FramePush.
type topicPush struct {
	Topic string `msgpack:"topic" json:"topic"`
}

// pluginTask is the request payload shape. The action is the RPC method.
type pluginTask struct {
	Type   string          `msgpack:"type" json:"type"`
	Plugin string          `msgpack:"plugin" json:"plugin"`
	Action string          `msgpack:"action" json:"action"`
	Params json.RawMessage `msgpack:"params" json:"params"`
}

// taskResult is the response payload. The result is JSON-encoded into
// Stdout rather than nested — an odd shape, but it is the contract.
type taskResult struct {
	Success  bool   `msgpack:"success"`
	ExitCode int    `msgpack:"exit_code"`
	Stdout   string `msgpack:"stdout"`
	Stderr   string `msgpack:"stderr"`
}

func (c *Client) serve(ctx context.Context) error {
	conn, err := c.dial(ctx, c.Config.URL)
	if err != nil {
		return fmt.Errorf("dial bus: %w", err)
	}
	defer conn.Close()

	if err := c.bootstrap(conn); err != nil {
		return err
	}
	if err := c.subscribe(conn); err != nil {
		return err
	}
	slog.Info("connected to the bus", "service", c.Config.ServiceID)

	// Reads block, so cancellation closes the connection to unblock them.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, data, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if err := c.handleMessage(ctx, conn, data); err != nil {
			slog.Warn("bus message handling failed", "err", err)
		}
	}
}

// bootstrap performs the JSON handshake phase.
func (c *Client) bootstrap(conn Conn) error {
	req := bootstrapRequest{
		Bootstrap: "service",
		ServiceID: c.Config.ServiceID,
		Token:     c.Config.Token,
		Labels:    map[string]string{},
		Methods:   Methods(),
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.TextMessage, raw); err != nil {
		return fmt.Errorf("send bootstrap: %w", err)
	}

	_, data, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read bootstrap response: %w", err)
	}
	var resp bootstrapResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("malformed bootstrap response: %w", err)
	}
	if resp.Bootstrap != "accepted" {
		reason := resp.Reason
		if reason == "" {
			reason = "unknown"
		}
		return fmt.Errorf("bootstrap rejected: %s", reason)
	}
	return nil
}

// subscribe registers for config pushes. The topic is fixed by the control
// plane's configuration, not derived from the service id.
func (c *Client) subscribe(conn Conn) error {
	payload, err := msgpack.Marshal(subscribeEvent{
		Type: "Subscribe", Topics: []string{ConfigTopic},
	})
	if err != nil {
		return err
	}
	frame := newFrame(FrameEvent, randomUUID(), payload, time.Now())
	if err := conn.WriteMessage(websocket.BinaryMessage, frame.Encode()); err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	return nil
}

func (c *Client) handleMessage(ctx context.Context, conn Conn, data []byte) error {
	frame, err := ParseFrame(data)
	if err != nil {
		// A frame we cannot parse is dropped rather than answered: replying
		// to a malformed request with a nil-uuid response only confuses the
		// far side.
		return err
	}

	switch frame.Type {
	case FrameRequest:
		return c.handleRequest(ctx, conn, frame)
	case FrameHeartbeat:
		// Purely reactive: the control plane pings, we pong. This service
		// never initiates a heartbeat.
		pong := newFrame(FrameHeartbeat, randomUUID(), nil, time.Now())
		return conn.WriteMessage(websocket.BinaryMessage, pong.Encode())
	case FramePush:
		return c.handlePush(ctx, frame)
	default:
		return nil
	}
}

func (c *Client) handleRequest(ctx context.Context, conn Conn, frame Frame) error {
	result := c.dispatch(ctx, frame)
	payload, err := msgpack.Marshal(result)
	if err != nil {
		return err
	}
	// The response reuses the request's uuid so the caller can correlate.
	resp := newFrame(FrameResponse, frame.UUID, payload, time.Now())
	return conn.WriteMessage(websocket.BinaryMessage, resp.Encode())
}

func (c *Client) dispatch(ctx context.Context, frame Frame) taskResult {
	var task pluginTask
	var err error
	if frame.Version == ProtocolJSON {
		err = json.Unmarshal(frame.Payload, &task)
	} else {
		err = msgpack.Unmarshal(frame.Payload, &task)
	}
	if err != nil {
		return taskResult{ExitCode: 1, Stderr: fmt.Sprintf("could not decode the request: %v", err)}
	}
	if c.Dispatch == nil {
		return taskResult{ExitCode: 1, Stderr: "no dispatcher configured"}
	}

	value, err := c.Dispatch(ctx, task.Action, task.Params)
	if err != nil {
		return taskResult{ExitCode: 1, Stderr: err.Error()}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return taskResult{ExitCode: 1, Stderr: err.Error()}
	}
	// The result rides as a JSON string inside stdout — the control plane's
	// contract, not a design choice.
	return taskResult{Success: true, ExitCode: 0, Stdout: string(encoded)}
}

func (c *Client) handlePush(ctx context.Context, frame Frame) error {
	var push topicPush
	if err := msgpack.Unmarshal(frame.Payload, &push); err != nil {
		return fmt.Errorf("malformed push: %w", err)
	}
	if !isConfigTopic(push.Topic) {
		return nil
	}
	slog.Info("config change pushed", "topic", push.Topic)

	if c.FetchConfig == nil || c.ApplyConfig == nil {
		return nil
	}
	// The push carries no payload worth trusting; re-resolve instead.
	fetchCtx, cancel := context.WithTimeout(ctx, configRPCTimeout)
	defer cancel()

	resolved, err := c.FetchConfig(fetchCtx)
	if err != nil {
		return fmt.Errorf("resolve pushed config: %w", err)
	}
	return c.ApplyConfig(resolved)
}

func isConfigTopic(topic string) bool {
	return len(topic) >= len(ConfigTopic) && topic[:len(ConfigTopic)] == ConfigTopic
}

func randomUUID() [16]byte {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A correlation id that repeats is far better than a crash here.
		binaryPutTime(&b, time.Now().UnixNano())
	}
	// Version 4, variant 1, so the far side sees a well-formed UUID.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return b
}

func binaryPutTime(b *[16]byte, v int64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (56 - 8*i))
	}
}
