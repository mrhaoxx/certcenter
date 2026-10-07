// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/mrhaoxx/certcenter/internal/config"
	"github.com/mrhaoxx/certcenter/internal/db"
)

// fakeConn scripts inbound messages and records outbound ones.
type fakeConn struct {
	mu       sync.Mutex
	inbound  chan wsMessage
	Outbound []wsMessage
	closed   bool
}

type wsMessage struct {
	Type int
	Data []byte
}

func newFakeConn(scripted ...wsMessage) *fakeConn {
	c := &fakeConn{inbound: make(chan wsMessage, len(scripted)+8)}
	for _, m := range scripted {
		c.inbound <- m
	}
	return c
}

func (c *fakeConn) ReadMessage() (int, []byte, error) {
	m, ok := <-c.inbound
	if !ok {
		return 0, nil, fmt.Errorf("connection closed")
	}
	return m.Type, m.Data, nil
}

func (c *fakeConn) WriteMessage(messageType int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]byte, len(data))
	copy(copied, data)
	c.Outbound = append(c.Outbound, wsMessage{Type: messageType, Data: copied})
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.inbound)
	}
	return nil
}

func (c *fakeConn) sent() []wsMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]wsMessage, len(c.Outbound))
	copy(out, c.Outbound)
	return out
}

func acceptedBootstrap() wsMessage {
	raw, _ := json.Marshal(bootstrapResponse{Bootstrap: "accepted"})
	return wsMessage{Type: websocket.TextMessage, Data: raw}
}

func testClient(conn *fakeConn) *Client {
	mgmt := "ws://bus:9901/api/events/ws"
	return &Client{
		Config: &config.BusConfig{
			URL: "ws://bus:9900/ws", ServiceID: "certcenter", Token: "tok",
			ManagementURL: &mgmt,
		},
		Dial: func(context.Context, string) (Conn, error) { return conn, nil },
	}
}

func TestBootstrapHandshake(t *testing.T) {
	conn := newFakeConn(acceptedBootstrap())
	c := testClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { time.Sleep(50 * time.Millisecond); conn.Close() }()
	_ = c.serve(ctx)

	sent := conn.sent()
	if len(sent) < 2 {
		t.Fatalf("sent %d messages, want the bootstrap plus the subscribe", len(sent))
	}
	if sent[0].Type != websocket.TextMessage {
		t.Errorf("bootstrap sent as type %d, want a text message", sent[0].Type)
	}
	var req bootstrapRequest
	if err := json.Unmarshal(sent[0].Data, &req); err != nil {
		t.Fatalf("bootstrap is not JSON: %v", err)
	}
	if req.Bootstrap != "service" || req.ServiceID != "certcenter" || req.Token != "tok" {
		t.Errorf("bootstrap = %+v", req)
	}
	if len(req.Methods) != 27 {
		t.Errorf("advertised %d methods, want all 27", len(req.Methods))
	}

	// 第二条是订阅配置主题的 EVENT 帧。
	if sent[1].Type != websocket.BinaryMessage {
		t.Errorf("subscribe sent as type %d, want binary", sent[1].Type)
	}
	frame, err := ParseFrame(sent[1].Data)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != FrameEvent {
		t.Errorf("subscribe frame type = %d, want %d", frame.Type, FrameEvent)
	}
	var sub subscribeEvent
	if err := msgpack.Unmarshal(frame.Payload, &sub); err != nil {
		t.Fatal(err)
	}
	if sub.Type != "Subscribe" || len(sub.Topics) != 1 || sub.Topics[0] != ConfigTopic {
		t.Errorf("subscribe = %+v, want the config topic", sub)
	}
}

func TestBootstrapRejectionStopsTheConnection(t *testing.T) {
	raw, _ := json.Marshal(bootstrapResponse{Bootstrap: "rejected", Reason: "bad token"})
	conn := newFakeConn(wsMessage{Type: websocket.TextMessage, Data: raw})
	c := testClient(conn)

	err := c.serve(context.Background())
	if err == nil {
		t.Fatal("serve = nil error, want the rejection surfaced")
	}
	if !contains(err.Error(), "bad token") {
		t.Errorf("error = %v, want it to carry the reason", err)
	}
}

func TestHeartbeatIsAnswered(t *testing.T) {
	// 只被动响应：控制面 ping，我们 pong，从不主动发起。
	beat := newFrame(FrameHeartbeat, [16]byte{1}, nil, time.Unix(1700000000, 0))
	conn := newFakeConn(
		acceptedBootstrap(),
		wsMessage{Type: websocket.BinaryMessage, Data: beat.Encode()},
	)
	c := testClient(conn)

	go func() { time.Sleep(80 * time.Millisecond); conn.Close() }()
	_ = c.serve(context.Background())

	var sawPong bool
	for _, m := range conn.sent()[2:] {
		f, err := ParseFrame(m.Data)
		if err == nil && f.Type == FrameHeartbeat {
			sawPong = true
			if len(f.Payload) != 0 {
				t.Errorf("heartbeat reply carries a %d-byte payload, want none", len(f.Payload))
			}
		}
	}
	if !sawPong {
		t.Error("no heartbeat reply was sent")
	}
}

func TestRequestIsDispatchedAndAnswered(t *testing.T) {
	task := pluginTask{Type: "PluginTask", Action: "cert.stats", Params: json.RawMessage(`{}`)}
	payload, err := msgpack.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	reqUUID := [16]byte{9, 9, 9}
	req := newFrame(FrameRequest, reqUUID, payload, time.Unix(1700000000, 0))

	conn := newFakeConn(
		acceptedBootstrap(),
		wsMessage{Type: websocket.BinaryMessage, Data: req.Encode()},
	)
	c := testClient(conn)
	c.Dispatch = func(_ context.Context, method string, _ json.RawMessage) (any, error) {
		if method != "cert.stats" {
			return nil, fmt.Errorf("unexpected method %q", method)
		}
		return map[string]int{"totalCertificates": 3}, nil
	}

	go func() { time.Sleep(80 * time.Millisecond); conn.Close() }()
	_ = c.serve(context.Background())

	var answered bool
	for _, m := range conn.sent()[2:] {
		f, err := ParseFrame(m.Data)
		if err != nil || f.Type != FrameResponse {
			continue
		}
		answered = true
		// 响应必须复用请求的 uuid，调用方才能对上。
		if f.UUID != reqUUID {
			t.Errorf("response uuid = %x, want the request's %x", f.UUID, reqUUID)
		}
		var result taskResult
		if err := msgpack.Unmarshal(f.Payload, &result); err != nil {
			t.Fatal(err)
		}
		if !result.Success || result.ExitCode != 0 {
			t.Errorf("result = %+v, want success", result)
		}
		// 结果是 JSON 字符串塞进 stdout —— 控制面的契约。
		var decoded map[string]int
		if err := json.Unmarshal([]byte(result.Stdout), &decoded); err != nil {
			t.Fatalf("stdout is not the JSON-encoded result: %v (%q)", err, result.Stdout)
		}
		if decoded["totalCertificates"] != 3 {
			t.Errorf("decoded = %v", decoded)
		}
	}
	if !answered {
		t.Error("the request was never answered")
	}
}

func TestDispatchErrorBecomesStderr(t *testing.T) {
	task := pluginTask{Type: "PluginTask", Action: "cert.nope"}
	payload, _ := msgpack.Marshal(task)
	req := newFrame(FrameRequest, [16]byte{1}, payload, time.Now())

	conn := newFakeConn(
		acceptedBootstrap(),
		wsMessage{Type: websocket.BinaryMessage, Data: req.Encode()},
	)
	c := testClient(conn)
	c.Dispatch = func(context.Context, string, json.RawMessage) (any, error) {
		return nil, fmt.Errorf("unknown method: cert.nope")
	}

	go func() { time.Sleep(80 * time.Millisecond); conn.Close() }()
	_ = c.serve(context.Background())

	for _, m := range conn.sent()[2:] {
		f, err := ParseFrame(m.Data)
		if err != nil || f.Type != FrameResponse {
			continue
		}
		var result taskResult
		msgpack.Unmarshal(f.Payload, &result)
		if result.Success || result.ExitCode != 1 {
			t.Errorf("result = %+v, want a failure", result)
		}
		if !contains(result.Stderr, "unknown method") {
			t.Errorf("stderr = %q", result.Stderr)
		}
		return
	}
	t.Error("no response frame was sent")
}

func TestConfigPushTriggersReload(t *testing.T) {
	push, err := msgpack.Marshal(topicPush{Topic: ConfigTopic})
	if err != nil {
		t.Fatal(err)
	}
	frame := newFrame(FramePush, [16]byte{2}, push, time.Now())

	conn := newFakeConn(
		acceptedBootstrap(),
		wsMessage{Type: websocket.BinaryMessage, Data: frame.Encode()},
	)
	c := testClient(conn)

	applied := make(chan string, 1)
	c.FetchConfig = func(context.Context) (string, error) {
		return "[server]\nport = 4001\n", nil
	}
	c.ApplyConfig = func(resolved string) error {
		applied <- resolved
		return nil
	}

	go func() { time.Sleep(100 * time.Millisecond); conn.Close() }()
	_ = c.serve(context.Background())

	select {
	case got := <-applied:
		if !contains(got, "4001") {
			t.Errorf("applied config = %q", got)
		}
	default:
		t.Error("a config push did not trigger a reload")
	}
}

func TestUnrelatedPushIsIgnored(t *testing.T) {
	push, _ := msgpack.Marshal(topicPush{Topic: "config:watch:someone-else"})
	frame := newFrame(FramePush, [16]byte{3}, push, time.Now())

	conn := newFakeConn(
		acceptedBootstrap(),
		wsMessage{Type: websocket.BinaryMessage, Data: frame.Encode()},
	)
	c := testClient(conn)
	var fetched bool
	c.FetchConfig = func(context.Context) (string, error) {
		fetched = true
		return "", nil
	}
	c.ApplyConfig = func(string) error { return nil }

	go func() { time.Sleep(80 * time.Millisecond); conn.Close() }()
	_ = c.serve(context.Background())

	if fetched {
		t.Error("a push for another service triggered our config reload")
	}
}

func TestMalformedFrameDoesNotKillTheConnection(t *testing.T) {
	conn := newFakeConn(
		acceptedBootstrap(),
		wsMessage{Type: websocket.BinaryMessage, Data: []byte{0x01, 0x02}},
		wsMessage{Type: websocket.BinaryMessage,
			Data: newFrame(FrameHeartbeat, [16]byte{4}, nil, time.Now()).Encode()},
	)
	c := testClient(conn)

	go func() { time.Sleep(100 * time.Millisecond); conn.Close() }()
	_ = c.serve(context.Background())

	// 心跳仍被处理，说明坏帧只是被丢弃而没有拖垮连接。
	var sawPong bool
	for _, m := range conn.sent()[2:] {
		if f, err := ParseFrame(m.Data); err == nil && f.Type == FrameHeartbeat {
			sawPong = true
		}
	}
	if !sawPong {
		t.Error("the connection stopped processing after a malformed frame")
	}
}

func TestMethodsAreStable(t *testing.T) {
	// 方法名是外部契约，ServerAgent 按这些字符串调用。
	methods := Methods()
	if len(methods) != 27 {
		t.Fatalf("Methods() = %d entries, want 27", len(methods))
	}
	seen := map[string]bool{}
	for _, m := range methods {
		if seen[m] {
			t.Errorf("duplicate method %q", m)
		}
		seen[m] = true
		if len(m) < 6 || m[:5] != "cert." {
			t.Errorf("method %q does not use the cert. prefix", m)
		}
	}
	for _, want := range []string{
		"cert.stats", "cert.list", "cert.get", "cert.create", "cert.update",
		"cert.delete", "cert.renew", "cert.deploy", "cert.download", "cert.info",
		"cert.events", "cert.deployments", "cert.deploymentEvents",
		"cert.acmeAccounts", "cert.dnsProviders", "cert.deployTargets", "cert.logs",
	} {
		if !seen[want] {
			t.Errorf("method %q is missing", want)
		}
	}
}

// ── RPC dispatch ───────────────────────────────────────────────────────

type fakeApp struct {
	store    db.Store
	issued   []int64
	deployed []int64
	mu       sync.Mutex
}

func (f *fakeApp) Store() db.Store { return f.store }
func (f *fakeApp) Issue(_ context.Context, certID int64, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = append(f.issued, certID)
	return nil
}
func (f *fakeApp) Deploy(_ context.Context, certID int64, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deployed = append(f.deployed, certID)
	return nil
}

func newTestHandler(t *testing.T) (*Handler, *fakeApp) {
	t.Helper()
	store, err := db.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	app := &fakeApp{store: store}
	return &Handler{App: app}, app
}

func TestDispatchRequiresNumericID(t *testing.T) {
	h, _ := newTestHandler(t)
	ctx := context.Background()
	for _, params := range []string{`{}`, `{"id":"5"}`, `{"id":0}`} {
		if _, err := h.Dispatch(ctx, MethodGet, json.RawMessage(params)); err == nil {
			t.Errorf("Dispatch with params %s = nil error, want a complaint about the id", params)
		}
	}
}

func TestDispatchUnknownMethod(t *testing.T) {
	h, _ := newTestHandler(t)
	if _, err := h.Dispatch(context.Background(), "cert.teleport", nil); err == nil {
		t.Error("Dispatch of an unknown method = nil error, want failure")
	}
}

func TestDispatchDownloadIsAudited(t *testing.T) {
	// 这是唯一会经总线吐出私钥的方法，而总线只靠引导 token 认证，
	// 所以必须留下可归因的审计记录。
	h, app := newTestHandler(t)
	ctx := context.Background()
	store := app.store

	acctID, _ := store.CreateACMEAccount(ctx, db.ACMEAccount{
		Name: "le", DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
	})
	dnsID, _ := store.CreateDNSProvider(ctx, db.DNSProvider{Name: "cf", Kind: "cloudflare", Config: "{}"})
	certID, _ := store.CreateCertificate(ctx, db.Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	err := store.SaveIssuedCertificate(ctx, certID, db.IssuedCertificate{
		CertPEM: "LEAF", ChainPEM: "INTER", KeyPEM: "SECRET",
		Serial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	params, _ := json.Marshal(idParams{ID: certID})
	result, err := h.Dispatch(ctx, MethodDownload, params)
	if err != nil {
		t.Fatal(err)
	}
	bundle := result.(map[string]string)
	if bundle["keyPem"] != "SECRET" {
		t.Errorf("bundle = %v, want the key included", bundle)
	}

	logs, err := store.ListLogs(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || logs[0].Action != "download" || logs[0].Operator != "bus" {
		t.Errorf("logs = %+v, want a download entry attributed to the bus", logs)
	}
}

func TestDispatchRenewSchedulesIssuance(t *testing.T) {
	h, app := newTestHandler(t)
	params, _ := json.Marshal(idParams{ID: 7})
	if _, err := h.Dispatch(context.Background(), MethodRenew, params); err != nil {
		t.Fatal(err)
	}
	// 签发在后台跑，给它一点时间。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		app.mu.Lock()
		n := len(app.issued)
		app.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("cert.renew did not start an issuance")
}

func TestDispatchListDegradesOnBadParams(t *testing.T) {
	// 参数坏掉时退化为"不过滤"，与 Rust 行为一致，而不是让调用失败。
	h, _ := newTestHandler(t)
	if _, err := h.Dispatch(context.Background(), MethodList, json.RawMessage(`"not an object"`)); err != nil {
		t.Errorf("Dispatch = %v, want bad list params to degrade to no filter", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
