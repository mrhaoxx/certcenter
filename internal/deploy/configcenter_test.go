// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// fakeRPC replays scripted responses for the config center's JSON-RPC.
type fakeRPC struct {
	Sent      []rpcRequest
	Responses []rpcResponse
	// Extra responses are delivered before the real ones, standing in for
	// the topic pushes the management plane interleaves.
	pos      int
	WriteErr error
	ReadErr  error
	closed   bool
}

func (f *fakeRPC) WriteJSON(v any) error {
	if f.WriteErr != nil {
		return f.WriteErr
	}
	req, ok := v.(rpcRequest)
	if !ok {
		return fmt.Errorf("unexpected write type %T", v)
	}
	f.Sent = append(f.Sent, req)
	return nil
}

func (f *fakeRPC) ReadJSON(v any) error {
	if f.ReadErr != nil {
		return f.ReadErr
	}
	if f.pos >= len(f.Responses) {
		return fmt.Errorf("no more responses")
	}
	resp := f.Responses[f.pos]
	f.pos++
	raw, _ := json.Marshal(resp)
	return json.Unmarshal(raw, v)
}

func (f *fakeRPC) Close() error { f.closed = true; return nil }

func newTestConfigCenter(t *testing.T, fake *fakeRPC) *configCenter {
	t.Helper()
	target, err := newConfigCenter(
		`{"config_key_cert":"tls/cert","config_key_key":"tls/key"}`,
		"ws://bus:9901/api/events/ws")
	if err != nil {
		t.Fatal(err)
	}
	cc := target.(*configCenter)
	cc.dial = func(context.Context, string) (rpcConn, error) { return fake, nil }
	return cc
}

func TestConfigCenterPublishesBothKeys(t *testing.T) {
	fake := &fakeRPC{Responses: []rpcResponse{
		{ID: "deploy-cert"},
		{ID: "deploy-key"},
	}}
	cc := newTestConfigCenter(t, fake)

	events, err := cc.Deploy(context.Background(), testCert())
	if err != nil {
		t.Fatalf("Deploy() = %v", err)
	}
	if len(fake.Sent) != 2 {
		t.Fatalf("sent %d requests, want 2", len(fake.Sent))
	}
	for _, req := range fake.Sent {
		if req.Method != "config.put" {
			t.Errorf("method = %q, want config.put", req.Method)
		}
		params, ok := req.Params.(configPutParams)
		if !ok {
			t.Fatalf("params are %T, want configPutParams", req.Params)
		}
		if params.Format != "text" {
			t.Errorf("format = %q, want text", params.Format)
		}
		switch req.ID {
		case "deploy-cert":
			if params.Key != "tls/cert" {
				t.Errorf("cert key = %q", params.Key)
			}
			// 证书侧推的是完整链。库里叶子和链分开存，这里必须重新拼；
			// Rust 版因为两列存的是同一份完整链，拼出来是重复的两遍。
			if !strings.Contains(params.Template, "LEAF-PEM") ||
				!strings.Contains(params.Template, "CHAIN-PEM") {
				t.Errorf("cert template = %q, want the full chain", params.Template)
			}
			if strings.Count(params.Template, "LEAF-PEM") != 1 {
				t.Errorf("cert template repeats the leaf: %q", params.Template)
			}
		case "deploy-key":
			if params.Key != "tls/key" {
				t.Errorf("key key = %q", params.Key)
			}
			if params.Template != "KEY-PEM\n" {
				t.Errorf("key template = %q", params.Template)
			}
		default:
			t.Errorf("unexpected request id %q", req.ID)
		}
	}
	if !hasEvent(events, "configcenter_success", "Published") {
		t.Errorf("events = %v", eventSummary(events))
	}
	if !fake.closed {
		t.Error("the connection was not closed")
	}
}

func TestConfigCenterSkipsTopicPushes(t *testing.T) {
	// 管理面会在响应之间夹杂主题推送，它们没有匹配的 id，必须跳过。
	fake := &fakeRPC{Responses: []rpcResponse{
		{ID: ""},
		{ID: "some-other-subscription"},
		{ID: "deploy-cert"},
		{ID: ""},
		{ID: "deploy-key"},
	}}
	cc := newTestConfigCenter(t, fake)
	if _, err := cc.Deploy(context.Background(), testCert()); err != nil {
		t.Errorf("Deploy() = %v, want topic pushes to be skipped", err)
	}
}

func TestConfigCenterSurfacesRPCError(t *testing.T) {
	fake := &fakeRPC{Responses: []rpcResponse{
		{ID: "deploy-cert", Error: json.RawMessage(`{"message":"permission denied"}`)},
	}}
	cc := newTestConfigCenter(t, fake)

	events, err := cc.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("Deploy = nil error, want the RPC error surfaced")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v", err)
	}
	if !hasEvent(events, "configcenter_error", "permission denied") {
		t.Errorf("events = %v", eventSummary(events))
	}
}

func TestConfigCenterRequiresManagementURL(t *testing.T) {
	// management_url 来自应用的 [bus] 配置，不是每个目标各自填写。
	target, err := newConfigCenter(`{"config_key_cert":"c","config_key_key":"k"}`, "")
	if err != nil {
		t.Fatal(err)
	}
	events, err := target.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("Deploy without a management URL = nil error, want failure")
	}
	if !hasEvent(events, "configcenter_error", "management_url") {
		t.Errorf("events = %v, want the missing URL named", eventSummary(events))
	}
}

func TestConfigCenterAcceptsDoubleEncodedConfig(t *testing.T) {
	// Rust 版有时把配置存成"包着 JSON 的 JSON 字符串"，要能读回来。
	inner := `{"config_key_cert":"c","config_key_key":"k"}`
	doubled, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newConfigCenter(string(doubled), "ws://x"); err != nil {
		t.Errorf("newConfigCenter on a double-encoded config = %v, want it unwrapped", err)
	}
}

func TestConfigCenterRequiresBothKeys(t *testing.T) {
	if _, err := newConfigCenter(`{"config_key_cert":"c"}`, "ws://x"); err == nil {
		t.Error("newConfigCenter without config_key_key = nil error, want failure")
	}
}
