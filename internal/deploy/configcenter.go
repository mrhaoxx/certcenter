// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
)

// configCenterTimeout bounds the whole publish, matching the Rust
// implementation's ten seconds.
const configCenterTimeout = 10 * time.Second

// configCenter publishes the certificate into the ServerAgent config
// center over its management WebSocket, which speaks JSON-RPC and is
// auto-admin (no bootstrap handshake).
type configCenter struct {
	ConfigKeyCert string `json:"config_key_cert"`
	ConfigKeyKey  string `json:"config_key_key"`

	// managementURL is injected from the app's [bus] config, never authored
	// per target — the operator configures the bus once.
	managementURL string

	// dial is swapped in tests.
	dial func(ctx context.Context, url string) (rpcConn, error)
}

// rpcConn is the subset of a WebSocket connection this target needs.
type rpcConn interface {
	WriteJSON(v any) error
	ReadJSON(v any) error
	Close() error
}

func newConfigCenter(configJSON, managementURL string) (Target, error) {
	var c configCenter
	// The stored config was sometimes double-encoded by the Rust
	// implementation (a JSON string containing JSON), so unwrap one layer
	// before giving up.
	if err := decodeConfig(configJSON, &c); err != nil {
		var inner string
		if json.Unmarshal([]byte(configJSON), &inner) == nil {
			if err2 := decodeConfig(inner, &c); err2 != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	if c.ConfigKeyCert == "" || c.ConfigKeyKey == "" {
		return nil, fmt.Errorf("configcenter requires config_key_cert and config_key_key")
	}
	c.managementURL = managementURL
	c.dial = dialWebSocket
	return &c, nil
}

func dialWebSocket(ctx context.Context, url string) (rpcConn, error) {
	dialer := websocket.Dialer{HandshakeTimeout: configCenterTimeout}
	conn, _, err := dialer.DialContext(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// rpcRequest is the management plane's JSON-RPC shape.
type rpcRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params"`
}

type rpcResponse struct {
	ID     string          `json:"id"`
	Error  json.RawMessage `json:"error"`
	Result json.RawMessage `json:"result"`
}

// configPutParams matches config.put on the management plane.
type configPutParams struct {
	Key         string `json:"key"`
	Template    string `json:"template"`
	Format      string `json:"format"`
	Description string `json:"description"`
}

func (c *configCenter) Deploy(ctx context.Context, cert *CertificateData) ([]Event, error) {
	var events []Event
	events = append(events, Event{
		Type: "configcenter_connect", Level: LevelInfo,
		Message: fmt.Sprintf("Connecting to the config center at %s", c.managementURL),
		Detail:  fmt.Sprintf("cert_key=%s, key_key=%s", c.ConfigKeyCert, c.ConfigKeyKey),
	})

	if c.managementURL == "" {
		err := fmt.Errorf("management_url is not configured (check the [bus] section)")
		events = append(events, Event{Type: "configcenter_error", Level: LevelError,
			Message: err.Error()})
		return events, err
	}

	ctx, cancel := context.WithTimeout(ctx, configCenterTimeout)
	defer cancel()

	conn, err := c.dial(ctx, c.managementURL)
	if err != nil {
		events = append(events, Event{Type: "configcenter_error", Level: LevelError,
			Message: "Could not reach the config center", Detail: err.Error()})
		return events, err
	}
	defer conn.Close()

	// The certificate side gets the full chain; cert_pem holds the leaf
	// alone, so the two are recombined here.
	sends := []struct{ id, key, template, description string }{
		{"deploy-cert", c.ConfigKeyCert, cert.FullChainPEM(),
			"TLS certificate (auto-deployed by certcenter)"},
		{"deploy-key", c.ConfigKeyKey, cert.KeyPEM,
			"TLS private key (auto-deployed by certcenter)"},
	}
	pending := map[string]string{}
	for _, s := range sends {
		if err := conn.WriteJSON(rpcRequest{
			ID: s.id, Method: "config.put",
			Params: configPutParams{
				Key: s.key, Template: s.template, Format: "text", Description: s.description,
			},
		}); err != nil {
			events = append(events, Event{Type: "configcenter_error", Level: LevelError,
				Message: "Could not send the configuration", Detail: err.Error()})
			return events, err
		}
		pending[s.id] = s.key
	}

	// Read until both requests are acknowledged, skipping topic pushes
	// (which carry no matching id).
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			events = append(events, Event{Type: "configcenter_error", Level: LevelError,
				Message: "Timed out waiting for the config center"})
			return events, fmt.Errorf("timed out publishing to the config center")
		}
		var resp rpcResponse
		if err := conn.ReadJSON(&resp); err != nil {
			events = append(events, Event{Type: "configcenter_error", Level: LevelError,
				Message: "Config center connection failed", Detail: err.Error()})
			return events, err
		}
		key, ours := pending[resp.ID]
		if !ours {
			continue
		}
		if len(resp.Error) > 0 && string(resp.Error) != "null" {
			err := fmt.Errorf("config center rejected %q: %s", key, truncate(string(resp.Error), 500))
			events = append(events, Event{Type: "configcenter_error", Level: LevelError,
				Message: err.Error()})
			return events, err
		}
		delete(pending, resp.ID)
	}

	events = append(events, Event{Type: "configcenter_success", Level: LevelSuccess,
		Message: fmt.Sprintf("Published to the config center (%s, %s)",
			c.ConfigKeyCert, c.ConfigKeyKey)})
	return events, nil
}
