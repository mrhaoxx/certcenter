// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gorilla/websocket"
)

// The management plane speaks plain JSON-RPC over its own WebSocket and is
// auto-admin: no bootstrap, no token. That is its design, not an oversight
// here — it is expected to be reachable only from inside the deployment.

const configResolveID = "config-fetch"

type resolveRequest struct {
	ID     string        `json:"id"`
	Method string        `json:"method"`
	Params resolveParams `json:"params"`
}

type resolveParams struct {
	ConfigKey string `json:"config_key"`
	NodeID    string `json:"node_id"`
}

type resolveResponse struct {
	ID     string          `json:"id"`
	Error  json.RawMessage `json:"error"`
	Result struct {
		Rendered string `json:"rendered"`
	} `json:"result"`
}

// FetchResolvedConfig asks the config center to render this service's
// configuration and returns the TOML document.
func FetchResolvedConfig(ctx context.Context, managementURL, configKey, nodeID string) (string, error) {
	if managementURL == "" {
		return "", fmt.Errorf("management_url is not configured")
	}
	dialer := websocket.Dialer{HandshakeTimeout: configRPCTimeout}
	conn, _, err := dialer.DialContext(ctx, managementURL, nil)
	if err != nil {
		return "", fmt.Errorf("dial the config center: %w", err)
	}
	defer conn.Close()

	req := resolveRequest{
		ID: configResolveID, Method: "config.resolve",
		Params: resolveParams{ConfigKey: configKey, NodeID: nodeID},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	if err := conn.WriteMessage(websocket.TextMessage, raw); err != nil {
		return "", fmt.Errorf("send config.resolve: %w", err)
	}

	// Cancellation has to unblock the read, so the connection is closed
	// from a watcher goroutine.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	// The management plane interleaves topic pushes with responses, so read
	// until our own id comes back.
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", fmt.Errorf("config.resolve timed out: %w", ctxErr)
			}
			return "", fmt.Errorf("read config.resolve response: %w", err)
		}
		var resp resolveResponse
		if err := json.Unmarshal(data, &resp); err != nil {
			continue // not a response we understand; keep waiting
		}
		if resp.ID != configResolveID {
			continue
		}
		if len(resp.Error) > 0 && string(resp.Error) != "null" {
			return "", fmt.Errorf("config.resolve failed: %s", resp.Error)
		}
		if resp.Result.Rendered == "" {
			return "", fmt.Errorf("config.resolve returned no rendered configuration")
		}
		return resp.Result.Rendered, nil
	}
}
