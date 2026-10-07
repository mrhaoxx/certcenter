// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"strings"
	"testing"
)

func TestNewUnknownKind(t *testing.T) {
	_, err := New("route53", `{}`)
	if err == nil {
		t.Fatal("New with an unknown kind = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "route53") {
		t.Errorf("error = %v, want it to name the unsupported kind", err)
	}
}

func TestNewRejectsMalformedConfig(t *testing.T) {
	for _, kind := range Kinds() {
		t.Run(kind, func(t *testing.T) {
			if _, err := New(kind, `not json`); err == nil {
				t.Error("New with malformed JSON = nil error, want failure")
			}
		})
	}
}

func TestNewRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name, kind, config, wantField string
	}{
		{"cloudflare 缺 api_token", KindCloudflare, `{"zone_id":"z"}`, "api_token"},
		// zone_id 现在可选：留空表示自动发现，见
		// TestNewCloudflareAcceptsMissingZoneID。
		{"aliyun 缺 access_key_id", KindAliyun, `{"access_key_secret":"s","domain":"example.com"}`, "access_key_id"},
		{"aliyun 缺 access_key_secret", KindAliyun, `{"access_key_id":"k","domain":"example.com"}`, "access_key_secret"},
		{"aliyun 缺 domain", KindAliyun, `{"access_key_id":"k","access_key_secret":"s"}`, "domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.kind, tt.config)
			if err == nil {
				t.Fatalf("New = nil error, want a complaint about %s", tt.wantField)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("error = %v, want it to name %q", err, tt.wantField)
			}
		})
	}
}

func TestNewRejectsUnknownConfigKey(t *testing.T) {
	// 配置里写错键名（比如 zone_id 写成 zoneid）不能静默忽略，
	// 否则用户对着一个"明明填了却不生效"的表单排查半天。
	if _, err := New(KindCloudflare, `{"api_token":"t","zone_id":"z","zoneid":"oops"}`); err == nil {
		t.Error("New with an unknown config key = nil error, want failure")
	}
}

func TestKinds(t *testing.T) {
	kinds := Kinds()
	if len(kinds) != 2 {
		t.Fatalf("Kinds() = %v, want two entries", kinds)
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		seen[k] = true
	}
	if !seen[KindCloudflare] || !seen[KindAliyun] {
		t.Errorf("Kinds() = %v, want it to contain %q and %q", kinds, KindCloudflare, KindAliyun)
	}
}
