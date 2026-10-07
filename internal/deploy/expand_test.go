// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Placeholders were expanded in commands, URLs and bodies but not in any
// path, which is where {{domain}} is most useful: a per-domain layout like
// /etc/ssl/{{domain}}.crt wrote a file with the braces still in its name.
func TestPathsExpandPlaceholders(t *testing.T) {
	t.Run("upload_file", func(t *testing.T) {
		fake := &fakeSession{}
		target := buildPipeline(t, fake, step(StepUploadFile, map[string]any{
			"source": "fullchain", "dest_path": "/home/certer/{{domain}}.crt", "mode": "0644",
		}))
		if _, err := target.Deploy(context.Background(), testCert()); err != nil {
			t.Fatal(err)
		}
		if len(fake.Uploads) != 1 {
			t.Fatalf("uploads = %v", fake.Uploads)
		}
		if got := fake.Uploads[0].Dest; got != "/home/certer/example.com.crt" {
			t.Errorf("dest = %q, want the domain substituted", got)
		}
	})

	t.Run("write_content", func(t *testing.T) {
		fake := &fakeSession{}
		target := buildPipeline(t, fake, step(StepWriteContent, map[string]any{
			"content": "ok", "dest_path": "/etc/nginx/{{domain}}.conf",
		}))
		if _, err := target.Deploy(context.Background(), testCert()); err != nil {
			t.Fatal(err)
		}
		if got := fake.Uploads[0].Dest; got != "/etc/nginx/example.com.conf" {
			t.Errorf("dest = %q, want the domain substituted", got)
		}
	})

	t.Run("backup_file", func(t *testing.T) {
		fake := &fakeSession{}
		target := buildPipeline(t, fake, step(StepBackupFile, map[string]any{
			"path": "/etc/ssl/{{domain}}.crt", "suffix": ".bak",
		}))
		if _, err := target.Deploy(context.Background(), testCert()); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(fake.Commands, " ")
		if !strings.Contains(joined, "example.com.crt") {
			t.Errorf("commands = %v, want the domain substituted", fake.Commands)
		}
		if strings.Contains(joined, "{{domain}}") {
			t.Errorf("the placeholder survived: %v", fake.Commands)
		}
	})

	t.Run("local_write", func(t *testing.T) {
		dir := t.TempDir()
		st := &pipelineState{cert: testCert(), paths: map[string]string{}}
		cfg, _ := json.Marshal(map[string]any{
			"source": SourceCertificate, "path": filepath.Join(dir, "{{domain}}.pem"),
		})
		if err := stepLocalWrite(context.Background(), st, cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "example.com.pem")); err != nil {
			entries, _ := os.ReadDir(dir)
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("no file named for the domain; directory holds %v", names)
		}
	})
}

// TestUploadedPathIsRecordedExpanded pins that a later step referencing
// {{cert_path}} gets the real path, not the template that produced it.
func TestUploadedPathIsRecordedExpanded(t *testing.T) {
	fake := &fakeSession{}
	target := buildPipeline(t, fake,
		step(StepUploadFile, map[string]any{
			"source": "certificate", "dest_path": "/ssl/{{domain}}.crt",
		}),
		step(StepRunCommand, map[string]any{"command": "reload {{cert_path}}"}),
	)
	if _, err := target.Deploy(context.Background(), testCert()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.Commands, " ")
	if !strings.Contains(joined, "/ssl/example.com.crt") {
		t.Errorf("commands = %v, want the recorded path already expanded", fake.Commands)
	}
}
