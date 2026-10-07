// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// stepLocalWriteConfig writes certificate material to a path on the
// machine running CertCenter.
//
// This is what a co-located service needs: nginx in the next container
// with a shared volume, or anything reading from disk. Doing it over SSH
// back to ourselves would need credentials for our own host.
type stepLocalWriteConfig struct {
	// Source selects the material: certificate, private_key, chain or
	// fullchain. Content overrides it for a rendered snippet.
	Source  string `json:"source"`
	Content string `json:"content"`
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	// EnsureDir creates the parent directory first.
	EnsureDir bool `json:"ensure_dir"`
}

func stepLocalWrite(_ context.Context, st *pipelineState, raw json.RawMessage) error {
	var cfg stepLocalWriteConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse local_write config: %w", err)
	}
	if cfg.Path == "" {
		return fmt.Errorf("local_write needs a path")
	}
	path := st.expand(cfg.Path)

	body, err := materialFor(st, cfg.Source, cfg.Content)
	if err != nil {
		return err
	}

	mode := parseFileMode(cfg.Mode, 0o644)
	if cfg.EnsureDir {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
		}
	}

	// Write to a temporary file in the same directory and rename over the
	// target. A reader that opens the file midway through a plain write
	// gets a truncated certificate, and a web server reloading at that
	// moment fails to start.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".certcenter-*")
	if err != nil {
		return fmt.Errorf("create a temporary file next to %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}

	// Register the path so later steps can reference it, the same way
	// upload_file does for the remote side.
	switch cfg.Source {
	case SourceCertificate, "":
		st.paths["cert_path"] = path
	case SourcePrivateKey:
		st.paths["key_path"] = path
	case SourceChain:
		st.paths["chain_path"] = path
	case SourceFullChain:
		st.paths["fullchain_path"] = path
	}

	st.emit(Event{Type: StepLocalWrite, Level: LevelSuccess,
		Message: fmt.Sprintf("Wrote %s", path),
		Detail:  fmt.Sprintf("%d bytes, mode %s", len(body), mode)})
	return nil
}

// materialFor resolves what a step should write: an explicit rendered
// Content, or one of the certificate's parts.
func materialFor(st *pipelineState, source, content string) (string, error) {
	if content != "" {
		return st.expand(content), nil
	}
	switch source {
	case SourceCertificate, "":
		return st.cert.CertPEM, nil
	case SourcePrivateKey:
		return st.cert.KeyPEM, nil
	case SourceChain:
		return st.cert.ChainPEM, nil
	case SourceFullChain:
		return st.cert.FullChainPEM(), nil
	default:
		return "", fmt.Errorf("unknown source %q", source)
	}
}

func parseFileMode(s string, fallback os.FileMode) os.FileMode {
	if s == "" {
		return fallback
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return fallback
	}
	return os.FileMode(n)
}
