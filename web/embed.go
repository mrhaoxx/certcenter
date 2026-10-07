// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package web embeds the built SPA. web/dist ships a committed
// placeholder so `go build ./...` works without Node; the real bundle
// comes from milestone 7.
package web

import (
	"bytes"
	"embed"
)

//go:embed all:dist
var Dist embed.FS

// placeholderMarker appears only in the committed stand-in for the SPA.
const placeholderMarker = "Placeholder bundle."

// IsPlaceholder reports whether the embedded SPA is the committed
// stand-in rather than a real build.
//
// The stand-in is valid HTML with a #root div and no script tag, so a
// binary built from it serves a blank page that looks like a frontend
// crash. That happens whenever the binary is compiled before `vite build`
// runs — or after the placeholder is restored — and the failure shows up
// only in a browser, far from the mistake.
func IsPlaceholder() bool {
	raw, err := Dist.ReadFile("dist/index.html")
	if err != nil {
		return true
	}
	return bytes.Contains(raw, []byte(placeholderMarker))
}
