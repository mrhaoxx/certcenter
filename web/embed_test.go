// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
)

func TestIsPlaceholderMatchesTheCommittedStandIn(t *testing.T) {
	// The committed tree holds the placeholder, so this must report true.
	// A real build replaces it and the startup warning goes quiet.
	if !IsPlaceholder() {
		t.Skip("dist holds a real build; nothing to check here")
	}
	raw, err := Dist.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	// The trap this guards against: valid HTML with a mount point and no
	// script, which renders as a blank page rather than an error.
	if !strings.Contains(string(raw), `id="root"`) {
		t.Error("the placeholder has no mount point; the guard is matching the wrong file")
	}
	if strings.Contains(string(raw), "<script") {
		t.Error("the placeholder carries a script tag, so it is not the stand-in")
	}
}
