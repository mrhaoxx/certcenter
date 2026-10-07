// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// buildPipeline turns a step list into a target with a dialer that hands
// out a distinct fake session per host.
func buildMultiHost(t *testing.T, steps []map[string]any) (*sshTarget, map[string]*fakeSession) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	target, err := newPipeline(string(raw), Options{})
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	ssht := target.(*sshTarget)

	byHost := map[string]*fakeSession{}
	ssht.dial = func(_ context.Context, cfg connectConfig) (session, error) {
		f := &fakeSession{}
		byHost[cfg.Host] = f
		return f, nil
	}
	return ssht, byHost
}

func connectStep(id, host string) map[string]any {
	cfg := map[string]any{"host": host, "username": "root", "auth_type": "password", "password": "x"}
	if id != "" {
		cfg["id"] = id
	}
	return step(StepSSHConnect, cfg)
}

func TestPipelineReachesTwoHosts(t *testing.T) {
	// One certificate on web1 and web2 is an ordinary requirement. A single
	// session per target meant one target per machine, with no way to order
	// the work or stop after the first failure.
	ssht, hosts := buildMultiHost(t, []map[string]any{
		connectStep("web1", "10.0.0.1"),
		step(StepRunCommand, map[string]any{"command": "reload-one", "on": "web1"}),
		connectStep("web2", "10.0.0.2"),
		step(StepRunCommand, map[string]any{"command": "reload-two", "on": "web2"}),
		// Naming an earlier connection must still work after a later one
		// was opened — the pipeline is not a stack.
		step(StepRunCommand, map[string]any{"command": "verify-one", "on": "web1"}),
	})

	if _, err := ssht.Deploy(context.Background(), testCert()); err != nil {
		t.Fatalf("Deploy = %v", err)
	}

	one, two := hosts["10.0.0.1"], hosts["10.0.0.2"]
	if one == nil || two == nil {
		t.Fatalf("expected both hosts dialled, got %v", hosts)
	}
	if got := strings.Join(one.Commands, " "); !strings.Contains(got, "reload-one") ||
		!strings.Contains(got, "verify-one") {
		t.Errorf("web1 ran %v", one.Commands)
	}
	if strings.Contains(strings.Join(one.Commands, " "), "reload-two") {
		t.Error("a command meant for web2 ran on web1")
	}
	if got := strings.Join(two.Commands, " "); !strings.Contains(got, "reload-two") {
		t.Errorf("web2 ran %v", two.Commands)
	}
}

func TestStepWithoutOnUsesTheLatestConnection(t *testing.T) {
	// A single-host pipeline should not have to name anything.
	ssht, hosts := buildMultiHost(t, []map[string]any{
		connectStep("", "10.0.0.9"),
		step(StepRunCommand, map[string]any{"command": "plain"}),
	})
	if _, err := ssht.Deploy(context.Background(), testCert()); err != nil {
		t.Fatalf("Deploy = %v", err)
	}
	if got := hosts["10.0.0.9"].Commands; len(got) != 1 || !strings.Contains(got[0], "plain") {
		t.Errorf("commands = %v", got)
	}
}

func TestUnknownConnectionIsRefusedWithTheOpenOnes(t *testing.T) {
	// A typo in "on" would otherwise run the command on whichever host
	// happened to be current.
	ssht, _ := buildMultiHost(t, []map[string]any{
		connectStep("web1", "10.0.0.1"),
		step(StepRunCommand, map[string]any{"command": "x", "on": "wbe1"}),
	})
	_, err := ssht.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("a misspelled connection id was accepted")
	}
	if !strings.Contains(err.Error(), "wbe1") || !strings.Contains(err.Error(), "web1") {
		t.Errorf("error = %v, want both the bad id and the open ones", err)
	}
}

func TestDuplicateConnectionIDIsRefused(t *testing.T) {
	// Two connections sharing an id would make "on" ambiguous.
	ssht, _ := buildMultiHost(t, []map[string]any{
		connectStep("web", "10.0.0.1"),
		connectStep("web", "10.0.0.2"),
	})
	_, err := ssht.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("a duplicate connection id was accepted")
	}
	if !strings.Contains(err.Error(), "already open") {
		t.Errorf("error = %v", err)
	}
}

func TestEveryHostIsClosed(t *testing.T) {
	// Each connection is closed when the pipeline ends, including after a
	// failure partway through.
	ssht, hosts := buildMultiHost(t, []map[string]any{
		connectStep("a", "10.0.0.1"),
		connectStep("b", "10.0.0.2"),
		step(StepTestCommand, map[string]any{"command": "false", "on": "a"}),
	})
	hostFails := func() {
		for _, f := range hosts {
			f.Exit = map[string]int{"false": 1}
		}
	}
	ssht.dial = func(_ context.Context, cfg connectConfig) (session, error) {
		f := &fakeSession{Exit: map[string]int{"false": 1}}
		hosts[cfg.Host] = f
		return f, nil
	}
	hostFails()

	if _, err := ssht.Deploy(context.Background(), testCert()); err == nil {
		t.Fatal("the failing test_command did not stop the pipeline")
	}
	for host, f := range hosts {
		if !f.closed {
			t.Errorf("the session for %s was left open", host)
		}
	}
}
