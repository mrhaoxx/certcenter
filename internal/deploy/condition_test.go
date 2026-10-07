// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"strings"
	"testing"
)

func TestConditionBranchRunsEveryStep(t *testing.T) {
	// A branch used to be a single step, so "if nginx is installed, upload
	// the config, reload it and check" could only be written by nesting
	// conditions inside one another.
	fake := &fakeSession{}
	target := buildPipeline(t, fake, step(StepCondition, map[string]any{
		"mode":    "exit_code",
		"command": "which nginx",
		"then_steps": []map[string]any{
			step(StepRunCommand, map[string]any{"command": "install-config"}),
			step(StepRunCommand, map[string]any{"command": "reload-nginx"}),
			step(StepRunCommand, map[string]any{"command": "check-nginx"}),
		},
	}))

	if _, err := target.Deploy(context.Background(), testCert()); err != nil {
		t.Fatalf("Deploy = %v", err)
	}
	joined := strings.Join(fake.Commands, " | ")
	for _, want := range []string{"install-config", "reload-nginx", "check-nginx"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q did not run; commands = %v", want, fake.Commands)
		}
	}
	// And in order, since a reload before the config is written is useless.
	iConfig := strings.Index(joined, "install-config")
	iReload := strings.Index(joined, "reload-nginx")
	iCheck := strings.Index(joined, "check-nginx")
	if !(iConfig < iReload && iReload < iCheck) {
		t.Errorf("branch steps ran out of order: %v", fake.Commands)
	}
}

func TestConditionBranchStopsAtTheFirstFailure(t *testing.T) {
	// A failing step inside a branch must abort the pipeline rather than
	// letting the rest of the branch run against a half-finished state.
	fake := &fakeSession{Exit: map[string]int{"will-fail": 1}}
	target := buildPipeline(t, fake, step(StepCondition, map[string]any{
		"command": "probe",
		"then_steps": []map[string]any{
			step(StepTestCommand, map[string]any{"command": "will-fail"}),
			step(StepRunCommand, map[string]any{"command": "must-not-run"}),
		},
	}))

	_, err := target.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("a failing branch step did not stop the pipeline")
	}
	if !strings.Contains(err.Error(), "then_steps") {
		t.Errorf("error = %v, want it to name the branch", err)
	}
	if strings.Contains(strings.Join(fake.Commands, " "), "must-not-run") {
		t.Error("the branch continued past a failure")
	}
}

func TestConditionEmptyBranchIsFine(t *testing.T) {
	// "Do nothing when the condition does not hold" is a normal shape.
	fake := &fakeSession{Exit: map[string]int{"probe": 1}}
	target := buildPipeline(t, fake, step(StepCondition, map[string]any{
		"command":    "probe",
		"then_steps": []map[string]any{step(StepRunCommand, map[string]any{"command": "skipped"})},
	}))
	if _, err := target.Deploy(context.Background(), testCert()); err != nil {
		t.Fatalf("Deploy = %v", err)
	}
	if strings.Contains(strings.Join(fake.Commands, " "), "skipped") {
		t.Error("the then branch ran although the condition failed")
	}
}
