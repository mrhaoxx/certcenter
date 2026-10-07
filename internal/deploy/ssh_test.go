// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// fakeSession records what the pipeline asked for and replays scripted
// results, so every step is testable without an SSH server.
type fakeSession struct {
	mu       sync.Mutex
	Commands []string
	Uploads  []upload
	// Exit maps a substring of the command to the exit code to return.
	Exit map[string]int
	// Output maps a substring of the command to combined output.
	Output map[string]string
	// RunErr, when set, makes every Run fail at the transport level.
	RunErr error
	closed bool
}

type upload struct {
	Dest    string
	Content string
	Mode    string
}

func (f *fakeSession) Run(_ context.Context, cmd string) (int, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Commands = append(f.Commands, cmd)
	if f.RunErr != nil {
		return 0, "", f.RunErr
	}
	out := ""
	for k, v := range f.Output {
		if strings.Contains(cmd, k) {
			out = v
		}
	}
	for k, code := range f.Exit {
		if strings.Contains(cmd, k) {
			return code, out, nil
		}
	}
	return 0, out, nil
}

func (f *fakeSession) Upload(_ context.Context, dest string, content []byte, mode string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Uploads = append(f.Uploads, upload{Dest: dest, Content: string(content), Mode: mode})
	return nil
}

func (f *fakeSession) Close() error {
	f.closed = true
	return nil
}

func (f *fakeSession) ranContaining(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.Commands {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func testCert() *CertificateData {
	return &CertificateData{
		Domain:   "example.com",
		CertPEM:  "LEAF-PEM\n",
		KeyPEM:   "KEY-PEM\n",
		ChainPEM: "CHAIN-PEM\n",
	}
}

// buildPipeline makes an sshTarget whose session is the given fake.
func buildPipeline(t *testing.T, fake *fakeSession, steps ...map[string]any) *sshTarget {
	t.Helper()
	all := []map[string]any{{
		"type": StepSSHConnect, "name": "connect",
		"config": map[string]any{"host": "h", "username": "u", "auth_type": "password"},
	}}
	all = append(all, steps...)
	raw, err := json.Marshal(map[string]any{"steps": all})
	if err != nil {
		t.Fatal(err)
	}
	target, err := newPipeline(string(raw), Options{})
	if err != nil {
		t.Fatalf("newSSH: %v", err)
	}
	ssht := target.(*sshTarget)
	ssht.dial = func(context.Context, connectConfig) (session, error) { return fake, nil }
	return ssht
}

func step(stepType string, config map[string]any) map[string]any {
	return map[string]any{"type": stepType, "name": stepType, "config": config}
}

func TestPipelineRejectsUnusableConfig(t *testing.T) {
	tests := []struct{ name, config string }{
		{"空 steps", `{"steps":[]}`},
		{"既无 steps 也无 host", `{"other":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newPipeline(tt.config, Options{}); err == nil {
				t.Error("newPipeline = nil error, want failure")
			}
		})
	}
}

func TestPipelineNeedsNoSSHAtAll(t *testing.T) {
	// ssh_connect used to be required as the first step, which meant a
	// deployment that only writes a local file or calls a reload endpoint
	// had to open a shell it never used.
	target, err := newPipeline(
		`{"steps":[{"type":"local_write","name":"w","config":{"path":"/dev/null"}}]}`,
		Options{})
	if err != nil {
		t.Fatalf("a pipeline without ssh_connect was rejected: %v", err)
	}
	if target == nil {
		t.Fatal("newPipeline returned no target")
	}
}

func TestStepsNeedingAShellSayWhenThereIsNone(t *testing.T) {
	// Dropping the ssh_connect requirement moves the check to the steps
	// that actually need one; the message has to name the fix.
	target, err := newPipeline(
		`{"steps":[{"type":"run_command","name":"r","config":{"command":"true"}}]}`,
		Options{})
	if err != nil {
		t.Fatal(err)
	}
	events, err := target.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("run_command without a session succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), StepSSHConnect) {
		t.Errorf("error = %v, want it to name %s as the fix", err, StepSSHConnect)
	}
	if len(events) == 0 {
		t.Error("no events were recorded; the failure would be invisible in the timeline")
	}
}

func TestSSHLegacyConfigDesugars(t *testing.T) {
	// 旧扁平配置仍在生产的部署目标里，必须继续可用。
	steps, err := parseSSHSteps(`{"host":"h1","username":"root","private_key":"KEY",
		"cert_path":"/etc/ssl/c.pem","key_path":"/etc/ssl/k.pem","reload_command":"nginx -s reload"}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 4 {
		t.Fatalf("steps = %d, want 4 (connect, cert, key, reload)", len(steps))
	}
	want := []string{StepSSHConnect, StepUploadFile, StepUploadFile, StepRunCommand}
	for i, w := range want {
		if steps[i].Type != w {
			t.Errorf("steps[%d].Type = %q, want %q", i, steps[i].Type, w)
		}
	}
	var connect connectConfig
	json.Unmarshal(steps[0].Config, &connect)
	if connect.AuthType != "private_key" {
		t.Errorf("auth_type = %q, want private_key when a key is present", connect.AuthType)
	}
	if connect.Port != 22 {
		t.Errorf("port = %d, want the 22 default", connect.Port)
	}
	// 私钥的权限必须是 0600。
	var keyUpload struct {
		Mode string `json:"mode"`
	}
	json.Unmarshal(steps[2].Config, &keyUpload)
	if keyUpload.Mode != "0600" {
		t.Errorf("key upload mode = %q, want 0600", keyUpload.Mode)
	}
}

func TestUploadFileSources(t *testing.T) {
	tests := []struct {
		source, want string
	}{
		{"certificate", "LEAF-PEM\n"},
		{"private_key", "KEY-PEM\n"},
		{"chain", "CHAIN-PEM\n"},
		{"fullchain", "LEAF-PEM\nCHAIN-PEM\n"},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			fake := &fakeSession{}
			p := buildPipeline(t, fake, step(StepUploadFile, map[string]any{
				"source": tt.source, "dest_path": "/tmp/out", "mode": "0644",
			}))
			if _, err := p.Deploy(context.Background(), testCert()); err != nil {
				t.Fatal(err)
			}
			if len(fake.Uploads) != 1 {
				t.Fatalf("uploads = %d, want 1", len(fake.Uploads))
			}
			if fake.Uploads[0].Content != tt.want {
				t.Errorf("content = %q, want %q", fake.Uploads[0].Content, tt.want)
			}
		})
	}
}

func TestUploadFileRejectsUnknownSource(t *testing.T) {
	fake := &fakeSession{}
	p := buildPipeline(t, fake, step(StepUploadFile, map[string]any{"source": "nope"}))
	if _, err := p.Deploy(context.Background(), testCert()); err == nil {
		t.Error("Deploy = nil error, want failure on an unknown upload source")
	}
}

func TestUploadFileRegistersPathsForTemplates(t *testing.T) {
	// upload_file 登记的路径要能被后续步骤的 {{cert_path}} 引用。
	fake := &fakeSession{}
	p := buildPipeline(t, fake,
		step(StepUploadFile, map[string]any{"source": "certificate", "dest_path": "/etc/ssl/c.pem"}),
		step(StepUploadFile, map[string]any{"source": "private_key", "dest_path": "/etc/ssl/k.pem"}),
		step(StepRunCommand, map[string]any{"command": "install {{cert_path}} {{key_path}} {{domain}}"}),
	)
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Fatal(err)
	}
	if !fake.ranContaining("install /etc/ssl/c.pem /etc/ssl/k.pem example.com") {
		t.Errorf("commands = %v, want the registered paths expanded", fake.Commands)
	}
}

func TestTemplatePlaceholderNames(t *testing.T) {
	// {{certificate}} 与 {{private_key}}，不是 {{cert}}/{{key}}——
	// 这是数据契约，生产环境已有的配置按这些名字写。
	fake := &fakeSession{}
	p := buildPipeline(t, fake, step(StepWriteContent, map[string]any{
		"content":   "cert={{certificate}} key={{private_key}} chain={{chain}} d={{domain}}",
		"dest_path": "/tmp/rendered",
	}))
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Fatal(err)
	}
	got := fake.Uploads[0].Content
	for _, want := range []string{"cert=LEAF-PEM", "key=KEY-PEM", "chain=CHAIN-PEM", "d=example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered = %q, want it to contain %q", got, want)
		}
	}
}

func TestRunCommandNonZeroIsNotFatal(t *testing.T) {
	// 重载脚本经常以非零退出，不该让整条流水线失败。
	fake := &fakeSession{Exit: map[string]int{"reload": 3}}
	p := buildPipeline(t, fake,
		step(StepRunCommand, map[string]any{"command": "reload"}),
		step(StepRunCommand, map[string]any{"command": "echo after"}),
	)
	events, err := p.Deploy(context.Background(), testCert())
	if err != nil {
		t.Fatalf("Deploy = %v, want a non-zero run_command to be non-fatal", err)
	}
	if !fake.ranContaining("echo after") {
		t.Error("the pipeline stopped after a non-zero run_command")
	}
	if !hasEvent(events, StepRunCommand, "non-fatal") {
		t.Errorf("events = %v, want the non-fatal exit recorded", eventSummary(events))
	}
}

func TestTestCommandNonZeroAborts(t *testing.T) {
	// test_command 与 run_command 执行相同、策略相反。
	fake := &fakeSession{Exit: map[string]int{"nginx -t": 1}}
	p := buildPipeline(t, fake,
		step(StepTestCommand, map[string]any{"command": "nginx -t"}),
		step(StepRunCommand, map[string]any{"command": "echo unreachable"}),
	)
	if _, err := p.Deploy(context.Background(), testCert()); err == nil {
		t.Fatal("Deploy = nil error, want a failing test_command to abort")
	}
	if fake.ranContaining("echo unreachable") {
		t.Error("the pipeline continued past a failing test_command")
	}
}

func TestBackupFileNeverFatal(t *testing.T) {
	fake := &fakeSession{Exit: map[string]int{"test -f": 1}}
	p := buildPipeline(t, fake, step(StepBackupFile, map[string]any{
		"path": "/etc/ssl/c.pem", "suffix": ".old",
	}))
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Errorf("Deploy = %v, want backup_file to never be fatal", err)
	}
	if !fake.ranContaining("'/etc/ssl/c.pem.old'") {
		t.Errorf("commands = %v, want the suffix applied", fake.Commands)
	}
}

func TestConditionBranches(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		exit       int
		output     string
		match      string
		wantBranch string
	}{
		{"exit_code 成立走 then", "exit_code", 0, "", "", "then-ran"},
		{"exit_code 不成立走 else", "exit_code", 1, "", "", "else-ran"},
		{"output_contains 命中走 then", "output_contains", 1, "nginx/1.25", "nginx", "then-ran"},
		{"output_contains 未命中走 else", "output_contains", 0, "apache", "nginx", "else-ran"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeSession{
				Exit:   map[string]int{"probe": tt.exit},
				Output: map[string]string{"probe": tt.output},
			}
			p := buildPipeline(t, fake, step(StepCondition, map[string]any{
				"mode": tt.mode, "command": "probe", "match_string": tt.match,
				"then_steps": []map[string]any{step(StepRunCommand, map[string]any{"command": "then-ran"})},
				"else_steps": []map[string]any{step(StepRunCommand, map[string]any{"command": "else-ran"})},
			}))
			if _, err := p.Deploy(context.Background(), testCert()); err != nil {
				t.Fatal(err)
			}
			if !fake.ranContaining(tt.wantBranch) {
				t.Errorf("commands = %v, want %q to have run", fake.Commands, tt.wantBranch)
			}
		})
	}
}

func TestConditionWithoutBranchIsFine(t *testing.T) {
	fake := &fakeSession{}
	p := buildPipeline(t, fake, step(StepCondition, map[string]any{"command": "probe"}))
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Errorf("Deploy = %v, want a branchless condition to succeed", err)
	}
}

func TestConditionDepthIsBounded(t *testing.T) {
	// Rust 版对嵌套没有上限，自引用的配置会一直递归到爆栈。
	inner := step(StepRunCommand, map[string]any{"command": "deepest"})
	for i := 0; i < 12; i++ {
		inner = step(StepCondition, map[string]any{
			"command": "probe", "then_steps": []map[string]any{inner},
		})
	}
	fake := &fakeSession{}
	p := buildPipeline(t, fake, inner)
	if _, err := p.Deploy(context.Background(), testCert()); err == nil {
		t.Error("Deploy = nil error, want nesting beyond the depth limit to fail")
	}
	if fake.ranContaining("deepest") {
		t.Error("recursion reached the innermost step despite the depth limit")
	}
}

func TestDockerSteps(t *testing.T) {
	fake := &fakeSession{}
	p := buildPipeline(t, fake,
		step(StepDockerExec, map[string]any{"container": "web", "command": "nginx -s reload"}),
		step(StepDockerRestart, map[string]any{"container": "web"}),
		step(StepDockerRestart, map[string]any{
			"container": "api", "method": "compose_restart",
			"compose_file": "/srv/app/docker-compose.yml",
		}),
	)
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"docker exec 'web' nginx -s reload",
		"docker restart 'web'",
		"cd '/srv/app' && docker compose -f 'docker-compose.yml' restart 'api'",
	} {
		if !fake.ranContaining(want) {
			t.Errorf("commands = %v, want one containing %q", fake.Commands, want)
		}
	}
}

func TestDockerStepsNeverFatal(t *testing.T) {
	fake := &fakeSession{Exit: map[string]int{"docker": 1}}
	p := buildPipeline(t, fake,
		step(StepDockerRestart, map[string]any{"container": "web"}),
		step(StepRunCommand, map[string]any{"command": "echo after"}),
	)
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Errorf("Deploy = %v, want docker steps to be non-fatal", err)
	}
	if !fake.ranContaining("echo after") {
		t.Error("the pipeline stopped after a failing docker step")
	}
}

func TestUnknownStepIsSkipped(t *testing.T) {
	fake := &fakeSession{}
	p := buildPipeline(t, fake,
		step("some_future_step", map[string]any{}),
		step(StepRunCommand, map[string]any{"command": "echo after"}),
	)
	events, err := p.Deploy(context.Background(), testCert())
	if err != nil {
		t.Fatalf("Deploy = %v, want an unknown step to be skipped", err)
	}
	if !fake.ranContaining("echo after") {
		t.Error("the pipeline stopped at an unknown step")
	}
	if !hasEvent(events, "unknown", "skipping") {
		t.Errorf("events = %v, want the skip recorded", eventSummary(events))
	}
}

func TestEnsureDirRunsMkdir(t *testing.T) {
	fake := &fakeSession{}
	p := buildPipeline(t, fake, step(StepUploadFile, map[string]any{
		"source": "certificate", "dest_path": "/etc/ssl/certs/site/c.pem", "ensure_dir": true,
	}))
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Fatal(err)
	}
	if !fake.ranContaining("mkdir -p '/etc/ssl/certs/site'") {
		t.Errorf("commands = %v, want a mkdir -p for the parent", fake.Commands)
	}
}

func TestConnectFailureAbortsWithEvents(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"steps": []map[string]any{
		{"type": StepSSHConnect, "name": "c", "config": map[string]any{
			"host": "h", "username": "u", "auth_type": "password"}},
	}})
	target, err := newPipeline(string(raw), Options{})
	if err != nil {
		t.Fatal(err)
	}
	ssht := target.(*sshTarget)
	ssht.dial = func(context.Context, connectConfig) (session, error) {
		return nil, fmt.Errorf("connection refused")
	}

	events, err := ssht.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("Deploy = nil error, want the connect failure surfaced")
	}
	// 失败也必须带回事件——这正是操作者要看的部分。
	if !hasEvent(events, StepSSHConnect, "connection refused") {
		t.Errorf("events = %v, want the failure recorded", eventSummary(events))
	}
}

func TestSessionIsClosed(t *testing.T) {
	fake := &fakeSession{}
	p := buildPipeline(t, fake, step(StepRunCommand, map[string]any{"command": "x"}))
	if _, err := p.Deploy(context.Background(), testCert()); err != nil {
		t.Fatal(err)
	}
	if !fake.closed {
		t.Error("the SSH session was not closed")
	}
}

func TestConnectConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]any
		wantErr bool
	}{
		{"密码认证", map[string]any{"auth_type": "password", "password": "p"}, false},
		{"私钥认证", map[string]any{"auth_type": "private_key", "private_key": "K"}, false},
		{"私钥为空", map[string]any{"auth_type": "private_key"}, true},
		{"未知认证方式", map[string]any{"auth_type": "kerberos"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := json.Marshal(tt.config)
			_, err := parseConnect(raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConnect = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestShellQuoteEscapes(t *testing.T) {
	// 路径里的单引号不能把命令截断。
	got := shellQuote(`/tmp/it's here`)
	if strings.Contains(got, `it's here'`) && !strings.Contains(got, `'\''`) {
		t.Errorf("shellQuote(%q) = %q, want the embedded quote escaped", `/tmp/it's here`, got)
	}
}

func hasEvent(events []Event, eventType, substr string) bool {
	for _, e := range events {
		if e.Type == eventType && (strings.Contains(e.Message, substr) || strings.Contains(e.Detail, substr)) {
			return true
		}
	}
	return false
}

func eventSummary(events []Event) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Type+"/"+e.Level+": "+e.Message)
	}
	return out
}
