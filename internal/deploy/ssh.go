// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// The SSH target runs a pipeline of steps over one session. Step type
// strings and their config keys are a data contract: existing deploy
// targets are stored with exactly these names.
const (
	StepSSHConnect    = "ssh_connect"
	StepLocalWrite    = "local_write"
	StepWebhook       = "webhook"
	StepConfigCenter  = "configcenter_put"
	StepAliyunCDN     = "aliyun_cdn"
	StepTencentCDN    = "tencent_cdn"
	StepK8sSecret     = "k8s_secret"
	StepK8sRestart    = "k8s_restart"
	StepUploadFile    = "upload_file"
	StepRunCommand    = "run_command"
	StepTestCommand   = "test_command"
	StepBackupFile    = "backup_file"
	StepWriteContent  = "write_content"
	StepCondition     = "condition"
	StepVerifySSL     = "verify_ssl"
	StepSleep         = "sleep"
	StepHTTPRequest   = "http_request"
	StepDockerExec    = "docker_exec"
	StepDockerRestart = "docker_restart"
)

// maxConditionDepth bounds condition nesting. The Rust implementation had
// no limit, so a config that nested a condition inside itself would recurse
// until the stack blew.
const maxConditionDepth = 8

// heredocMarker delimits shell-written file content.
const heredocMarker = "CERTCENTER_EOF"

// PipelineStep is one entry of the pipeline.
type PipelineStep struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

// sshConfig is the pipeline form of the target config.
type sshConfig struct {
	Steps []PipelineStep `json:"steps"`
}

// legacySSHConfig is the pre-pipeline flat form, kept working because
// stored targets may still use it.
type legacySSHConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	PrivateKey    string `json:"private_key"`
	Password      string `json:"password"`
	CertPath      string `json:"cert_path"`
	KeyPath       string `json:"key_path"`
	ReloadCommand string `json:"reload_command"`
}

// session is the command channel a pipeline runs over. Abstracting it keeps
// every step testable without standing up an SSH server.
type session interface {
	// Run executes a command, returning its exit status and the combined
	// output. A non-zero exit is not an error; only transport failures are.
	Run(ctx context.Context, cmd string) (int, string, error)
	// Upload writes content to dest with the given octal mode.
	Upload(ctx context.Context, dest string, content []byte, mode string) error
	Close() error
}

// dialer opens a session; swapped in tests.
type dialer func(ctx context.Context, cfg connectConfig) (session, error)

type sshTarget struct {
	opts  Options
	steps []PipelineStep
	dial  dialer
}

func newPipeline(configJSON string, opts Options) (Target, error) {
	steps, err := parseSSHSteps(configJSON)
	if err != nil {
		return nil, err
	}
	return &sshTarget{steps: steps, dial: dialSSH, opts: opts}, nil
}

// parseSSHSteps accepts either the pipeline form or the legacy flat form.
func parseSSHSteps(configJSON string) ([]PipelineStep, error) {
	// Probe which shape this is before decoding strictly.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &probe); err != nil {
		return nil, fmt.Errorf("parse ssh config: %w", err)
	}
	if _, ok := probe["steps"]; ok {
		var cfg sshConfig
		if err := decodeConfig(configJSON, &cfg); err != nil {
			return nil, err
		}
		if len(cfg.Steps) == 0 {
			return nil, fmt.Errorf("the pipeline has no steps")
		}
		// ssh_connect is no longer required to lead. A pipeline may never
		// touch SSH at all — writing a file locally, pushing to the config
		// center and poking a reload endpoint needs no shell. The steps
		// that do need a session say so when there is none.
		return cfg.Steps, nil
	}
	if _, ok := probe["host"]; ok {
		var legacy legacySSHConfig
		if err := decodeConfig(configJSON, &legacy); err != nil {
			return nil, err
		}
		return desugarLegacy(legacy)
	}
	return nil, fmt.Errorf("ssh config has neither 'steps' nor 'host'")
}

func desugarLegacy(l legacySSHConfig) ([]PipelineStep, error) {
	authType := "password"
	if l.PrivateKey != "" {
		authType = "private_key"
	}
	port := l.Port
	if port == 0 {
		port = 22
	}
	mk := func(stepType, name string, cfg map[string]any) PipelineStep {
		raw, _ := json.Marshal(cfg)
		return PipelineStep{Type: stepType, Name: name, Config: raw}
	}
	steps := []PipelineStep{
		mk(StepSSHConnect, "connect", map[string]any{
			"host": l.Host, "port": port, "username": l.Username,
			"auth_type": authType, "private_key": l.PrivateKey, "password": l.Password,
		}),
		mk(StepUploadFile, "upload certificate", map[string]any{
			"source": "certificate", "method": "scp", "dest_path": l.CertPath, "mode": "0644",
		}),
		mk(StepUploadFile, "upload key", map[string]any{
			"source": "private_key", "method": "scp", "dest_path": l.KeyPath, "mode": "0600",
		}),
	}
	if l.ReloadCommand != "" {
		steps = append(steps, mk(StepRunCommand, "reload", map[string]any{
			"command": l.ReloadCommand,
		}))
	}
	return steps, nil
}

// pipelineState carries what the steps share: the session, the certificate,
// and the paths registered by upload_file for template expansion.
type pipelineState struct {
	// opts carries what the application injects rather than the operator
	// configuring: the config center's URL, for instance.
	opts Options
	// sessions holds every open SSH connection by id. A pipeline can reach
	// more than one host — the same certificate on web1 and web2 — so a
	// single session would have meant one target per machine and no way to
	// order the work between them.
	sessions map[string]session
	// current is the id of the most recent ssh_connect, used by steps that
	// do not name one.
	current string
	cert    *CertificateData
	paths   map[string]string
	events  []Event
}

func (p *pipelineState) emit(e Event) { p.events = append(p.events, e) }

// requireSession resolves the connection a step runs over.
//
// A pipeline can legitimately have no shell at all, so this is a
// step-level precondition rather than something checked when the config is
// parsed. "on" names a connection opened earlier; empty means the most
// recent one, which is what a single-host pipeline wants without saying so.
func (p *pipelineState) requireSession(stepType, on string) (session, error) {
	if len(p.sessions) == 0 {
		return nil, fmt.Errorf("step %q needs an SSH session; add an %s step before it",
			stepType, StepSSHConnect)
	}
	id := on
	if id == "" {
		id = p.current
	}
	sess, ok := p.sessions[id]
	if !ok {
		return nil, fmt.Errorf("step %q names connection %q, which no %s step opened; open ones are %v",
			stepType, id, StepSSHConnect, p.sessionIDs())
	}
	return sess, nil
}

func (p *pipelineState) sessionIDs() []string {
	ids := make([]string, 0, len(p.sessions))
	for id := range p.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// expand substitutes the template placeholders. These names are a data
// contract — note {{certificate}} and {{private_key}}, not {{cert}}/{{key}}.
func (p *pipelineState) expand(s string) string {
	r := strings.NewReplacer(
		"{{domain}}", p.cert.Domain,
		"{{certificate}}", p.cert.CertPEM,
		"{{private_key}}", p.cert.KeyPEM,
		"{{chain}}", p.cert.ChainPEM,
		"{{fullchain}}", p.cert.FullChainPEM(),
		"{{cert_path}}", p.paths["cert_path"],
		"{{key_path}}", p.paths["key_path"],
		"{{chain_path}}", p.paths["chain_path"],
	)
	return r.Replace(s)
}

func (t *sshTarget) Deploy(ctx context.Context, cert *CertificateData) ([]Event, error) {
	state := &pipelineState{cert: cert, paths: map[string]string{},
		opts: t.opts, sessions: map[string]session{}}
	// Closed here rather than by the step that opened it: the session has
	// to outlive ssh_connect and live until the pipeline ends.
	defer func() {
		for _, sess := range state.sessions {
			sess.Close()
		}
	}()

	total := len(t.steps)
	for i, step := range t.steps {
		state.emit(Event{Type: step.Type, Level: LevelInfo,
			Message: fmt.Sprintf("[Step %d/%d] %s", i+1, total, step.Name)})

		if err := t.execute(ctx, state, step, 0); err != nil {
			state.emit(Event{Type: step.Type, Level: LevelError,
				Message: fmt.Sprintf("Step %q failed: %v", step.Name, err)})
			return state.events, fmt.Errorf("step %d %q failed: %w", i+1, step.Name, err)
		}
	}

	state.emit(Event{Type: "complete", Level: LevelSuccess,
		Message: fmt.Sprintf("Pipeline completed — %d steps executed", total)})
	return state.events, nil
}

// stepSSHConnect opens the session later steps run over. It is an ordinary
// step now: a pipeline that writes a file locally and calls a reload
// endpoint has no reason to open a shell, and requiring one meant every
// target carried SSH credentials whether or not it used them.
// sessionTarget reads the optional "on" field naming which connection a
// step runs over. A malformed config is left for the step's own decoding
// to report.
func sessionTarget(raw json.RawMessage) string {
	var probe struct {
		On string `json:"on"`
	}
	_ = json.Unmarshal(raw, &probe)
	return probe.On
}

func (t *sshTarget) stepSSHConnect(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	cfg, err := parseConnect(raw)
	if err != nil {
		return err
	}
	// Connections are named so later steps can pick one. Without an
	// explicit id the host stands in, which reads well in the timeline and
	// is unique in the common case.
	id := cfg.ID
	if id == "" {
		id = cfg.Host
	}
	if _, taken := st.sessions[id]; taken {
		return fmt.Errorf("connection %q is already open; give this %s a distinct id", id, StepSSHConnect)
	}
	st.emit(Event{Type: StepSSHConnect, Level: LevelInfo,
		Message: fmt.Sprintf("Connecting to %s@%s:%d", cfg.Username, cfg.Host, cfg.Port),
		Detail:  fmt.Sprintf("auth_type=%s; connection id: %s", cfg.AuthType, id)})

	sess, err := t.dial(ctx, cfg)
	if err != nil {
		return err
	}
	st.sessions[id] = sess
	st.current = id
	st.emit(Event{Type: StepSSHConnect, Level: LevelSuccess,
		Message: fmt.Sprintf("Connected to %s@%s:%d", cfg.Username, cfg.Host, cfg.Port),
		Detail:  fmt.Sprintf("Connection id: %s", id)})
	return nil
}

// execute dispatches one step. Returning an error aborts the pipeline; the
// non-fatal steps swallow their own failures and return nil.
func (t *sshTarget) execute(ctx context.Context, st *pipelineState, step PipelineStep, depth int) error {
	switch step.Type {
	case StepSSHConnect:
		return t.stepSSHConnect(ctx, st, step.Config)
	case StepUploadFile:
		return stepUploadFile(ctx, st, step.Config)
	case StepRunCommand:
		return stepRunCommand(ctx, st, step.Config)
	case StepTestCommand:
		return stepTestCommand(ctx, st, step.Config)
	case StepBackupFile:
		return stepBackupFile(ctx, st, step.Config)
	case StepWriteContent:
		return stepWriteContent(ctx, st, step.Config)
	case StepCondition:
		return t.stepCondition(ctx, st, step.Config, depth)
	case StepSleep:
		return stepSleep(ctx, st, step.Config)
	case StepHTTPRequest:
		return stepHTTPRequest(ctx, st, step.Config)
	case StepVerifySSL:
		return stepVerifySSL(ctx, st, step.Config)
	case StepDockerExec:
		return stepDockerExec(ctx, st, step.Config)
	case StepDockerRestart:
		return stepDockerRestart(ctx, st, step.Config)
	case StepLocalWrite:
		return stepLocalWrite(ctx, st, step.Config)
	case StepWebhook:
		return stepWebhook(ctx, st, step.Config)
	case StepConfigCenter:
		return stepConfigCenter(ctx, st, step.Config)
	case StepAliyunCDN:
		return stepAliyunCDN(ctx, st, step.Config)
	case StepTencentCDN:
		return stepTencentCDN(ctx, st, step.Config)
	case StepK8sSecret:
		return stepK8sSecret(ctx, st, step.Config)
	case StepK8sRestart:
		return stepK8sRestart(ctx, st, step.Config)
	default:
		// Unknown types are skipped, not fatal, so the UI can introduce a
		// step type before the backend understands it.
		st.emit(Event{Type: "unknown", Level: LevelInfo,
			Message: fmt.Sprintf("Unknown step type %q, skipping", step.Type)})
		return nil
	}
}

// ── ssh_connect ────────────────────────────────────────────────────────

type connectConfig struct {
	// ID names this connection so later steps can pick it. Empty falls
	// back to the host, which is unique whenever a pipeline reaches each
	// machine once.
	ID          string `json:"id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	AuthType    string `json:"auth_type"`
	PrivateKey  string `json:"private_key"`
	Passphrase  string `json:"passphrase"`
	Password    string `json:"password"`
	TimeoutSecs int    `json:"timeout_secs"`
	// KnownHostKey is an optional authorized_keys-format host key. Empty
	// keeps the Rust behaviour of not verifying, which is why it must be
	// opt-in rather than silently absent.
	KnownHostKey string `json:"known_host_key"`
}

func parseConnect(raw json.RawMessage) (connectConfig, error) {
	cfg := connectConfig{Host: "127.0.0.1", Port: 22, Username: "root", AuthType: "private_key"}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, err
		}
	}
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Username == "" {
		cfg.Username = "root"
	}
	if cfg.AuthType == "" {
		cfg.AuthType = "private_key"
	}
	switch cfg.AuthType {
	case "private_key":
		if cfg.PrivateKey == "" {
			return cfg, fmt.Errorf("auth_type=private_key but private_key is empty")
		}
	case "password":
	default:
		return cfg, fmt.Errorf("unknown auth_type %q", cfg.AuthType)
	}
	return cfg, nil
}

// dialSSH opens a real SSH session.
func dialSSH(ctx context.Context, cfg connectConfig) (session, error) {
	var auth []ssh.AuthMethod
	switch cfg.AuthType {
	case "private_key":
		var signer ssh.Signer
		var err error
		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(
				[]byte(cfg.PrivateKey), []byte(cfg.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	case "password":
		auth = append(auth, ssh.Password(cfg.Password))
	}

	hostKey := ssh.InsecureIgnoreHostKey()
	if cfg.KnownHostKey != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.KnownHostKey))
		if err != nil {
			return nil, fmt.Errorf("parse known_host_key: %w", err)
		}
		hostKey = ssh.FixedHostKey(pub)
	}

	timeout := time.Duration(cfg.TimeoutSecs) * time.Second
	if timeout <= 0 {
		// The Rust implementation relied on the OS default, so a black-holed
		// host could hang a deployment for minutes.
		timeout = 30 * time.Second
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         timeout,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return &sshSession{client: ssh.NewClient(clientConn, chans, reqs)}, nil
}

type sshSession struct{ client *ssh.Client }

func (s *sshSession) Run(ctx context.Context, cmd string) (int, string, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return 0, "", err
	}
	defer sess.Close()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			sess.Signal(ssh.SIGKILL)
		case <-done:
		}
	}()
	out, err := sess.CombinedOutput(cmd)
	close(done)

	if exitErr, ok := err.(*ssh.ExitError); ok {
		return exitErr.ExitStatus(), string(out), nil
	}
	if err != nil {
		return 0, string(out), err
	}
	return 0, string(out), nil
}

// Upload writes via a heredoc rather than scp: it needs no extra binary on
// the far side and works identically through the session abstraction.
func (s *sshSession) Upload(ctx context.Context, dest string, content []byte, mode string) error {
	code, out, err := s.Run(ctx, heredocWrite(dest, string(content)))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("writing %s failed (exit %d): %s", dest, code, truncate(out, 500))
	}
	if mode != "" {
		// Best effort: a mode we cannot set is worth reporting but the file
		// is already in place.
		if code, out, err := s.Run(ctx, fmt.Sprintf("chmod %s %s", mode, shellQuote(dest))); err == nil && code != 0 {
			return fmt.Errorf("chmod %s %s failed: %s", mode, dest, truncate(out, 200))
		}
	}
	return nil
}

func (s *sshSession) Close() error { return s.client.Close() }

// heredocWrite builds a shell command writing content to dest. The marker is
// quoted so the shell performs no expansion on the payload — PEM data
// contains no shell metacharacters, but a rendered config might.
func heredocWrite(dest, content string) string {
	return fmt.Sprintf("cat <<'%s' > %s\n%s\n%s", heredocMarker, shellQuote(dest), content, heredocMarker)
}

// shellQuote makes a value safe as a single shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ── upload_file ────────────────────────────────────────────────────────

func stepUploadFile(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	sess, err := st.requireSession(StepUploadFile, sessionTarget(raw))
	if err != nil {
		return err
	}
	cfg := struct {
		Source    string `json:"source"`
		Method    string `json:"method"`
		DestPath  string `json:"dest_path"`
		Mode      string `json:"mode"`
		EnsureDir bool   `json:"ensure_dir"`
	}{Source: "certificate", Method: "scp", DestPath: "/tmp/cert.pem", Mode: "0644"}
	if err := json.Unmarshal(raw, &cfg); err != nil && len(raw) > 0 {
		return err
	}

	var content, pathKey string
	switch cfg.Source {
	case "certificate":
		content, pathKey = st.cert.CertPEM, "cert_path"
	case "private_key":
		content, pathKey = st.cert.KeyPEM, "key_path"
	case "chain":
		content, pathKey = st.cert.ChainPEM, "chain_path"
	case "fullchain":
		content, pathKey = st.cert.FullChainPEM(), "cert_path"
	default:
		return fmt.Errorf("unknown upload source %q", cfg.Source)
	}

	// Paths take placeholders like every other field. A per-domain layout
	// such as /etc/ssl/{{domain}}.crt is the ordinary case, and leaving
	// them unexpanded wrote a file with the braces still in its name.
	dest := st.expand(cfg.DestPath)

	if cfg.EnsureDir {
		if err := ensureParentDir(ctx, st, sess, dest); err != nil {
			return err
		}
	}

	st.emit(Event{Type: StepUploadFile, Level: LevelInfo,
		Message: fmt.Sprintf("Uploading %s to %s", cfg.Source, dest),
		Detail:  fmt.Sprintf("mode=%s, method=%s", cfg.Mode, cfg.Method)})

	if err := sess.Upload(ctx, dest, []byte(content), cfg.Mode); err != nil {
		return err
	}
	st.paths[pathKey] = dest
	st.emit(Event{Type: StepUploadFile, Level: LevelSuccess,
		Message: fmt.Sprintf("Uploaded %s to %s (%d bytes)", cfg.Source, dest, len(content))})
	return nil
}

func ensureParentDir(ctx context.Context, st *pipelineState, sess session, dest string) error {
	parent := path.Dir(dest)
	if parent == "" || parent == "/" || parent == "." {
		return nil
	}
	code, out, err := sess.Run(ctx, "mkdir -p "+shellQuote(parent))
	if err != nil {
		return err
	}
	if code != 0 {
		st.emit(Event{Type: "ensure_dir", Level: LevelError,
			Message: fmt.Sprintf("mkdir -p %s failed (exit %d)", parent, code),
			Detail:  truncate(out, 500)})
		return fmt.Errorf("mkdir -p %s failed (exit %d)", parent, code)
	}
	st.emit(Event{Type: "ensure_dir", Level: LevelInfo,
		Message: fmt.Sprintf("Ensured directory exists: %s", parent)})
	return nil
}

// ── run_command / test_command ─────────────────────────────────────────

type commandConfig struct {
	Command string `json:"command"`
}

func stepRunCommand(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	sess, err := st.requireSession(StepRunCommand, sessionTarget(raw))
	if err != nil {
		return err
	}
	var cfg commandConfig
	json.Unmarshal(raw, &cfg)
	cmd := st.expand(cfg.Command)

	code, out, err := sess.Run(ctx, cmd)
	if err != nil {
		return err
	}
	// A non-zero exit is informational: reload scripts routinely exit
	// non-zero for reasons that do not invalidate the deployment.
	if code != 0 {
		st.emit(Event{Type: StepRunCommand, Level: LevelInfo,
			Message: fmt.Sprintf("Command exited with code %d (non-fatal)", code),
			Detail:  truncate(strings.TrimSpace(out), 500)})
		return nil
	}
	st.emit(Event{Type: StepRunCommand, Level: LevelSuccess,
		Message: "Command completed (exit 0)", Detail: truncate(strings.TrimSpace(out), 500)})
	return nil
}

func stepTestCommand(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	sess, err := st.requireSession(StepTestCommand, sessionTarget(raw))
	if err != nil {
		return err
	}
	var cfg commandConfig
	json.Unmarshal(raw, &cfg)
	cmd := st.expand(cfg.Command)

	code, out, err := sess.Run(ctx, cmd)
	if err != nil {
		return err
	}
	if code != 0 {
		detail := truncate(strings.TrimSpace(out), 500)
		st.emit(Event{Type: StepTestCommand, Level: LevelError,
			Message: fmt.Sprintf("Test failed (exit %d) — aborting pipeline", code),
			Detail:  detail})
		return fmt.Errorf("test command %q failed (exit %d): %s", cmd, code, detail)
	}
	st.emit(Event{Type: StepTestCommand, Level: LevelSuccess, Message: "Test passed"})
	return nil
}

// ── backup_file ────────────────────────────────────────────────────────

func stepBackupFile(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	sess, err := st.requireSession(StepBackupFile, sessionTarget(raw))
	if err != nil {
		return err
	}
	cfg := struct {
		Path   string `json:"path"`
		Suffix string `json:"suffix"`
	}{Suffix: ".bak"}
	json.Unmarshal(raw, &cfg)
	if cfg.Suffix == "" {
		cfg.Suffix = ".bak"
	}

	// Paths take placeholders like every other field: a per-domain layout
	// such as /etc/ssl/{{domain}}.crt is the ordinary case, and leaving
	// them unexpanded wrote a file named with the braces still in it.
	path := st.expand(cfg.Path)
	q := shellQuote(path)
	cmd := fmt.Sprintf("test -f %s && cp %s %s || true", q, q, shellQuote(path+cfg.Suffix))
	code, out, err := sess.Run(ctx, cmd)
	if err != nil {
		return err
	}
	if code != 0 {
		st.emit(Event{Type: StepBackupFile, Level: LevelInfo,
			Message: "Backup warning", Detail: truncate(out, 500)})
		return nil
	}
	st.emit(Event{Type: StepBackupFile, Level: LevelSuccess, Message: "Backup completed"})
	return nil
}

// ── write_content ──────────────────────────────────────────────────────

func stepWriteContent(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	sess, err := st.requireSession(StepWriteContent, sessionTarget(raw))
	if err != nil {
		return err
	}
	cfg := struct {
		Content   string `json:"content"`
		DestPath  string `json:"dest_path"`
		Mode      string `json:"mode"`
		EnsureDir bool   `json:"ensure_dir"`
	}{DestPath: "/tmp/output", Mode: "0644"}
	json.Unmarshal(raw, &cfg)
	dest := st.expand(cfg.DestPath)

	if cfg.EnsureDir {
		if err := ensureParentDir(ctx, st, sess, dest); err != nil {
			return err
		}
	}
	content := st.expand(cfg.Content)
	if err := sess.Upload(ctx, dest, []byte(content), cfg.Mode); err != nil {
		st.emit(Event{Type: StepWriteContent, Level: LevelError,
			Message: fmt.Sprintf("Could not write %s", dest), Detail: err.Error()})
		return err
	}
	st.emit(Event{Type: StepWriteContent, Level: LevelSuccess,
		Message: fmt.Sprintf("Wrote content to %s", dest)})
	return nil
}

// ── condition ──────────────────────────────────────────────────────────

func (t *sshTarget) stepCondition(ctx context.Context, st *pipelineState, raw json.RawMessage, depth int) error {
	if depth >= maxConditionDepth {
		return fmt.Errorf("condition nesting exceeded %d levels", maxConditionDepth)
	}
	// A branch is a list. It used to be a single step, so "if nginx is
	// installed, upload the config, reload it and check the result" could
	// only be expressed by nesting conditions inside each other.
	cfg := struct {
		Mode        string         `json:"mode"`
		Command     string         `json:"command"`
		MatchString string         `json:"match_string"`
		ThenSteps   []PipelineStep `json:"then_steps"`
		ElseSteps   []PipelineStep `json:"else_steps"`
		On          string         `json:"on"`
	}{Mode: "exit_code"}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse condition: %w", err)
	}

	sess, err := st.requireSession(StepCondition, cfg.On)
	if err != nil {
		return err
	}
	code, out, err := sess.Run(ctx, st.expand(cfg.Command))
	if err != nil {
		return err
	}
	met := code == 0
	if cfg.Mode == "output_contains" {
		met = strings.Contains(out, cfg.MatchString)
	}

	branch, label := cfg.ElseSteps, "else_steps"
	if met {
		branch, label = cfg.ThenSteps, "then_steps"
	}
	st.emit(Event{Type: StepCondition, Level: LevelInfo,
		Message: fmt.Sprintf("Condition %s (exit=%d) → %s",
			map[bool]string{true: "met", false: "not met"}[met], code, label),
		Detail: truncate(strings.TrimSpace(out), 500)})

	for i, sub := range branch {
		st.emit(Event{Type: StepCondition, Level: LevelInfo,
			Message: fmt.Sprintf("  %s [%d/%d] %s", label, i+1, len(branch), sub.Name)})
		if err := t.execute(ctx, st, sub, depth+1); err != nil {
			return fmt.Errorf("%s step %d %q: %w", label, i+1, sub.Name, err)
		}
	}
	return nil
}

// ── sleep ──────────────────────────────────────────────────────────────

func stepSleep(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	cfg := struct {
		Seconds int `json:"seconds"`
	}{Seconds: 1}
	json.Unmarshal(raw, &cfg)
	if cfg.Seconds <= 0 {
		cfg.Seconds = 1
	}
	st.emit(Event{Type: StepSleep, Level: LevelInfo,
		Message: fmt.Sprintf("Waiting %ds", cfg.Seconds)})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(cfg.Seconds) * time.Second):
	}
	st.emit(Event{Type: StepSleep, Level: LevelSuccess,
		Message: fmt.Sprintf("Waited %ds", cfg.Seconds)})
	return nil
}

// ── docker_exec / docker_restart ───────────────────────────────────────

func stepDockerExec(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	sess, err := st.requireSession(StepDockerExec, sessionTarget(raw))
	if err != nil {
		return err
	}
	cfg := struct {
		Container string `json:"container"`
		Command   string `json:"command"`
	}{}
	json.Unmarshal(raw, &cfg)
	cmd := fmt.Sprintf("docker exec %s %s",
		shellQuote(st.expand(cfg.Container)), st.expand(cfg.Command))

	st.emit(Event{Type: StepDockerExec, Level: LevelInfo, Message: cmd})
	code, out, err := sess.Run(ctx, cmd)
	if err != nil {
		return err
	}
	level := LevelSuccess
	if code != 0 {
		level = LevelInfo // never fatal
	}
	st.emit(Event{Type: StepDockerExec, Level: level,
		Message: fmt.Sprintf("docker exec exited with code %d", code),
		Detail:  truncate(strings.TrimSpace(out), 500)})
	return nil
}

func stepDockerRestart(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	sess, err := st.requireSession(StepDockerRestart, sessionTarget(raw))
	if err != nil {
		return err
	}
	cfg := struct {
		Container   string `json:"container"`
		Method      string `json:"method"`
		ComposeFile string `json:"compose_file"`
	}{Method: "restart", ComposeFile: "docker-compose.yml"}
	json.Unmarshal(raw, &cfg)

	container := st.expand(cfg.Container)
	cmd := fmt.Sprintf("docker restart %s", shellQuote(container))
	if cfg.Method == "compose_restart" {
		dir := path.Dir(cfg.ComposeFile)
		if dir == "" {
			dir = "."
		}
		cmd = fmt.Sprintf("cd %s && docker compose -f %s restart %s",
			shellQuote(dir), shellQuote(path.Base(cfg.ComposeFile)), shellQuote(container))
	}

	st.emit(Event{Type: StepDockerRestart, Level: LevelInfo, Message: cmd})
	code, out, err := sess.Run(ctx, cmd)
	if err != nil {
		return err
	}
	level := LevelSuccess
	if code != 0 {
		level = LevelInfo // never fatal
	}
	st.emit(Event{Type: StepDockerRestart, Level: level,
		Message: fmt.Sprintf("Exited with code %d", code),
		Detail:  truncate(strings.TrimSpace(out), 500)})
	return nil
}
