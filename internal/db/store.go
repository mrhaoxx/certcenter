// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a lookup by key or id finds no row.
var ErrNotFound = errors.New("not found")

// Setting keys.
const (
	// SettingAdminPasswordHash holds the live bcrypt hash. config's
	// auth.password_hash only seeds it on first boot, so changing the
	// password no longer means rewriting config.toml.
	SettingAdminPasswordHash = "admin_password_hash"
)

// Pagination bounds for ListLogs.
const (
	DefaultLogLimit = 100
	MaxLogLimit     = 500
)

// OperationLog is one audit entry. JSON tags are the API shape.
type OperationLog struct {
	ID           int64   `json:"id"`
	Action       string  `json:"action"`
	ResourceType string  `json:"resourceType"`
	ResourceID   *int64  `json:"resourceId"`
	Detail       *string `json:"detail"`
	Operator     string  `json:"operator"`
	CreatedAt    string  `json:"createdAt"`
}

// ACMEAccount is a registered account at a CA. JSON tags are the API shape.
type ACMEAccount struct {
	ID           int64   `json:"id"`
	Name         string  `json:"name"`
	DirectoryURL string  `json:"directoryUrl"`
	Email        string  `json:"email"`
	AccountURL   *string `json:"accountUrl"`
	// PrivateKeyPEM is the account key (PKCS#8 PEM). It is the credential
	// that authenticates us to the CA, so it never leaves the process:
	// json:"-" keeps it out of every API response.
	PrivateKeyPEM string `json:"-"`
	ValidityDays  int64  `json:"validityDays"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

// ACMEAccountUpdate is a sparse patch: nil fields are left unchanged.
// DirectoryURL and the private key are immutable — changing either would
// silently point the account at a different CA identity.
type ACMEAccountUpdate struct {
	Name         *string
	Email        *string
	ValidityDays *int64
}

// Certificate is one managed certificate. JSON tags are the API shape.
type Certificate struct {
	ID            int64    `json:"id"`
	Domain        string   `json:"domain"`
	SANs          []string `json:"sans"`
	ACMEAccountID int64    `json:"acmeAccountId"`
	DNSProviderID int64    `json:"dnsProviderId"`

	// CertPEM holds the leaf alone and ChainPEM the intermediates alone.
	// The Rust implementation wrote the full chain into both, so the UI
	// rendered the leaf twice and the config-center deploy pushed the chain
	// duplicated.
	CertPEM  *string `json:"certPem"`
	ChainPEM *string `json:"chainPem"`
	// KeyPEM never leaves the process except through the bundle endpoint.
	KeyPEM string `json:"-"`

	Serial     *string `json:"serial"`
	NotBefore  *string `json:"notBefore"`
	NotAfter   *string `json:"notAfter"`
	RenewAfter *string `json:"renewAfter"`

	// ValidityDays is a legacy hint only. A CA issues whatever lifetime it
	// chooses; use Profile to actually influence it where the CA supports
	// ACME profiles.
	ValidityDays int64 `json:"validityDays"`
	// Profile is the ACME profile requested at order time (Let's Encrypt
	// offers "classic", "tlsserver", "shortlived"). Empty uses the CA's
	// default.
	Profile string `json:"profile"`
	Status  string `json:"status"` // pending|issued|error|expired|revoked
	// RevokedAt and RevocationReason record a revocation rather than
	// deleting the row, so the history stays readable.
	RevokedAt        *string `json:"revokedAt"`
	RevocationReason string  `json:"revocationReason"`
	// CSRPEM is a caller-supplied certificate request. When set, issuance
	// signs it rather than generating a key, and KeyPEM stays empty.
	CSRPEM    string  `json:"csrPem"`
	LastError *string `json:"lastError"`
	AutoRenew bool    `json:"autoRenew"`
	// SkipDNSCheck bypasses the propagation check before handing the
	// challenge to the CA, for a zone our resolver cannot see.
	SkipDNSCheck bool `json:"skipDnsCheck"`
	// SkipDNSWaitSeconds overrides how long the skip waits. Nil inherits
	// the global setting; zero deliberately waits not at all.
	SkipDNSWaitSeconds *int64 `json:"skipDnsWaitSeconds"`
	// RotateKey generates a fresh private key on every renewal instead of
	// keeping the existing one.
	RotateKey bool `json:"rotateKey"`
	// KeyType is the certificate key algorithm: ec-256 (the default),
	// ec-384, ec-521, rsa-2048, rsa-3072, rsa-4096. Empty means ec-256.
	KeyType string `json:"keyType"`
	// PreferredChain picks among the chains a CA offers by issuer Common
	// Name; empty takes the first.
	PreferredChain string `json:"preferredChain"`
	// NotBeforeDays requests a start date this many days out. Zero asks
	// for nothing.
	NotBeforeDays int64 `json:"notBeforeDays"`
	// ExtendedKeyUsage overrides the CSR's EKU. Most public CAs ignore it.
	ExtendedKeyUsage string `json:"extendedKeyUsage"`
	// RenewBeforeDays renews once fewer than this many days remain,
	// overriding ARI and the lifetime fraction. Zero keeps them.
	RenewBeforeDays int64   `json:"renewBeforeDays"`
	RetryCount      int64   `json:"retryCount"`
	RetryAfter      *string `json:"retryAfter"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// CertificateFilter narrows a list query. Search matches the domain or any
// SAN; Status matches exactly. Empty fields are ignored.
type CertificateFilter struct {
	Search string
	Status string
}

// IssuedCertificate is what a successful issuance produces. The dates come
// from parsing the leaf, never from arithmetic on ValidityDays.
type IssuedCertificate struct {
	CertPEM   string
	ChainPEM  string
	KeyPEM    string
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	// RenewAfter is the ARI-selected renewal instant, nil when the CA does
	// not support ARI.
	RenewAfter *time.Time
}

// CertificateSettings is a sparse update: a nil field is left alone.
type CertificateSettings struct {
	// ACMEAccountID moves the certificate to another CA at its next
	// issuance. The certificate already in hand is unaffected — it was
	// signed by whoever signed it.
	ACMEAccountID    *int64
	AutoRenew        *bool
	ValidityDays     *int64
	Profile          *string
	SkipDNSCheck     *bool
	RotateKey        *bool
	KeyType          *string
	PreferredChain   *string
	NotBeforeDays    *int64
	ExtendedKeyUsage *string
	RenewBeforeDays  *int64
	// SkipDNSWaitSeconds is a double pointer so "not mentioned" and
	// "explicitly inherit the global wait" stay distinguishable.
	SkipDNSWaitSeconds **int64
}

// DNSProvider is a stored DNS credential set.
type DNSProvider struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Config    string `json:"config"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// DeployTarget is somewhere a certificate gets installed.
type DeployTarget struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Config    string `json:"config"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// Deployment binds a certificate to a target and carries the last outcome.
type Deployment struct {
	ID             int64   `json:"id"`
	CertificateID  int64   `json:"certificateId"`
	DeployTargetID int64   `json:"deployTargetId"`
	TargetName     string  `json:"targetName"`
	TargetKind     string  `json:"targetKind"`
	Status         string  `json:"status"` // pending|success|failed
	LastDeployedAt *string `json:"lastDeployedAt"`
	LastError      *string `json:"lastError"`
}

// NamedUpdate is a sparse patch for the name/config of a provider or target.
type NamedUpdate struct {
	Name   *string
	Config *string
}

// Run kinds, statuses, and event levels. These strings reach the API and
// the UI, so they are a contract.
const (
	RunKindIssue  = "issue"
	RunKindDeploy = "deploy"

	RunStatusRunning = "running"
	RunStatusSuccess = "success"
	RunStatusError   = "error"

	LevelInfo    = "info"
	LevelSuccess = "success"
	LevelError   = "error"
)

// Run is one issuance or one deployment attempt.
type Run struct {
	ID            int64   `json:"id"`
	Kind          string  `json:"kind"`
	CertificateID int64   `json:"certificateId"`
	DeploymentID  *int64  `json:"deploymentId"`
	Attempt       int64   `json:"attempt"`
	Trigger       string  `json:"trigger"` // manual|auto|api|bus
	Status        string  `json:"status"`
	Error         *string `json:"error"`
	StartedAt     string  `json:"startedAt"`
	FinishedAt    *string `json:"finishedAt"`
}

// Event is one entry of a run's timeline. Seq is assigned by AppendEvent so
// the UI can order entries that share a timestamp.
type Event struct {
	ID      int64   `json:"id"`
	RunID   int64   `json:"runId"`
	Seq     int64   `json:"seq"`
	Type    string  `json:"type"`
	Message string  `json:"message"`
	Detail  *string `json:"detail"`
	Level   string  `json:"level"`
	At      string  `json:"at"`
}

// Store is the persistence boundary. Later milestones extend it with the
// provider and deploy-target methods.
type Store interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error

	GetDNSSettings(ctx context.Context, fallback DNSSettings) (DNSSettings, error)
	PutDNSSettings(ctx context.Context, v DNSSettings) error

	AppendLog(ctx context.Context, l OperationLog) error
	ListLogs(ctx context.Context, limit, offset int) ([]OperationLog, error)

	CreateACMEAccount(ctx context.Context, a ACMEAccount) (int64, error)
	GetACMEAccount(ctx context.Context, id int64) (*ACMEAccount, error)
	ListACMEAccounts(ctx context.Context) ([]ACMEAccount, error)
	UpdateACMEAccount(ctx context.Context, id int64, p ACMEAccountUpdate) error
	DeleteACMEAccount(ctx context.Context, id int64) error

	CreateCertificate(ctx context.Context, c Certificate) (int64, error)
	GetCertificate(ctx context.Context, id int64) (*Certificate, error)
	ListCertificates(ctx context.Context, f CertificateFilter) ([]Certificate, error)
	UpdateCertificateStatus(ctx context.Context, id int64, status, lastErr string) error
	SaveIssuedCertificate(ctx context.Context, id int64, issued IssuedCertificate) error
	DueForRenewal(ctx context.Context, now time.Time) ([]Certificate, error)
	RecordRenewalFailure(ctx context.Context, id int64, now time.Time) error
	UpdateCertificateSettings(ctx context.Context, id int64, u CertificateSettings) error
	DeleteCertificate(ctx context.Context, id int64) error

	CreateDNSProvider(ctx context.Context, p DNSProvider) (int64, error)
	GetDNSProvider(ctx context.Context, id int64) (*DNSProvider, error)
	ListDNSProviders(ctx context.Context) ([]DNSProvider, error)
	UpdateDNSProvider(ctx context.Context, id int64, u NamedUpdate) error
	DeleteDNSProvider(ctx context.Context, id int64) error
	CountCertificatesUsingDNSProvider(ctx context.Context, id int64) (int, error)

	CreateDeployTarget(ctx context.Context, t DeployTarget) (int64, error)
	GetDeployTarget(ctx context.Context, id int64) (*DeployTarget, error)
	ListDeployTargets(ctx context.Context) ([]DeployTarget, error)
	UpdateDeployTarget(ctx context.Context, id int64, u NamedUpdate) error
	DeleteDeployTarget(ctx context.Context, id int64) error
	CountDeploymentsUsingTarget(ctx context.Context, id int64) (int, error)

	SetCertificateDeployTargets(ctx context.Context, certID int64, targetIDs []int64) error
	ListDeployments(ctx context.Context, certID int64) ([]Deployment, error)
	UpdateDeploymentResult(ctx context.Context, deploymentID int64, status, lastErr string) error
	CountCertificatesUsingACMEAccount(ctx context.Context, id int64) (int, error)

	StartRun(ctx context.Context, kind string, certID int64, deploymentID *int64, trigger string) (*Run, error)
	FinishRun(ctx context.Context, runID int64, status, errMsg string) error
	AppendEvent(ctx context.Context, runID int64, e Event) error
	ListRuns(ctx context.Context, certID int64) ([]Run, error)
	ListRunEvents(ctx context.Context, runID int64) ([]Event, error)

	ListCertificateDNSProviders(ctx context.Context, certID int64) ([]DNSProvider, error)
	SetCertificateDNSProviders(ctx context.Context, certID int64, providerIDs []int64) error

	ReapOrphanedRuns(ctx context.Context) (int, error)

	MarkRevoked(ctx context.Context, id int64, reason string) error

	Close() error
}
