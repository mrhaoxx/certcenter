// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mholt/acmez/v3/acme"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/dns"
)

// IssueTimeout bounds one issuance. The Rust implementation had no overall
// deadline, so a single stuck certificate stalled the whole renewal batch.
const IssueTimeout = 10 * time.Minute

// cleanupTimeout bounds the deferred TXT removal, which runs on its own
// context so it still happens after the issuance context is cancelled.
const cleanupTimeout = 30 * time.Second

// Issuer obtains certificates over DNS-01.
type Issuer struct {
	Store     db.Store
	Registrar *Registrar

	// OnProgress fires whenever the timeline gains an entry, so the UI can
	// follow a run instead of waiting minutes for it to end.
	OnProgress func()

	// ResolveTarget follows a CNAME from the challenge name to where the
	// TXT actually belongs. Nil uses the configured DoH resolver.
	ResolveTarget func(ctx context.Context, name string) (string, error)

	// DoH reports the current propagation-check settings. It is a function
	// rather than plain fields because the config center can replace the
	// configuration at runtime: captured values would leave a pushed change
	// to dns_verification silently ineffective until the next restart.
	//
	// Nil means "check propagation with the package defaults".
	DoH func() DoHSettings

	// HTTPClient overrides the ACME transport (tests point it at Pebble).
	HTTPClient *http.Client

	// NewProvider builds a DNS provider from a stored row; overridable so
	// tests can inject a fake.
	NewProvider func(kind, configJSON string) (dns.Provider, error)
}

func (is *Issuer) newProvider(kind, configJSON string) (dns.Provider, error) {
	if is.NewProvider != nil {
		return is.NewProvider(kind, configJSON)
	}
	return dns.New(kind, configJSON)
}

// Issue drives one full DNS-01 issuance for a certificate, recording every
// phase in the run's timeline.
func (is *Issuer) Issue(ctx context.Context, certID int64, trigger string) error {
	ctx, cancel := context.WithTimeout(ctx, IssueTimeout)
	defer cancel()

	cert, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		return err
	}

	run, err := is.Store.StartRun(ctx, db.RunKindIssue, certID, nil, trigger)
	if err != nil {
		return fmt.Errorf("start issuance run: %w", err)
	}
	rec := &recorder{store: is.Store, runID: run.ID, onEvent: is.OnProgress}

	if err := is.Store.UpdateCertificateStatus(ctx, certID, "pending", ""); err != nil {
		return err
	}

	if err := is.issue(ctx, rec, cert); err != nil {
		rec.failure(ctx, "failed", fmt.Sprintf("Issuance failed: %v", err), "")
		_ = is.Store.FinishRun(ctx, run.ID, db.RunStatusError, err.Error())
		_ = is.Store.UpdateCertificateStatus(ctx, certID, "error", err.Error())
		return err
	}
	return is.Store.FinishRun(ctx, run.ID, db.RunStatusSuccess, "")
}

// plantedRecord is a TXT record we created and must remove.
// plantedRecord remembers which provider wrote a challenge record, so
// cleanup returns to the same account rather than asking again — the
// answer could differ, or the lookup could fail after the run is over.
type plantedRecord struct {
	name, value string
	via         dns.Provider
}

// issue is the state machine. Each step emits events; the caller turns a
// returned error into the failure bookkeeping.
func (is *Issuer) issue(ctx context.Context, rec *recorder, cert *db.Certificate) error {
	domains := append([]string{cert.Domain}, cert.SANs...)

	rec.info(ctx, "start", fmt.Sprintf("Starting certificate issuance for %s", cert.Domain),
		fmt.Sprintf("Domains: %s\nCertificate ID: %d\nACME account ID: %d\nDNS provider ID: %d",
			strings.Join(domains, ", "), cert.ID, cert.ACMEAccountID, cert.DNSProviderID))

	// ── account ────────────────────────────────────────────────────────
	rec.info(ctx, "load_account", "Loading ACME account", "")
	acct, err := is.Store.GetACMEAccount(ctx, cert.ACMEAccountID)
	if err != nil {
		rec.failure(ctx, "load_account", "Could not load the ACME account", err.Error())
		return err
	}
	signer, err := ParseAccountKey(acct.PrivateKeyPEM)
	if err != nil {
		rec.failure(ctx, "load_account", "The stored account key is unusable", err.Error())
		return err
	}
	account := acme.Account{PrivateKey: signer}
	if acct.AccountURL != nil {
		account.Location = *acct.AccountURL
	}
	rec.success(ctx, "load_account", fmt.Sprintf("ACME account %q loaded", acct.Name), "")

	// ── DNS providers ──────────────────────────────────────────────────
	// A certificate can span zones held at different providers, so this is
	// a set; each challenge goes to whichever one owns its zone.
	rec.info(ctx, "load_dns_provider", "Loading the DNS providers", "")
	providers, err := is.loadProviders(ctx, cert.ID, cert.DNSProviderID)
	if err != nil {
		rec.failure(ctx, "load_dns_provider", "Could not load the DNS providers", err.Error())
		return err
	}
	names := make([]string, 0, len(providers))
	for _, p := range providers {
		names = append(names, fmt.Sprintf("%s (%s)", p.name, p.kind))
	}
	rec.success(ctx, "load_dns_provider",
		fmt.Sprintf("%d DNS provider(s) loaded", len(providers)), strings.Join(names, "\n"))

	// ── connect ────────────────────────────────────────────────────────
	client := &acme.Client{
		Directory:  acct.DirectoryURL,
		HTTPClient: is.HTTPClient,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	rec.info(ctx, "acme_connect", fmt.Sprintf("Connecting to the CA at %s", acct.DirectoryURL), "")
	if _, err := client.GetDirectory(ctx); err != nil {
		rec.failure(ctx, "acme_connect", "Could not reach the CA", err.Error())
		return err
	}
	rec.success(ctx, "acme_connect", "Connected to the CA", "")

	// ── order ──────────────────────────────────────────────────────────
	// Refuse an IP address up front. RFC 8738 forbids dns-01 for IP
	// identifiers — Let's Encrypt puts it plainly: "you can't use the DNS
	// challenge method to prove your control over an IP address; only the
	// http-01 and tls-alpn-01 methods can be used." This service does
	// DNS-01 only, so the order would be accepted and then fail at
	// challenge selection with something far less clear than this.
	for _, d := range domains {
		if IdentifierType(d) == "ip" {
			err := fmt.Errorf(
				"%s is an IP address, and an IP certificate cannot be validated over DNS-01; "+
					"it needs http-01 or tls-alpn-01, which this service does not implement", d)
			rec.failure(ctx, "create_order", "IP addresses are not supported", err.Error())
			return err
		}
	}

	ids := make([]acme.Identifier, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, acme.Identifier{Type: IdentifierType(d), Value: d})
	}
	newOrder := acme.Order{Identifiers: ids}
	// An ACME profile is the only mechanism that actually influences the
	// issued lifetime; a CA ignores any validity the client merely asks
	// for. acmez validates the name against the directory's advertised
	// profiles before sending, so a typo fails here rather than at the CA.
	if cert.Profile != "" {
		newOrder.Profile = cert.Profile
	}
	// A requested lifetime rides on the order's notAfter field. Only some
	// CAs accept it — Google Trust Services does, down to a day; Let's
	// Encrypt rejects any order carrying notBefore or notAfter outright, so
	// this stays zero unless the operator asked for a lifetime.
	if cert.ValidityDays > 0 {
		notAfter := time.Now().UTC().Add(time.Duration(cert.ValidityDays) * 24 * time.Hour)
		newOrder.NotAfter = &notAfter
	}
	if cert.NotBeforeDays > 0 {
		notBefore := time.Now().UTC().Add(time.Duration(cert.NotBeforeDays) * 24 * time.Hour)
		newOrder.NotBefore = &notBefore
	}
	rec.info(ctx, "create_order", fmt.Sprintf("Creating an order for %d domain(s)", len(ids)),
		orderDetail(cert.Profile, cert.ValidityDays))
	order, err := client.NewOrder(ctx, account, newOrder)
	if err != nil {
		rec.failure(ctx, "create_order", "The CA rejected the order", err.Error())
		return err
	}
	rec.success(ctx, "create_order", "Order created", fmt.Sprintf("Order: %s", order.Location))

	// Cleanup is registered before any record is written and runs on every
	// path. The Rust implementation cleaned up only on success, so a failed
	// issuance left challenge records behind in DNS.
	var written []plantedRecord
	defer func() {
		if len(written) == 0 {
			return
		}
		// A fresh context: the issuance context may already be cancelled or
		// past its deadline, and cleanup still has to happen.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		rec.info(cleanupCtx, "dns_cleanup",
			fmt.Sprintf("Removing %d challenge record(s)", len(written)), "")
		for _, w := range written {
			if err := w.via.RemoveTXT(cleanupCtx, w.name, w.value); err != nil {
				// Non-fatal: a leftover TXT record is harmless, and failing
				// here would mask the real issuance outcome.
				rec.info(cleanupCtx, "dns_cleanup",
					fmt.Sprintf("Could not remove %s", w.name), err.Error())
			}
		}
		rec.success(cleanupCtx, "dns_cleanup", "Challenge records cleaned up", "")
	}()

	// ── authorizations ─────────────────────────────────────────────────
	rec.info(ctx, "get_authorizations",
		fmt.Sprintf("Fetching %d authorization(s)", len(order.Authorizations)), "")
	type pending struct {
		authz     acme.Authorization
		challenge acme.Challenge
	}
	var todo []pending
	for _, authzURL := range order.Authorizations {
		authz, err := client.GetAuthorization(ctx, account, authzURL)
		if err != nil {
			rec.failure(ctx, "get_authorizations", "Could not fetch an authorization", err.Error())
			return err
		}
		if authz.Status == acme.StatusValid {
			rec.success(ctx, "dns_skip",
				fmt.Sprintf("Authorization for %s is already valid", authz.Identifier.Value), "")
			continue
		}
		var challenge acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == acme.ChallengeTypeDNS01 {
				challenge = c
				break
			}
		}
		if challenge.Type == "" {
			err := fmt.Errorf("no dns-01 challenge offered for %s", authz.Identifier.Value)
			rec.failure(ctx, "get_authorizations", err.Error(), "")
			return err
		}
		todo = append(todo, pending{authz: authz, challenge: challenge})
	}
	rec.success(ctx, "get_authorizations",
		fmt.Sprintf("%d authorization(s) need a challenge", len(todo)), "")

	// ── present every challenge before validating any ──────────────────
	// A certificate covering both example.com and *.example.com yields two
	// authorizations whose record names are identical but whose digests
	// differ. Both TXT records must exist simultaneously, which is why the
	// providers add rather than replace.
	// The resolver used for delegation lookups and for the propagation
	// check is the same one; build it once.
	settings := is.dohSettings()
	verifier := dns.NewVerifier(settings.Server, settings.Retries, settings.Interval)

	for _, p := range todo {
		name := p.challenge.DNS01TXTRecordName()
		value := p.challenge.DNS01KeyAuthorization()

		// Follow any CNAME from the challenge name. An operator who cannot
		// get DNS credentials for the real zone points its challenge record
		// at one they do control; the CA follows the same CNAME as ordinary
		// resolution. acme.sh makes this a per-certificate flag
		// (--challenge-alias); resolving it needs no configuration and
		// cannot fall out of sync.
		if target, err := is.resolveTarget(ctx, verifier, name); err != nil {
			// Not fatal: a resolver hiccup must not break an issuance that
			// uses no delegation at all.
			rec.info(ctx, "dns_add", "Could not check for delegation; using the challenge name as-is",
				err.Error())
		} else if target != name {
			rec.info(ctx, "dns_add",
				fmt.Sprintf("%s is delegated to %s", name, target),
				"The TXT record goes in the delegated zone; the CA follows the CNAME.")
			name = target
		}

		// Route by the resolved name: with delegation the TXT belongs in
		// the aliased zone, which may sit at a different provider than the
		// certificate's own domain.
		bound, err := providerFor(ctx, providers, name)
		if err != nil {
			rec.failure(ctx, "dns_add", "No DNS provider for this record", err.Error())
			return err
		}
		detail := fmt.Sprintf("%s TXT %q", name, value)
		if len(providers) > 1 {
			detail += "\nvia " + bound.name
		}
		rec.info(ctx, "dns_add", fmt.Sprintf("Adding TXT record %s", name), detail)
		if err := bound.provider.AddTXT(ctx, name, value); err != nil {
			rec.failure(ctx, "dns_add", fmt.Sprintf("Could not add the TXT record for %s",
				p.authz.Identifier.Value), err.Error())
			return err
		}
		// The provider is remembered so cleanup goes back to the same
		// account; asking again could pick a different one, or fail.
		written = append(written, plantedRecord{name: name, value: value, via: bound.provider})
		rec.success(ctx, "dns_add",
			fmt.Sprintf("TXT record added for %s", p.authz.Identifier.Value), "")
	}

	// ── wait for propagation ───────────────────────────────────────────
	// Either switch turns the check off: the global one for a deployment
	// whose resolver never sees its records, the per-certificate one for a
	// single zone that is invisible to us but fine for the CA.
	if settings.Skip || cert.SkipDNSCheck {
		reason := "disabled in the settings"
		if cert.SkipDNSCheck {
			reason = "disabled for this certificate"
		}
		// Wait blind rather than handing the challenge over immediately.
		// Without the check something still has to absorb propagation
		// delay, and if the CA absorbs it the failure surfaces later and
		// reads worse than ours would have.
		// The per-certificate value wins when set, including an explicit
		// zero: a zone that publishes instantly should not inherit a wait
		// chosen for the slowest provider in the deployment.
		wait := settings.SkipWait
		waitSource := "global setting"
		if cert.SkipDNSWaitSeconds != nil {
			wait = time.Duration(*cert.SkipDNSWaitSeconds) * time.Second
			waitSource = "set for this certificate"
		}
		// Nothing was written when every authorization was already valid —
		// the CA remembers a recent validation — so there is no
		// propagation to wait for. Sleeping anyway added a minute to an
		// issuance that had no DNS work in it at all.
		if wait > 0 && len(written) > 0 {
			rec.info(ctx, "dns_verify",
				fmt.Sprintf("Propagation check skipped; waiting %s instead", wait),
				reason+"; wait "+waitSource)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			rec.success(ctx, "dns_verify", fmt.Sprintf("Waited %s without checking", wait),
				reason+"; wait "+waitSource)
		} else if len(written) == 0 {
			rec.success(ctx, "dns_verify", "No challenge records were needed", "")
		} else if len(written) == 0 {
			rec.success(ctx, "dns_verify", "No challenge records were needed", "")
		} else if len(written) == 0 {
			rec.success(ctx, "dns_verify", "No challenge records were needed", "")
		} else {
			rec.success(ctx, "dns_verify", "DNS propagation check skipped", reason)
		}
	} else {
		for _, w := range written {
			rec.info(ctx, "dns_verify", fmt.Sprintf("Verifying propagation of %s", w.name), "")
			if err := verifier.Wait(ctx, w.name, w.value); err != nil {
				rec.failure(ctx, "dns_verify",
					fmt.Sprintf("%s did not propagate", w.name), err.Error())
				return err
			}
			rec.success(ctx, "dns_verify", fmt.Sprintf("%s is visible", w.name), "")
		}
	}

	// ── tell the CA to validate ────────────────────────────────────────
	for _, p := range todo {
		rec.info(ctx, "challenge_ready",
			fmt.Sprintf("Telling the CA the challenge for %s is ready", p.authz.Identifier.Value), "")
		if _, err := client.InitiateChallenge(ctx, account, p.challenge); err != nil {
			rec.failure(ctx, "challenge_ready",
				fmt.Sprintf("The CA rejected our readiness notice for %s",
					p.authz.Identifier.Value), err.Error())
			return err
		}
		rec.success(ctx, "challenge_ready",
			fmt.Sprintf("CA notified for %s", p.authz.Identifier.Value), "")
	}

	// ── poll ───────────────────────────────────────────────────────────
	for _, p := range todo {
		rec.info(ctx, "poll_order",
			fmt.Sprintf("Waiting for the CA to validate %s", p.authz.Identifier.Value), "")
		final, err := client.PollAuthorization(ctx, account, p.authz)
		if err != nil {
			rec.failure(ctx, "poll_order",
				fmt.Sprintf("Validation failed for %s", p.authz.Identifier.Value), err.Error())
			return err
		}
		rec.success(ctx, "poll_order",
			fmt.Sprintf("%s validated (status %s)", p.authz.Identifier.Value, final.Status), "")
	}

	// ── CSR ────────────────────────────────────────────────────────────
	// Reuse the existing key unless rotation was asked for. Rotating is the
	// mainstream default — certbot rotates unless given --reuse-key — and
	// it limits how long a leaked key stays useful. Reuse keeps anything
	// pinning the public key working: a TLSA record with an SPKI selector
	// would otherwise need republishing on every renewal.
	var (
		certSigner crypto.Signer
		keyPEM     string
		csrDER     []byte
	)
	switch {
	case cert.CSRPEM != "":
		// A caller-supplied CSR skips key handling entirely: the private
		// half never reaches us, which is the whole reason to supply one —
		// a key that lives in an HSM cannot be handed over.
		csrDER, err = ParseCSR(cert.CSRPEM, domains)
		if err != nil {
			rec.failure(ctx, "generate_csr", "The supplied CSR is unusable", err.Error())
			return err
		}
		rec.success(ctx, "generate_csr", "Using the supplied CSR",
			fmt.Sprintf("CSR: %d bytes\nNo private key is stored for this certificate.", len(csrDER)))

	case !cert.RotateKey && cert.KeyPEM != "":
		rec.info(ctx, "generate_csr", "Reusing the existing private key", "")
		certSigner, err = ParseCertKey(cert.KeyPEM)
		if err != nil {
			// A key that will not parse must not silently become a new one:
			// whoever pinned it deserves to hear about it.
			rec.failure(ctx, "generate_csr", "The stored private key is unusable", err.Error())
			return err
		}
		keyPEM = cert.KeyPEM
	default:
		reason := "no key stored yet"
		if cert.RotateKey {
			reason = "rotation is enabled for this certificate"
		}
		rec.info(ctx, "generate_csr", "Generating a new certificate key and CSR",
			reason+"; key type: "+keyTypeOrDefault(cert.KeyType))
		certSigner, keyPEM, err = GenerateCertKey(cert.KeyType)
		if err != nil {
			rec.failure(ctx, "generate_csr", "Could not generate the certificate key", err.Error())
			return err
		}
	}
	if certSigner != nil {
		csrDER, err = BuildCSR(certSigner, domains, cert.ExtendedKeyUsage)
		if err != nil {
			rec.failure(ctx, "generate_csr", "Could not build the CSR", err.Error())
			return err
		}
		eku := cert.ExtendedKeyUsage
		if eku == "" {
			eku = "(left to the CA)"
		}
		rec.success(ctx, "generate_csr", "CSR generated",
			fmt.Sprintf("Key: %s\nCSR: %d bytes\nSubject: (empty; names are SANs)\nExtended key usage: %s",
				DescribeKey(certSigner), len(csrDER), eku))
	}

	// ── finalize ───────────────────────────────────────────────────────
	rec.info(ctx, "finalize_order", "Submitting the CSR", "")
	order, err = client.FinalizeOrder(ctx, account, order, csrDER)
	if err != nil {
		rec.failure(ctx, "finalize_order", "The CA rejected the CSR", err.Error())
		return err
	}
	rec.success(ctx, "finalize_order", "Order finalized; the CA is signing", "")

	// ── download ───────────────────────────────────────────────────────
	rec.info(ctx, "download_cert", "Downloading the signed certificate", "")
	chains, err := client.GetCertificateChain(ctx, account, order.Certificate)
	if err != nil {
		rec.failure(ctx, "download_cert", "Could not download the certificate", err.Error())
		return err
	}
	if len(chains) == 0 {
		err := errors.New("the CA returned no certificate chain")
		rec.failure(ctx, "download_cert", err.Error(), "")
		return err
	}
	chain, chainNote := pickChain(chains, cert.PreferredChain)
	rec.success(ctx, "download_cert", "Certificate downloaded", chainNote)

	// ── save ───────────────────────────────────────────────────────────
	rec.info(ctx, "save_cert", "Saving the certificate", "")
	leafPEM, restPEM, leaf, err := SplitChain(chain.ChainPEM)
	if err != nil {
		rec.failure(ctx, "save_cert", "The CA's chain could not be parsed", err.Error())
		return err
	}
	issued := db.IssuedCertificate{
		CertPEM:   leafPEM,
		ChainPEM:  restPEM,
		KeyPEM:    keyPEM,
		Serial:    fmt.Sprintf("%X", leaf.SerialNumber),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}
	// ARI tells us when the CA would like the certificate renewed, which
	// beats guessing from validity_days.
	//
	// SelectedTime, not SuggestedWindow.Start: acmez already picks a
	// uniformly random instant inside the window, which is the point of
	// ARI. Renewing at the window's start would put every certificate on
	// the same schedule and hand the CA a thundering herd.
	if info, err := client.GetRenewalInfo(ctx, leaf); err == nil {
		selected := info.SelectedTime
		issued.RenewAfter = &selected
	}
	if err := is.Store.SaveIssuedCertificate(ctx, cert.ID, issued); err != nil {
		rec.failure(ctx, "save_cert", "Could not save the certificate", err.Error())
		return err
	}
	rec.success(ctx, "save_cert", "Certificate saved",
		fmt.Sprintf("Serial: %s\nNot before: %s\nNot after: %s",
			issued.Serial,
			issued.NotBefore.UTC().Format(time.RFC3339),
			issued.NotAfter.UTC().Format(time.RFC3339)))

	rec.success(ctx, "complete", fmt.Sprintf("Certificate issued for %s", cert.Domain), "")
	return nil
}

// DoHSettings controls the DNS propagation check performed before a
// challenge is handed to the CA.
type DoHSettings struct {
	Server   string
	Retries  int
	Interval time.Duration
	// Skip turns the check off, for tests or an operator whose resolver
	// cannot see the record.
	Skip bool
	// SkipWait is how long to pause when Skip is set. Zero waits not at all,
	// which is what tests want and what an impatient operator gets.
	SkipWait time.Duration
}

func (is *Issuer) dohSettings() DoHSettings {
	if is.DoH == nil {
		return DoHSettings{}
	}
	return is.DoH()
}

// resolveTarget follows delegation, through the injected resolver when a
// test supplies one.
func (is *Issuer) resolveTarget(ctx context.Context, v *dns.Verifier, name string) (string, error) {
	if is.ResolveTarget != nil {
		return is.ResolveTarget(ctx, name)
	}
	// With no resolver configured there is nothing to ask. NewVerifier
	// substitutes a public one for an empty address, which quietly turned
	// every issuance into an outbound lookup — including in tests, which
	// this project keeps offline on purpose.
	if is.dohSettings().Server == "" {
		return name, nil
	}
	return v.ResolveChallengeTarget(ctx, name)
}

func keyTypeOrDefault(t string) string {
	if t == "" {
		return DefaultKeyType
	}
	return t
}

// pickChain chooses among the chains a CA offers, and explains the choice
// for the timeline. Taking the first unconditionally discarded the others
// silently; some deployments need a specific issuer, historically the
// cross-signed root that older clients trusted.
func pickChain(chains []acme.Certificate, preferred string) (acme.Certificate, string) {
	if preferred == "" {
		return chains[0], fmt.Sprintf("%d chain(s) offered; using the first", len(chains))
	}
	// A single chain is not a reason to skip the check. The operator named
	// an issuer; if the CA does not offer it they need to hear so, rather
	// than assume they got what they asked for.
	for _, c := range chains {
		issuer, err := ChainIssuerCN(c.ChainPEM)
		if err != nil {
			continue
		}
		if strings.EqualFold(issuer, preferred) {
			return c, fmt.Sprintf("%d chain(s) offered; matched preferred issuer %q", len(chains), issuer)
		}
	}
	// A preference that matches nothing must not fail the issuance — the
	// certificate is valid either way, and the operator can see why.
	return chains[0], fmt.Sprintf(
		"%d chain(s) offered; none matched preferred issuer %q, using the first", len(chains), preferred)
}

func orderDetail(profile string, validityDays int64) string {
	out := "Profile: (the CA's default)"
	if profile != "" {
		out = "Profile: " + profile
	}
	if validityDays > 0 {
		out += fmt.Sprintf("; requested lifetime: %d day(s)", validityDays)
	}
	return out
}

// dnsProviderRow reads the provider's kind and config. It lives here rather
// than on Store because milestone 4 owns the provider CRUD; this is the one
// read issuance needs.
func (is *Issuer) dnsProviderRow(ctx context.Context, id int64) (string, string, error) {
	sqlStore, ok := is.Store.(*db.SQLite)
	if !ok {
		return "", "", errors.New("store does not expose DNS provider rows")
	}
	var kind, configJSON string
	err := sqlStore.DB.QueryRowContext(ctx,
		`SELECT kind, config FROM dns_providers WHERE id = ?`, id).Scan(&kind, &configJSON)
	if err != nil {
		return "", "", fmt.Errorf("load dns provider %d: %w", id, err)
	}
	return kind, configJSON, nil
}

// redactConfig masks credential-bearing fields so the timeline can show a
// provider's configuration without leaking secrets.
func redactConfig(configJSON string) string {
	for _, key := range []string{"api_token", "access_key_secret", "secret_key"} {
		configJSON = redactJSONField(configJSON, key)
	}
	return configJSON
}

func redactJSONField(s, key string) string {
	marker := `"` + key + `":"`
	i := strings.Index(s, marker)
	if i < 0 {
		return s
	}
	start := i + len(marker)
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		return s
	}
	value := s[start : start+end]
	keep := value
	if len(keep) > 4 {
		keep = keep[:4]
	}
	return s[:start] + keep + "***" + s[start+end:]
}
