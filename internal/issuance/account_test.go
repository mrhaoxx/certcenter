// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"testing"
)

func TestGenerateAndParseAccountKey(t *testing.T) {
	pemStr, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pemStr, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("key PEM starts with %q, want a PKCS#8 header", pemStr[:30])
	}

	signer, err := ParseAccountKey(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("ParseAccountKey returned %T, want *ecdsa.PrivateKey", signer)
	}
	if name := ec.Curve.Params().Name; name != "P-256" {
		t.Errorf("curve = %q, want P-256", name)
	}
}

func TestParseAccountKeyRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"not pem at all",
		"-----BEGIN PRIVATE KEY-----\nnotbase64!!\n-----END PRIVATE KEY-----\n",
	} {
		if _, err := ParseAccountKey(in); err == nil {
			t.Errorf("ParseAccountKey(%q) = nil error, want failure", in)
		}
	}
}

func TestRegisterAgainstTestCA(t *testing.T) {
	caSrv := newTestCA(t)
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}

	r := &Registrar{HTTPClient: caSrv.HTTPClient}
	accountURL, err := r.Register(context.Background(), Registration{
		DirectoryURL: caSrv.DirectoryURL, Email: "admin@example.com", KeyPEM: keyPEM,
	})
	if err != nil {
		t.Fatalf("Register() = %v", err)
	}
	if accountURL == "" {
		t.Error("Register returned an empty account URL")
	}
	if !strings.HasPrefix(accountURL, "https://") {
		t.Errorf("accountURL = %q, want an absolute URL", accountURL)
	}
}

func TestVerifyAcceptsARegisteredAccount(t *testing.T) {
	// 导入流程：调用方给出私钥与账户 URL，我们回 CA 确认这对组合有效，
	// 而不是把用户填的东西直接信了存库。
	caSrv := newTestCA(t)
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	r := &Registrar{HTTPClient: caSrv.HTTPClient}
	accountURL, err := r.Register(context.Background(), Registration{
		DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c", KeyPEM: keyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Verify(context.Background(), caSrv.DirectoryURL, accountURL, keyPEM); err != nil {
		t.Errorf("Verify() on a freshly registered account = %v, want nil", err)
	}
}

func TestVerifyRejectsAMismatchedKey(t *testing.T) {
	caSrv := newTestCA(t)
	r := &Registrar{HTTPClient: caSrv.HTTPClient}

	realKey, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	accountURL, err := r.Register(context.Background(), Registration{
		DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c", KeyPEM: realKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(context.Background(), caSrv.DirectoryURL, accountURL, otherKey); err == nil {
		t.Error("Verify() with the wrong key = nil error, want rejection")
	}
}

func TestRegisterRejectsBadDirectory(t *testing.T) {
	r := &Registrar{}
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(context.Background(), Registration{
		DirectoryURL: "https://127.0.0.1:1/directory", Email: "a@b.c", KeyPEM: keyPEM,
	}); err == nil {
		t.Error("Register against an unreachable directory = nil error, want failure")
	}
}

func TestRegisterAgainstEABRequiringCA(t *testing.T) {
	// ZeroSSL、Google Trust Services、Sectigo 都要求外部账户绑定，
	// 不带 EAB 的 newAccount 会被拒。
	caSrv := newEABTestCA(t)
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	r := &Registrar{HTTPClient: caSrv.HTTPClient}

	t.Run("不带 EAB 被拒且可识别", func(t *testing.T) {
		_, err := r.Register(context.Background(), Registration{
			DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c", KeyPEM: keyPEM,
		})
		if err == nil {
			t.Fatal("Register without EAB = nil error, want rejection")
		}
		// API 层靠这个判断把泛泛的 502 换成可操作的提示。
		if !RequiresEAB(err) {
			t.Errorf("RequiresEAB(%v) = false, want true", err)
		}
	})

	t.Run("带正确 EAB 注册成功", func(t *testing.T) {
		accountURL, err := r.Register(context.Background(), Registration{
			DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c", KeyPEM: keyPEM,
			EABKeyID: testEABKeyID, EABMACKey: testEABMACKey,
		})
		if err != nil {
			t.Fatalf("Register with EAB = %v", err)
		}
		if accountURL == "" {
			t.Error("Register returned an empty account URL")
		}
	})

	t.Run("EAB 密钥错误被拒", func(t *testing.T) {
		otherKey, err := GenerateAccountKey()
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.Register(context.Background(), Registration{
			DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c", KeyPEM: otherKey,
			EABKeyID: "unknown-kid", EABMACKey: testEABMACKey,
		})
		if err == nil {
			t.Error("Register with an unknown EAB key ID = nil error, want rejection")
		}
	})
}

func TestRegisterRejectsHalfEAB(t *testing.T) {
	// 只填一半的 EAB 是配置错误，应在发请求前就拦下。
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	r := &Registrar{}
	for _, reg := range []Registration{
		{DirectoryURL: "https://unused.invalid/dir", KeyPEM: keyPEM, EABKeyID: "kid"},
		{DirectoryURL: "https://unused.invalid/dir", KeyPEM: keyPEM, EABMACKey: "mac"},
	} {
		if _, err := r.Register(context.Background(), reg); err == nil {
			t.Errorf("Register with a half-filled EAB = nil error, want rejection")
		}
	}
}

func TestNormalizeEABMACKey(t *testing.T) {
	// 同一把密钥的四种粘贴形态都必须能用。acmez 只认无填充 base64url，
	// 其余三种会报 "base64-decoding MAC key"，而那个错误完全看不出
	// 问题出在粘贴格式上。
	const wantRawURL = "-_7_-w" // 解码后为 fb fe ff fb
	tests := []struct {
		name, in string
	}{
		{"无填充 base64url（原样）", "-_7_-w"},
		{"带填充 base64url", "-_7_-w=="},
		{"标准字母表", "+/7/+w"},
		{"标准字母表带填充", "+/7/+w=="},
		{"前后有空白", "  -_7_-w \n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeEABMACKey(tt.in)
			if err != nil {
				t.Fatalf("normalizeEABMACKey(%q) = %v", tt.in, err)
			}
			if got != wantRawURL {
				t.Errorf("normalizeEABMACKey(%q) = %q, want %q", tt.in, got, wantRawURL)
			}
		})
	}
}

func TestNormalizeEABMACKeyRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "not base64!!!", "==="} {
		if _, err := normalizeEABMACKey(in); err == nil {
			t.Errorf("normalizeEABMACKey(%q) = nil error, want failure", in)
		}
	}
}

func TestRegisterAcceptsPaddedEABMACKey(t *testing.T) {
	// 端到端：把测试 CA 的密钥改成带填充的形态照样注册成功。
	caSrv := newEABTestCA(t)
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	r := &Registrar{HTTPClient: caSrv.HTTPClient}

	padded := testEABMACKey
	for len(padded)%4 != 0 {
		padded += "="
	}
	if padded == testEABMACKey {
		padded = testEABMACKey + "==" // 确保这轮真的在测填充形态
	}

	if _, err := r.Register(context.Background(), Registration{
		DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c", KeyPEM: keyPEM,
		EABKeyID: testEABKeyID, EABMACKey: padded,
	}); err != nil {
		t.Errorf("Register with a padded MAC key = %v, want it accepted", err)
	}
}
