// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package cloudsign

import (
	"strings"
	"testing"
)

// 官方算例（阿里云 SDK 文档《使用 V3 签名机制原生 HTTP 调用阿里云 OpenAPI》
// 的"固定参数示例"）。期望值来自阿里云自己的文档，而不是本实现的输出——
// 这样这个测试锁的是外部权威值，改坏签名一定会被抓住。
var officialExample = ACS3Request{
	AccessKeyID:     "YourAccessKeyId",
	AccessKeySecret: "YourAccessKeySecret",
	Host:            "ecs.cn-shanghai.aliyuncs.com",
	Action:          "RunInstances",
	Version:         "2014-05-26",
	Date:            "2023-10-26T10:22:32Z",
	Nonce:           "3156853299f313e23d1673dc12e1703d",
	Params: map[string]string{
		"ImageId":  "win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd",
		"RegionId": "cn-shanghai",
	},
}

const (
	officialCanonicalRequest = "POST\n" +
		"/\n" +
		"ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai\n" +
		"host:ecs.cn-shanghai.aliyuncs.com\n" +
		"x-acs-action:RunInstances\n" +
		"x-acs-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
		"x-acs-date:2023-10-26T10:22:32Z\n" +
		"x-acs-signature-nonce:3156853299f313e23d1673dc12e1703d\n" +
		"x-acs-version:2014-05-26\n" +
		"\n" +
		"host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	officialStringToSign = "ACS3-HMAC-SHA256\n" +
		"7ea06492da5221eba5297e897ce16e55f964061054b7695beedaac1145b1e259"

	officialSignature = "06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"
)

func TestACS3CanonicalRequestMatchesOfficialExample(t *testing.T) {
	got := officialExample.CanonicalRequest()
	if got != officialCanonicalRequest {
		t.Errorf("CanonicalRequest mismatch\n--- got ---\n%s\n--- want ---\n%s", got, officialCanonicalRequest)
	}
}

func TestACS3StringToSignMatchesOfficialExample(t *testing.T) {
	got := officialExample.StringToSign()
	if got != officialStringToSign {
		t.Errorf("StringToSign = %q, want %q", got, officialStringToSign)
	}
}

func TestACS3SignatureMatchesOfficialExample(t *testing.T) {
	auth, _, _ := officialExample.Sign()
	if !strings.Contains(auth, "Signature="+officialSignature) {
		t.Errorf("Authorization = %q, want it to carry Signature=%s", auth, officialSignature)
	}
}

func TestACS3AuthorizationHeaderFormat(t *testing.T) {
	auth, _, _ := officialExample.Sign()
	want := "ACS3-HMAC-SHA256 Credential=YourAccessKeyId," +
		"SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version," +
		"Signature=" + officialSignature
	if auth != want {
		t.Errorf("Authorization =\n  %q\nwant\n  %q", auth, want)
	}
}

func TestACS3PercentEncode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abcXYZ019", "abcXYZ019"},
		{"-_.~", "-_.~"}, // RFC 3986 unreserved, must stay literal
		{"a b", "a%20b"}, // space is %20, never '+'
		{"*", "%2A"},
		{"/", "%2F"},
		{"=", "%3D"},
		{"&", "%26"},
		{"_acme-challenge", "_acme-challenge"},
		{"中", "%E4%B8%AD"}, // encoded per UTF-8 byte, uppercase hex
	}
	for _, tt := range tests {
		if got := ACS3PercentEncode(tt.in); got != tt.want {
			t.Errorf("ACS3PercentEncode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestACS3CanonicalQuerySortsByKey(t *testing.T) {
	got := ACS3CanonicalQuery(map[string]string{
		"Zebra":      "1",
		"Apple":      "2",
		"Middle":     "3",
		"DomainName": "example.com",
	})
	want := "Apple=2&DomainName=example.com&Middle=3&Zebra=1"
	if got != want {
		t.Errorf("ACS3CanonicalQuery = %q, want %q", got, want)
	}
}

func TestACS3CanonicalQueryEncodesValues(t *testing.T) {
	got := ACS3CanonicalQuery(map[string]string{"Value": "a b/c"})
	want := "Value=a%20b%2Fc"
	if got != want {
		t.Errorf("ACS3CanonicalQuery = %q, want %q", got, want)
	}
}

func TestACS3SignedQueryMatchesCanonicalQuery(t *testing.T) {
	// 发送的 URL 查询串必须与签名时的字符串完全一致。用
	// url.Values.Encode() 构造 URL 会把空格编成 '+'，签名立即失效——
	// Sign() 因此把查询串一并返回，调用方直接用它拼 URL。
	req := officialExample
	req.Params = map[string]string{"RR": "a b", "Type": "TXT"}
	_, query, _ := req.Sign()
	if query != req.CanonicalQueryString() {
		t.Errorf("Sign() query = %q, want it identical to the signed canonical query %q",
			query, req.CanonicalQueryString())
	}
	if strings.Contains(query, "+") {
		t.Errorf("query = %q, must encode space as %%20 not '+'", query)
	}
}

func TestACS3SignHeadersAreComplete(t *testing.T) {
	_, _, headers := officialExample.Sign()
	for _, want := range []string{
		"Authorization", "host", "x-acs-action", "x-acs-content-sha256",
		"x-acs-date", "x-acs-signature-nonce", "x-acs-version",
	} {
		if _, ok := headers[want]; !ok {
			t.Errorf("headers missing %q; got %v", want, headers)
		}
	}
}

func TestACS3DifferentSecretGivesDifferentSignature(t *testing.T) {
	other := officialExample
	other.AccessKeySecret = "AnotherSecret"
	a, _, _ := officialExample.Sign()
	b, _, _ := other.Sign()
	if a == b {
		t.Error("changing the secret did not change the signature")
	}
}
