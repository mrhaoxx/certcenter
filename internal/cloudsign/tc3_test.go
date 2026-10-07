// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package cloudsign

import (
	"strings"
	"testing"
	"time"
)

// 腾讯云《签名方法 v3》文档的 DescribeInstances 算例。
//
// 文档把 SecretId/SecretKey 打了码，因此**最终签名无法端到端复现**；
// 但它公布了 payload 哈希与 CanonicalRequest 哈希，这两个值锁住的正是
// 签名实现最容易出错的部分——规范请求的拼装（头部排序、动作名小写、
// 空行位置、载荷哈希）。密钥派生链按文档实现，无法用公开数据验证。
const (
	// 反引号原始字符串：未 等在请求体里是字面的转义序列，不是解码后的
	// 汉字。官方算例签的就是这些字节，写成 "未命名" 哈希立刻对不上。
	tc3ExamplePayload = `{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}`

	tc3ExamplePayloadHash = "35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064"

	tc3ExampleCanonicalRequest = "POST\n" +
		"/\n" +
		"\n" +
		"content-type:application/json; charset=utf-8\n" +
		"host:cvm.tencentcloudapi.com\n" +
		"x-tc-action:describeinstances\n" +
		"\n" +
		"content-type;host;x-tc-action\n" +
		tc3ExamplePayloadHash

	tc3ExampleCanonicalRequestHash = "7019a55be8395899b900fb5564e4200d984910f34794a27cb3fb7d10ff6a1e84"

	tc3ExampleStringToSign = "TC3-HMAC-SHA256\n" +
		"1551113065\n" +
		"2019-02-25/cvm/tc3_request\n" +
		tc3ExampleCanonicalRequestHash
)

func tc3Example() TC3Request {
	return TC3Request{
		SecretID:  "AKIDEXAMPLE",
		SecretKey: "SECRETEXAMPLE",
		Host:      "cvm.tencentcloudapi.com",
		Service:   "cvm",
		Action:    "DescribeInstances",
		Version:   "2017-03-12",
		Region:    "ap-guangzhou",
		Timestamp: time.Unix(1551113065, 0).UTC(),
		Payload:   tc3ExamplePayload,
	}
}

func TestTC3PayloadHashMatchesOfficialExample(t *testing.T) {
	if got := sha256Hex(tc3ExamplePayload); got != tc3ExamplePayloadHash {
		t.Errorf("payload hash = %q, want %q", got, tc3ExamplePayloadHash)
	}
}

func TestTC3CanonicalRequestMatchesOfficialExample(t *testing.T) {
	got := tc3Example().CanonicalRequest()
	if got != tc3ExampleCanonicalRequest {
		t.Errorf("canonicalRequest mismatch\n--- got ---\n%s\n--- want ---\n%s",
			got, tc3ExampleCanonicalRequest)
	}
	if hash := sha256Hex(got); hash != tc3ExampleCanonicalRequestHash {
		t.Errorf("canonicalRequest hash = %q, want %q", hash, tc3ExampleCanonicalRequestHash)
	}
}

func TestTC3StringToSignMatchesOfficialExample(t *testing.T) {
	if got := tc3Example().StringToSign(); got != tc3ExampleStringToSign {
		t.Errorf("stringToSign =\n%q\nwant\n%q", got, tc3ExampleStringToSign)
	}
}

func TestTC3AuthorizationFormat(t *testing.T) {
	auth, headers := tc3Example().Sign()
	for _, want := range []string{
		"TC3-HMAC-SHA256 ",
		"Credential=AKIDEXAMPLE/2019-02-25/cvm/tc3_request",
		"SignedHeaders=content-type;host;x-tc-action",
		"Signature=",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization = %q, want it to contain %q", auth, want)
		}
	}
	for _, want := range []string{
		"Authorization", "Content-Type", "Host", "X-TC-Action",
		"X-TC-Version", "X-TC-Timestamp", "X-TC-Region",
	} {
		if _, ok := headers[want]; !ok {
			t.Errorf("headers missing %q; got %v", want, headers)
		}
	}
	if headers["X-TC-Timestamp"] != "1551113065" {
		t.Errorf("X-TC-Timestamp = %q", headers["X-TC-Timestamp"])
	}
	// 签名覆盖 content-type，发送的必须与签名的完全一致。
	if headers["Content-Type"] != tc3ContentType {
		t.Errorf("Content-Type = %q, want the signed value %q", headers["Content-Type"], tc3ContentType)
	}
}

func TestTC3DifferentKeyGivesDifferentSignature(t *testing.T) {
	a, _ := tc3Example().Sign()
	other := tc3Example()
	other.SecretKey = "ANOTHERSECRET"
	b, _ := other.Sign()
	if a == b {
		t.Error("changing the secret key did not change the signature")
	}
}

func TestTC3ActionHeaderIsLowercasedInCanonicalRequest(t *testing.T) {
	// 规范请求里的动作名必须小写，而发出去的 X-TC-Action 头保持原样。
	req := tc3Example()
	if !strings.Contains(req.CanonicalRequest(), "x-tc-action:describeinstances") {
		t.Error("the canonical request must carry the lowercased action")
	}
	_, headers := req.Sign()
	if headers["X-TC-Action"] != "DescribeInstances" {
		t.Errorf("X-TC-Action = %q, want the original casing", headers["X-TC-Action"])
	}
}
