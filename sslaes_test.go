// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink_test

import (
	"encoding/hex"
	"testing"

	"github.com/cB-Sigma/tplink"
)

// The HTTPS transport's hashes, against values computed with python-kasa
// 0.11.0.1's SslAesTransport functions (in the interop image) for the
// password "demo-password", cnonce 0123456789ABCDEF and nonce
// FEDCBA9876543210.
func TestSSLAESVectors(t *testing.T) {
	const cn, n = "0123456789ABCDEF", "FEDCBA9876543210"
	hashes := tplink.SSLAESPasswordHashes("demo-password")
	if hashes[0] != "41BD876B085D6031CB0E04DE35B88D77F83A4BA39F879FEE40805AC19E356023" || hashes[1] != "4B4D9529148D8D9440D7E20C78287F69" {
		t.Fatalf("password hashes %v", hashes)
	}
	ph := hashes[0]
	if got := tplink.SSLAESConfirm(cn, n, ph); got != "0E9163DFB0E314DE9F19598B1FF7DACF17B5FCBDCDD0E1A295379DBE348CFBF5"+n+cn {
		t.Errorf("confirm %s", got)
	}
	if got := tplink.SSLAESDigest(cn, n, ph); got != "1DA067D136D1ABF459EAB7A50A7960C9501E3122C0355CA8D90B84B8ABB9AF97"+cn+n {
		t.Errorf("digest %s", got)
	}
	key, iv := tplink.SSLAESKeys(cn, n, ph)
	if hex.EncodeToString(key) != "8ab30ef0ae7272ef3ffcdc57c9e3b69e" || hex.EncodeToString(iv) != "e8fc7072360355391c9ce1f3ef6f6c8b" {
		t.Errorf("keys %x %x", key, iv)
	}
	if got := tplink.SSLAESTag([]byte(`{"method":"securePassthrough"}`), cn, ph, 7); got != "5190C5FA0C0611240CFFBBDF50936D27FDA221F3F098CC49D61D5D9B419FB7DA" {
		t.Errorf("tag %s", got)
	}
}

func TestBaseURL(t *testing.T) {
	for _, c := range []struct {
		f    tplink.TapoFound
		want string
	}{
		{tplink.TapoFound{Host: "10.0.0.2", Encrypt: "KLAP"}, "http://10.0.0.2"},
		{tplink.TapoFound{Host: "10.0.0.2", Encrypt: "KLAP", HTTPPort: 8080}, "http://10.0.0.2:8080"},
		{tplink.TapoFound{Host: "10.0.0.2", Encrypt: "KLAP", HTTPS: true}, "https://10.0.0.2:4433"},
		{tplink.TapoFound{Host: "10.0.0.2", Encrypt: "AES", HTTPS: true}, "https://10.0.0.2:443"},
	} {
		if got := c.f.BaseURL(); got != c.want {
			t.Errorf("%+v: %s", c.f, got)
		}
	}
	f, err := tplink.ParseTapoAnswer(append(make([]byte, 16), []byte(`{"error_code":0,"result":{"device_type":"SMART.IPCAMERA","device_model":"C210(EU)",`+
		`"mac":"00-11-22-33-44-55","ip":"10.0.0.9","encrypt_type":["3"],"mgt_encrypt_schm":{"is_support_https":true}}}`)...))
	if err != nil || f.Protocol() != "aes" || f.LoginVersion != 3 || f.BaseURL() != "https://10.0.0.9:443" {
		t.Errorf("camera answer %+v %v", f, err)
	}
}
