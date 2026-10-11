// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"testing"

	"github.com/cB-Sigma/tplink"
)

// Covers: SIG-IPE-4446
func TestKasaFraming(t *testing.T) {
	plain := []byte(`{"system":{"get_sysinfo":{}}}`)
	enc := tplink.Encrypt(plain)
	// The autokey starts at 171: '{' becomes 0xd0 and '"' 0xf2.
	if hex.EncodeToString(enc[:2]) != "d0f2" {
		t.Errorf("first bytes %x", enc[:2])
	}
	if !bytes.Equal(tplink.Decrypt(enc), plain) {
		t.Error("round trip")
	}
	f := tplink.Frame(plain)
	if hex.EncodeToString(f[:4]) != "0000001d" {
		t.Errorf("length prefix %x", f[:4])
	}
	got, err := tplink.ReadFrame(bytes.NewReader(f))
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("read frame %q %v", got, err)
	}
}

// Covers: SIG-IPE-4447
func TestKLAPSessionAndHandshake(t *testing.T) {
	auth := tplink.AuthHash("user@example.invalid", "pw")
	if len(auth) != 32 {
		t.Fatal("auth hash length")
	}
	local, remote := bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16)
	a, b := tplink.NewSession(local, remote, auth), tplink.NewSession(local, remote, auth)
	seq, body := a.Encrypt([]byte(`{"method":"get_device_info"}`))
	if p, err := b.Decrypt(seq, body); err != nil || string(p) != `{"method":"get_device_info"}` {
		t.Fatalf("decrypt %q %v", p, err)
	}
	body[40] ^= 1
	if _, err := b.Decrypt(seq, body); err == nil {
		t.Error("a changed body passed the signature")
	}
	// The handshake against a simulated device is in tplink-sim
	// (TestKLAPHandshake).
}

// The module ships no vendor setup account: KLAPAuths and AESLogins try
// the owner's account (and blank credentials for KLAP); more accounts come
// only from the caller, in the order given.
func TestCredentialOrder(t *testing.T) {
	names := func(a []tplink.KLAPAuth) (out []string) {
		for _, x := range a {
			out = append(out, fmt.Sprintf("%s/%d", x.Name, x.Version))
		}
		return out
	}
	if got := fmt.Sprint(names(tplink.KLAPAuths("u@example.invalid", "p"))); got != "[account/2 account/1 blank/2 blank/1]" {
		t.Errorf("KLAPAuths %s", got)
	}
	if got := fmt.Sprint(names(tplink.KLAPAuths("", ""))); got != "[account/2 account/1]" {
		t.Errorf("KLAPAuths blank %s", got)
	}
	extra := tplink.Credential{Name: "x", Username: "x@example.invalid", Password: "y"}
	if got := fmt.Sprint(names(tplink.KLAPAuthsWith("u@example.invalid", "p", extra))); got != "[account/2 account/1 x/2 x/1 blank/2 blank/1]" {
		t.Errorf("KLAPAuthsWith %s", got)
	}
	if a := tplink.KLAPAuthsWith("u", "p", extra); !bytes.Equal(a[2].Hash, tplink.AuthHash("x@example.invalid", "y")) {
		t.Error("extra hash")
	}
	if l := tplink.AESLogins("", "", 2); len(l) != 0 {
		t.Errorf("AESLogins without an account %v", l)
	}
	l := tplink.AESLoginsWith("u", "p", 1, extra)
	if len(l) != 4 || l[0].Params["password"] == nil || l[1].Params["password2"] == nil || l[2].Name != "x" || l[2].Params["password2"] == nil {
		t.Errorf("AESLoginsWith %v", l)
	}
}

// The 20002 probe has the 16-byte header open-source clients describe
// (version 2, op code 1, payload length, flags 0x11, CRC-32 over the
// message with 0x5A6B7C8D in the CRC field) and an RSA public key; a
// device's answer is read for type, model, MAC and protocol.
//
// Covers: SIG-IMP-180
func TestTapoProbeAndAnswer(t *testing.T) {
	pem := []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
	p := tplink.TapoProbe(pem)
	if p[0] != 2 || p[1] != 0 || binary.BigEndian.Uint16(p[2:]) != 1 || p[6] != 0x11 || int(binary.BigEndian.Uint16(p[4:])) != len(p)-16 {
		t.Fatalf("header % x", p[:16])
	}
	c := append([]byte(nil), p...)
	binary.BigEndian.PutUint32(c[12:], 0x5A6B7C8D)
	if crc32.ChecksumIEEE(c) != binary.BigEndian.Uint32(p[12:]) {
		t.Error("CRC")
	}
	payload, err := tplink.CheckTapoProbe(p)
	if err != nil || !bytes.Contains(payload, []byte(`"rsa_key"`)) {
		t.Fatalf("check %s %v", payload, err)
	}
	p[20] ^= 1
	if _, err := tplink.CheckTapoProbe(p); err == nil {
		t.Error("a changed probe passed the CRC")
	}
	ans := append(make([]byte, 16), []byte(`{"error_code":0,"result":{"device_id":"8022AB","owner":"F00","device_type":"SMART.TAPOPLUG","device_model":"P110(EU)",`+
		`"ip":"192.168.1.23","mac":"3C-52-A1-11-22-33","is_support_iot_cloud":true,"obd_src":"tplink","factory_default":false,`+
		`"mgt_encrypt_schm":{"is_support_https":false,"encrypt_type":"AES","http_port":80,"lv":2},"new_field":1}}`)...)
	f, err := tplink.ParseTapoAnswer(ans)
	if err != nil || f.MAC != "3c52a1112233" || f.Model != "P110" || f.Protocol() != "aes" || f.LoginVersion != 2 || f.HTTPPort != 80 || f.Host != "192.168.1.23" {
		t.Errorf("answer %+v %v", f, err)
	}
}

// Covers: SIG-IMP-184
func TestKelvinRanges(t *testing.T) {
	for model, want := range map[string][3]float64{
		"KL120(EU)": {2700, 6500, 1}, "KL120(US)": {2700, 5000, 1}, "kl 130(eu)": {2500, 9000, 1}, "LB999": {2700, 5000, 0},
	} {
		lo, hi, known := tplink.KasaKelvinRange(model)
		if lo != want[0] || hi != want[1] || known != (want[2] == 1) {
			t.Errorf("%s: %v-%v %v", model, lo, hi, known)
		}
	}
	if lo, hi := tplink.TapoKelvinRange(map[string]any{"color_temp_range": []any{2700.0, 6500.0}}); lo != 2700 || hi != 6500 {
		t.Errorf("tapo range %v-%v", lo, hi)
	}
	for _, info := range []map[string]any{nil, {"color_temp_range": []any{6500.0, 2700.0}}, {"color_temp_range": "x"}} {
		if lo, hi := tplink.TapoKelvinRange(info); lo != 2500 || hi != 6500 {
			t.Errorf("tapo default for %v: %v-%v", info, lo, hi)
		}
	}
}
