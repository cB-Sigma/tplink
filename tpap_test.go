// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func scalarHex(t *testing.T, s string) *big.Int {
	return new(big.Int).SetBytes(unhex(t, s))
}

// RFC 9383 test vector for SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256,
// both sides.
//
// Covers: SIG-IMP-179
func TestSPAKE2PlusRFC9383(t *testing.T) {
	w0 := scalarHex(t, "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3")
	w1 := scalarHex(t, "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba")
	x := scalarHex(t, "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539")
	y := scalarHex(t, "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3")
	ctx := []byte("SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors")
	shareP := unhex(t, "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727")
	shareV := unhex(t, "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048")
	confirmP := unhex(t, "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527")
	confirmV := unhex(t, "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68")
	shared := unhex(t, "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7")

	v := newSpakeVerifier(w0, w1, y, ctx, []byte("client"), []byte("server"))
	if !bytes.Equal(v.share, shareV) {
		t.Fatalf("verifier share %x", v.share)
	}
	p, err := spakeProve(w0, w1, x, ctx, []byte("client"), []byte("server"), shareV)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.share, shareP) || !bytes.Equal(p.confirm, confirmP) || !bytes.Equal(p.shared, shared) {
		t.Fatalf("prover share %x confirm %x shared %x", p.share, p.confirm, p.shared)
	}
	if !p.verify(confirmV) || p.verify(confirmP) {
		t.Fatal("the prover's check of the verifier's confirmation")
	}
	gotV, gotShared, err := v.finish(shareP, confirmP)
	if err != nil || !bytes.Equal(gotV, confirmV) || !bytes.Equal(gotShared, shared) {
		t.Fatalf("verifier confirm %x shared %x err %v", gotV, gotShared, err)
	}
	if _, _, err := v.finish(shareP, confirmV); !errors.Is(err, ErrTPAPAuth) {
		t.Fatalf("a wrong confirmation: %v", err)
	}
}

// The prover refuses a share off the curve and one that cancels the
// password (w0*N).
//
// Covers: SIG-IMP-179
func TestSPAKE2PlusBadShares(t *testing.T) {
	w0, w1 := tpapW(TPAPPasscodeSHA1("demo"), make([]byte, 16), 1)
	off := append([]byte{4}, bytes.Repeat([]byte{1}, 64)...)
	if _, err := spakeProve(w0, w1, big.NewInt(7), nil, nil, nil, off); err == nil {
		t.Error("a share off the curve was taken")
	}
	nx, ny := p256.ScalarMult(spakeN.x, spakeN.y, scalarBytes(w0))
	if _, err := spakeProve(w0, w1, big.NewInt(7), nil, nil, nil, encodePoint(point{nx, ny})); err == nil {
		t.Error("a share that cancels the password was taken")
	}
}

// The passcode forms and the PBKDF2 split, checked against the values the
// tapo crate 0.11.1's unit tests give (MIT).
//
// Covers: SIG-IMP-179
func TestTPAPPasscodeAndW(t *testing.T) {
	sha := TPAPPasscodeSHA1("hunter2")
	if sha != "f3bbbd66a63d4bf1747940578ec3d0103530e21d" {
		t.Errorf("sha1 %s", sha)
	}
	pc, err := TPAPPasscode("hunter2", map[string]any{"type": "password_shadow", "params": map[string]any{"passwd_id": 2.0}}, false)
	if err != nil || pc != sha {
		t.Errorf("password_shadow 2: %q %v", pc, err)
	}
	pc, err = TPAPPasscode("hunter2", nil, true)
	if err != nil || pc != "2ab96390c7dbe3439de74d0c9b0b1767" {
		t.Errorf("camera: %q %v", pc, err)
	}
	if _, err := TPAPPasscode("hunter2", nil, false); !errors.Is(err, ErrTPAPUnsupported) {
		t.Errorf("no extra_crypt on a plug: %v", err)
	}
	if _, err := TPAPPasscode("hunter2", map[string]any{"type": "password_shadow", "params": map[string]any{"passwd_id": 5.0}}, false); !errors.Is(err, ErrTPAPUnsupported) || !strings.Contains(err.Error(), "passwd_id") {
		t.Errorf("passwd_id 5: %v", err)
	}
	w0, w1 := tpapW(sha, []byte("0123456789abcdef"), 3000)
	if got := hex.EncodeToString(scalarBytes(w0)); got != "f01588c03f935783a7c530a83ab1ade1a3261b13005521b6946dc5c7ad259f2c" {
		t.Errorf("w0 %s", got)
	}
	if got := hex.EncodeToString(scalarBytes(w1)); got != "de9bd4a17ba3b23e2a26fbf5ae94010c68f5e0e34388fe6ec227fcb45bd0b42e" {
		t.Errorf("w1 %s", got)
	}
}

// The session cipher: a known answer from the tapo crate 0.11.1's unit
// tests (MIT), the round trip, and answers under another sequence number
// or too short refused.
//
// Covers: SIG-IMP-179
func TestTPAPCipher(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := NewTPAPCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"method":"get_device_info"}`)
	body := c.Seal(0x01020304, msg)
	if got := hex.EncodeToString(body); got != "01020304c0331c1c36a5df4ce0c68e5a27b2667ebf842dc994a3fd24b9e860a60fab76d4b66b9b669d95cca10c012f13" {
		t.Fatalf("sealed %s", got)
	}
	if p, err := c.Open(0x01020304, body); err != nil || !bytes.Equal(p, msg) {
		t.Fatalf("open %q %v", p, err)
	}
	if _, err := c.Open(0x01020305, body); err == nil {
		t.Error("an answer under another sequence number was taken")
	}
	if _, err := c.Open(0, make([]byte, 19)); err == nil {
		t.Error("a short answer was taken")
	}
	body[10] ^= 1
	if _, err := c.Open(0x01020304, body); err == nil {
		t.Error("a changed answer was taken")
	}
}

// The tpap object of discovery: the URL, the passcode type, and devices in
// KLAP mode, locked or on older firmware.
//
// Covers: SIG-IMP-179
func TestTPAPInfo(t *testing.T) {
	cases := []struct {
		tpap      map[string]any
		host, url string
	}{
		{map[string]any{"tls": 0.0, "dac": 0.0, "noc": 0.0, "pake": []any{2.0}, "port": 80.0}, "192.168.1.100", "http://192.168.1.100:80"},
		{map[string]any{"tls": 0.0, "pake": []any{2.0}}, "192.168.1.100", "http://192.168.1.100:80"},
		{map[string]any{"tls": 0.0, "pake": []any{2.0}, "port": 8080.0}, "192.168.1.100", "http://192.168.1.100:8080"},
		{map[string]any{"tls": 0.0, "pake": []any{2.0}, "port": 80.0}, "192.168.1.100:8080", "http://192.168.1.100:8080"},
		{map[string]any{"tls": 0.0, "pake": []any{2.0}, "port": 80.0}, "[::1]:8080", "http://[::1]:8080"},
		{map[string]any{"tls": 0.0, "pake": []any{2.0}}, "::1", "http://[::1]:80"},
		{map[string]any{"noc": 1.0, "pake": []any{2.0}, "port": 443.0, "tls": 1.0}, "192.168.1.100", "https://192.168.1.100:443"},
		{map[string]any{"tls": 2.0, "pake": []any{2.0}, "port": 4433.0}, "192.168.1.100", "https://192.168.1.100:4433"},
	}
	for _, c := range cases {
		info, err := ParseTPAPInfo(c.tpap)
		if err != nil {
			t.Fatalf("%v: %v", c.tpap, err)
		}
		if got := info.BaseURL(c.host); got != c.url {
			t.Errorf("%v at %s: %s, want %s", c.tpap, c.host, got, c.url)
		}
		if pt, err := info.PasscodeType(); pt != "userpw" || err != nil {
			t.Errorf("%v: passcode type %q %v", c.tpap, pt, err)
		}
	}
	if _, err := ParseTPAPInfo(map[string]any{"pake": "2"}); err == nil {
		t.Error("an unreadable tpap object was taken")
	}
	for _, pake := range []any{[]any{0.0}, []any{1.0}, []any{}} {
		info, _ := ParseTPAPInfo(map[string]any{"tls": 0.0, "pake": pake})
		if _, err := info.PasscodeType(); !errors.Is(err, ErrTPAPUnsupported) {
			t.Errorf("pake %v: %v", pake, err)
		}
	}
	// The account password is offered whenever the device lists it, also
	// next to the default passcode.
	info, _ := ParseTPAPInfo(map[string]any{"tls": 0.0, "pake": []any{0.0, 2.0}})
	if pt, err := info.PasscodeType(); pt != "userpw" || err != nil {
		t.Errorf("pake [0 2]: %q %v", pt, err)
	}

	answers := []struct {
		body   string
		status int
		tpap   bool
		err    error
	}{
		{`{"result":{"sub_method":"discover","tpap_preferred":true,"mac":"AABBCCDDEEFF","tpap":{"tls":0,"dac":0,"noc":0,"pake":[2],"port":80}},"error_code":0}`, 200, true, nil},
		{`{"result":{"sub_method":"discover","tpap_preferred":false},"error_code":0}`, 200, false, nil},
		{`{"error_code":1003}`, 200, false, nil},
		{`{"error_code":-2101}`, 200, false, ErrTPAPLocked},
		{`not json`, 200, false, nil},
		{``, 404, false, nil},
	}
	for _, a := range answers {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &got)
			w.WriteHeader(a.status)
			_, _ = w.Write([]byte(a.body))
		}))
		info, err := TPAPDiscover(context.Background(), srv.Client(), srv.URL)
		srv.Close()
		if (info != nil) != a.tpap || !errors.Is(err, a.err) {
			t.Errorf("%s: info %v err %v", a.body, info, err)
		}
		if p, _ := got["params"].(map[string]any); got["method"] != "login" || p["sub_method"] != "discover" {
			t.Errorf("discover request %v", got)
		}
	}
}

// A 20002 answer of a device in TPAP mode (as an L930 announces it, per the
// tapo crate), a camera with a tpap object, and one in KLAP mode.
//
// Covers: SIG-IMP-179
func TestTapoAnswerTPAP(t *testing.T) {
	parse := func(result map[string]any) TapoFound {
		b, _ := json.Marshal(map[string]any{"error_code": 0, "result": result})
		f, err := ParseTapoAnswer(append(make([]byte, 16), b...))
		if err != nil {
			t.Fatal(err)
		}
		f.Host = "192.168.1.30"
		return f
	}
	f := parse(map[string]any{"device_type": "SMART.TAPOBULB", "device_model": "L930-5(EU)", "mac": "3C-52-A1-00-00-10",
		"mgt_encrypt_schm": map[string]any{"encrypt_type": "TPAP", "is_support_https": false},
		"tpap":             map[string]any{"tls": 0, "dac": 0, "noc": 0, "pake": []any{2}, "port": 80}})
	if f.Protocol() != "tpap" || f.TPAP == nil || f.BaseURL() != "http://192.168.1.30:80" {
		t.Errorf("TPAP mode: %q %+v %s", f.Protocol(), f.TPAP, f.BaseURL())
	}
	// A camera keeps its HTTPS protocol and carries the tpap object.
	f = parse(map[string]any{"device_type": "SMART.IPCAMERA", "device_model": "C220", "mac": "00-31-92-00-00-11",
		"mgt_encrypt_schm": map[string]any{"is_support_https": true, "lv": 3}, "tpap": map[string]any{"noc": 1, "pake": []any{2}, "port": 443, "tls": 1}})
	if f.Protocol() != "aes" || f.TPAP == nil || f.TPAP.BaseURL(f.Host) != "https://192.168.1.30:443" {
		t.Errorf("camera: %q %+v", f.Protocol(), f.TPAP)
	}
	f = parse(map[string]any{"device_type": "SMART.TAPOPLUG", "device_model": "P110", "mgt_encrypt_schm": map[string]any{"encrypt_type": "KLAP"}})
	if f.Protocol() != "klap" || f.TPAP != nil {
		t.Errorf("KLAP mode: %q %+v", f.Protocol(), f.TPAP)
	}
	// TPAP named without the object says nothing usable.
	f = parse(map[string]any{"device_type": "SMART.TAPOBULB", "mgt_encrypt_schm": map[string]any{"encrypt_type": "TPAP"}})
	if f.Protocol() != "" {
		t.Errorf("TPAP without the object: %q", f.Protocol())
	}
}

// fakeTPAP is a minimal device for the client tests here; the full one is
// in tplink-sim.
type fakeTPAP struct {
	mu       sync.Mutex
	passcode string
	camera   bool
	salt     []byte
	iter     int
	pending  *TPAPVerifier
	sessions map[string]*TPAPCipher
	seen     []map[string]any
	n        int
}

func (f *fakeTPAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if stok, ok := strings.CutPrefix(r.URL.Path, "/stok="); ok {
		c := f.sessions[strings.TrimSuffix(stok, "/ds")]
		if c == nil || len(b) < 4 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		seq := int32(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
		p, err := c.Open(seq, b)
		if err != nil {
			_, _ = w.Write([]byte(`{"error_code":-2402}`))
			return
		}
		var req map[string]any
		_ = json.Unmarshal(p, &req)
		f.seen = append(f.seen, req)
		out, _ := json.Marshal(map[string]any{"error_code": 0, "result": map[string]any{"method": req["method"], "seq": seq}})
		_, _ = w.Write(c.Seal(seq, out))
		return
	}
	var req struct {
		Params map[string]any `json:"params"`
	}
	_ = json.Unmarshal(b, &req)
	f.seen = append(f.seen, req.Params)
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch req.Params["sub_method"] {
	case "pake_register":
		ur, _ := base64.StdEncoding.DecodeString(str(req.Params["user_random"]))
		dr := bytes.Repeat([]byte{9}, 32)
		v, err := NewTPAPVerifier(f.passcode, f.salt, f.iter, ur, dr)
		if err != nil {
			reply(map[string]any{"error_code": -1})
			return
		}
		f.pending = v
		res := map[string]any{"dev_random": base64.StdEncoding.EncodeToString(dr), "dev_salt": base64.StdEncoding.EncodeToString(f.salt),
			"dev_share": base64.StdEncoding.EncodeToString(v.Share()), "cipher_suites": 1, "iterations": f.iter, "encryption": "aes_128_ccm"}
		if !f.camera {
			res["extra_crypt"] = map[string]any{"type": "password_shadow", "params": map[string]any{"passwd_id": 2}}
		}
		reply(map[string]any{"error_code": 0, "result": res})
	case "pake_share":
		us, _ := base64.StdEncoding.DecodeString(str(req.Params["user_share"]))
		uc, _ := base64.StdEncoding.DecodeString(str(req.Params["user_confirm"]))
		dc, key, err := f.pending.Finish(us, uc)
		if err != nil {
			code := -2203
			if f.camera {
				code = -40401
			}
			reply(map[string]any{"error_code": code})
			return
		}
		c, _ := NewTPAPCipher(key)
		f.n++
		stok := "STOK" + string(rune('A'+f.n))
		f.sessions[stok] = c
		reply(map[string]any{"error_code": 0, "result": map[string]any{"dev_confirm": base64.StdEncoding.EncodeToString(dc), "stok": stok, "start_seq": 41}})
	default:
		reply(map[string]any{"error_code": -1003})
	}
}

// The client against the minimal device: the login, requests, a session
// the device forgot, and a wrong password.
//
// Covers: SIG-IMP-179
func TestTPAPClient(t *testing.T) {
	for _, camera := range []bool{false, true} {
		pc, _ := TPAPPasscode("demo-password", nil, true)
		if !camera {
			pc = TPAPPasscodeSHA1("demo-password")
		}
		f := &fakeTPAP{passcode: pc, camera: camera, salt: []byte("0123456789abcdef"), iter: 1000, sessions: map[string]*TPAPCipher{}}
		srv := httptest.NewServer(f)
		c := &TPAPClient{Base: srv.URL, Password: "demo-password", Camera: camera, HTTP: srv.Client()}
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			res, err := c.Call(ctx, "get_device_info", nil)
			if err != nil || res["method"] != "get_device_info" || res["seq"] != float64(41+i) {
				t.Fatalf("camera %v call %d: %v %v", camera, i, res, err)
			}
		}
		f.mu.Lock()
		reg := f.seen[0]
		f.sessions = map[string]*TPAPCipher{} // a reboot
		f.mu.Unlock()
		if reg["username"] != "21232f297a57a5a743894a0e4a801fc3" || reg["passcode_type"] != "userpw" || len(reg["cipher_suites"].([]any)) != 1 {
			t.Errorf("pake_register %v", reg)
		}
		if _, err := c.Call(ctx, "get_device_info", nil); err != nil {
			t.Fatalf("camera %v after a reboot: %v", camera, err)
		}
		bad := &TPAPClient{Base: srv.URL, Password: "wrong", Camera: camera, HTTP: srv.Client()}
		if err := bad.Handshake(ctx); !errors.Is(err, ErrTPAPAuth) {
			t.Errorf("camera %v wrong password: %v", camera, err)
		}
		srv.Close()
	}
}

// A device that answers pake_share without knowing the password is caught
// by its confirmation.
//
// Covers: SIG-IMP-179
func TestTPAPClientDeviceProof(t *testing.T) {
	f := &fakeTPAP{passcode: TPAPPasscodeSHA1("other"), salt: []byte("salt"), iter: 10, sessions: map[string]*TPAPCipher{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if bytes.Contains(b, []byte("pake_share")) {
			_ = json.NewEncoder(w).Encode(map[string]any{"error_code": 0, "result": map[string]any{"dev_confirm": base64.StdEncoding.EncodeToString(make([]byte, 32)), "stok": "X", "start_seq": 1}})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	c := &TPAPClient{Base: srv.URL, Password: "demo", HTTP: &http.Client{Timeout: 5 * time.Second}}
	if err := c.Handshake(context.Background()); !errors.Is(err, ErrTPAPDeviceProof) {
		t.Fatalf("%v", err)
	}
}
