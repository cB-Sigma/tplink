// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop checks the tplink clients against a device that answers
// from python-kasa's recorded fixtures and encrypts with python-kasa's own
// transport code (peer/device.py), in a container: the legacy protocol,
// KLAP v1 and v2, securePassthrough with both login versions, a strip's
// children and the 20002 discovery. The tests need Docker and are skipped
// unless SIGMA_TPLINK_INTEROP=1.
package interop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/tplink"
)

var ctx = context.Background()

const (
	user = "demo@example.invalid"
	pass = "demo-tapo-password"
)

// event splits a peer line "<name> <json>" and decodes the JSON.
func event(t *testing.T, line string) map[string]any {
	t.Helper()
	_, js, _ := strings.Cut(line, " ")
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		t.Fatalf("peer line %q: %v", line, err)
	}
	return m
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// httpDevice starts the peer in an HTTP mode and returns its base URL.
func httpDevice(t *testing.T, args ...string) (string, *peer) {
	t.Helper()
	port := freePort(t)
	p := startPeer(t, append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:80", port), image, "python", "-u", "device.py"}, args...)...)
	p.expect(60*time.Second, "ready")
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	// The published port takes connections before the server listens.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if r, err := http.Get(base + "/"); err == nil {
			r.Body.Close()
			break
		}
	}
	return base, p
}

// The legacy protocol on TCP and UDP 9999, against an HS110 fixture.
func TestLegacyAgainstKasaFixture(t *testing.T) {
	needDocker(t)
	tcp, udp := freePort(t), freeUDPPort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:9999/tcp", tcp), "-p", fmt.Sprintf("127.0.0.1:%d:9999/udp", udp),
		image, "python", "-u", "device.py", "xor", "HS110(EU)_1.0_1.2.5.json")
	p.expect(60*time.Second, "ready")
	addr := fmt.Sprintf("127.0.0.1:%d", tcp)
	var m map[string]any
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if m, err = tplink.KasaRequest(ctx, addr, map[string]any{"system": map[string]any{"get_sysinfo": map[string]any{}}}, 3*time.Second); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	info := m["system"].(map[string]any)["get_sysinfo"].(map[string]any)
	if info["model"] != "HS110(EU)" {
		t.Errorf("sysinfo %v", info)
	}
	m, err = tplink.KasaRequest(ctx, addr, map[string]any{"system": map[string]any{"set_relay_state": map[string]any{"state": 1}}}, 3*time.Second)
	if err != nil || tplink.KasaError(m) != nil {
		t.Errorf("set_relay_state %v %v", m, err)
	}
	if req := event(t, p.expect(5*time.Second, "request", "set_relay_state")); req["system"].(map[string]any)["set_relay_state"].(map[string]any)["state"] != 1.0 {
		t.Errorf("the device decoded %v", req)
	}
	m, err = tplink.KasaRequest(ctx, addr, map[string]any{"emeter": map[string]any{"get_realtime": map[string]any{}}}, 3*time.Second)
	if err != nil || tplink.KasaError(m) != nil || m["emeter"] == nil {
		t.Errorf("emeter %v %v", m, err)
	}
	m, _ = tplink.KasaRequest(ctx, addr, map[string]any{"system": map[string]any{"no_such": map[string]any{}}}, 3*time.Second)
	if tplink.KasaError(m) == nil {
		t.Errorf("an unknown method %v", m)
	}
	found, err := tplink.KasaDiscover(ctx, fmt.Sprintf("127.0.0.1:%d", udp), 2*time.Second)
	if err != nil || len(found) != 1 || found[0].Sysinfo["model"] != "HS110(EU)" {
		t.Errorf("discovery %+v %v", found, err)
	}
}

// KLAP v2 with Tapo requests, against a P110 fixture; a wrong password.
func TestKLAPv2AgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpDevice(t, "klap2", "P110(UK)_1.0_1.3.0.json", user, pass)
	c := &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(user, pass), HTTP: &http.Client{Timeout: 5 * time.Second}}
	info, err := c.Call(ctx, "get_device_info", nil)
	if err != nil || info["model"] != "P110" || info["device_on"] != false {
		t.Fatalf("get_device_info %v %v", info, err)
	}
	if _, err := c.Call(ctx, "set_device_info", map[string]any{"device_on": true}); err != nil {
		t.Fatal(err)
	}
	if req := event(t, p.expect(5*time.Second, "request", "set_device_info")); req["params"].(map[string]any)["device_on"] != true {
		t.Errorf("the device decoded %v", req)
	}
	for i := 0; i < 3; i++ { // the sequence moves on within the session
		if info, err = c.Call(ctx, "get_device_info", nil); err != nil || info["device_on"] != true {
			t.Fatalf("get_device_info %d: %v %v", i, info, err)
		}
	}
	if u, err := c.Call(ctx, "get_energy_usage", nil); err != nil || u["today_energy"] == nil {
		t.Errorf("get_energy_usage %v %v", u, err)
	}
	if _, err := c.Call(ctx, "no_such_method", nil); !tplink.IsUnsupported(err) {
		t.Errorf("unknown method: %v", err)
	}
	if m := c.Matched(); m.Version != 2 || m.Name != "account" || c.BadSignatures() != 0 {
		t.Errorf("matched %+v, bad signatures %d", m, c.BadSignatures())
	}
	wrong := &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(user, "other"), HTTP: &http.Client{Timeout: 5 * time.Second}}
	if err := wrong.Handshake(ctx); !errors.Is(err, tplink.ErrKLAPAuth) {
		t.Errorf("a wrong password: %v", err)
	}
}

// KLAP v1 carrying the legacy Kasa JSON, against an HS100 hardware 4.1
// fixture.
func TestKLAPv1AgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpDevice(t, "klap1", "HS100(UK)_4.1_1.1.0.json", user, pass)
	c := &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(user, pass), HTTP: &http.Client{Timeout: 5 * time.Second}}
	m, err := c.KasaCall(ctx, map[string]any{"system": map[string]any{"get_sysinfo": map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	if info := m["system"].(map[string]any)["get_sysinfo"].(map[string]any); info["model"] != "HS100(UK)" {
		t.Errorf("sysinfo %v", info)
	}
	if _, err := c.KasaCall(ctx, map[string]any{"system": map[string]any{"set_relay_state": map[string]any{"state": 1}}}); err != nil {
		t.Fatal(err)
	}
	p.expect(5*time.Second, "request", "set_relay_state")
	if m := c.Matched(); m.Version != 1 || m.Name != "account" || c.BadSignatures() != 0 {
		t.Errorf("matched %+v, bad signatures %d", m, c.BadSignatures())
	}
}

// A power strip's children, paged, and a request to one child, against a
// P300 fixture.
func TestStripChildrenAgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpDevice(t, "klap2", "P300(EU)_1.0_1.0.15.json", user, pass)
	c := &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(user, pass), HTTP: &http.Client{Timeout: 5 * time.Second}}
	kids, err := tplink.ChildList(ctx, c)
	if err != nil || len(kids) != 3 || kids[2]["device_id"] != "SCRUBBED_CHILD_DEVICE_ID_3" {
		t.Fatalf("children %d %v", len(kids), err)
	}
	if _, err := tplink.ControlChild(ctx, c, "SCRUBBED_CHILD_DEVICE_ID_2", "set_device_info", map[string]any{"device_on": false}); err != nil {
		t.Fatal(err)
	}
	p.expect(5*time.Second, "request", "control_child", "SCRUBBED_CHILD_DEVICE_ID_2")
	info, err := tplink.ControlChild(ctx, c, "SCRUBBED_CHILD_DEVICE_ID_2", "get_device_info", nil)
	if err != nil || info["device_on"] != false || info["category"] != "plug.powerstrip.sub-plug" {
		t.Errorf("child %v %v", info, err)
	}
}

// securePassthrough with login version 2 and 1, against a P100 fixture,
// the login checked with python-kasa's own hashing; a wrong password.
func TestSecurePassthroughAgainstKasa(t *testing.T) {
	needDocker(t)
	for _, lv := range []int{2, 1} {
		t.Run(fmt.Sprint("login", lv), func(t *testing.T) {
			base, p := httpDevice(t, "aes", "P100(US)_1.0.0_1.1.3.json", user, pass, fmt.Sprint(lv))
			a := &tplink.AESClient{Base: base, Logins: tplink.AESLogins(user, pass, lv), HTTP: &http.Client{Timeout: 5 * time.Second}}
			info, err := a.Call(ctx, "get_device_info", nil)
			if err != nil || info["model"] != "P100" {
				t.Fatalf("get_device_info %v %v", info, err)
			}
			if l := event(t, p.expect(5*time.Second, "login", `"ok": true`)); l["ok"] != true {
				t.Errorf("login %v", l)
			}
			if _, err := a.Call(ctx, "set_device_info", map[string]any{"device_on": true}); err != nil {
				t.Fatal(err)
			}
			if info, _ := a.Call(ctx, "get_device_info", nil); info["device_on"] != true || a.Matched() != "account" {
				t.Errorf("after set: %v matched %q", info, a.Matched())
			}
			wrong := &tplink.AESClient{Base: base, Logins: tplink.AESLogins(user, "other", lv), HTTP: &http.Client{Timeout: 5 * time.Second}}
			if _, err := wrong.Call(ctx, "get_device_info", nil); !errors.Is(err, tplink.ErrKLAPAuth) {
				t.Errorf("a wrong password: %v", err)
			}
		})
	}
}

// The 20002 probe passes python-kasa's checks; the answers recorded in
// python-kasa's fixtures are read.
func TestTapoDiscoveryAgainstKasa(t *testing.T) {
	needDocker(t)
	udp := freeUDPPort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20002/udp", udp), image, "python", "-u", "device.py", "tdp",
		"P110(UK)_1.0_1.3.0.json", "P100(US)_1.0.0_1.1.3.json", "HS100(UK)_4.1_1.1.0.json")
	kp := event(t, p.expect(60*time.Second, "kasa-probe-header"))
	p.expect(10*time.Second, "ready")
	found, err := tplink.TapoDiscover(ctx, fmt.Sprintf("127.0.0.1:%d", udp), 3*time.Second)
	if err != nil || len(found) != 3 {
		t.Fatalf("found %+v %v", found, err)
	}
	probe := event(t, p.expect(5*time.Second, "probe"))
	if probe["ok"] != true || probe["header"].(string)[:12] != kp["hex"].(string)[:12] {
		t.Errorf("our probe %v, python-kasa's header %v", probe, kp)
	}
	byMAC := map[string]tplink.TapoFound{}
	for _, f := range found {
		byMAC[f.MAC] = f
	}
	if f := byMAC["482254000000"]; f.Model != "P110" || f.Protocol() != "klap" || f.DeviceType != "SMART.TAPOPLUG" || f.LoginVersion != 2 || f.HTTPPort != 80 {
		t.Errorf("P110 %+v", f)
	}
	if f := byMAC["1c3bf3000000"]; f.Model != "P100" || f.Protocol() != "aes" {
		t.Errorf("P100 %+v", f)
	}
	if f := byMAC["cc32e5000000"]; f.Model != "HS100" || f.Protocol() != "klap" || f.DeviceType != "IOT.SMARTPLUGSWITCH" {
		t.Errorf("HS100 %+v", f)
	}
}
