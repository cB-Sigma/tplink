// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cB-Sigma/tplink"
)

// httpsDevice starts the peer in an HTTPS mode (port 443, self-signed)
// and returns its base URL.
func httpsDevice(t *testing.T, args ...string) (string, *peer) {
	t.Helper()
	port := freePort(t)
	p := startPeer(t, append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:443", port), image, "python", "-u", "device.py"}, args...)...)
	p.expect(60*time.Second, "ready")
	base := fmt.Sprintf("https://127.0.0.1:%d", port)
	hc := tplink.InsecureHTTP(2 * time.Second)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if r, err := hc.Get(base + "/"); err == nil {
			r.Body.Close()
			break
		}
	}
	return base, p
}

// The camera transport against a device whose login, keys and tags are
// computed with python-kasa's SslAesTransport functions, answering from
// a recorded C210 camera: device information, a setting read and
// changed, signed requests in sequence, a wrong password.
func TestCameraTransportAgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpsDevice(t, "sslaes", "C210(EU)_2.0_1.4.3.json", "admin", "camera-pass")
	c := &tplink.SSLAESClient{Base: base, Username: "admin", Password: "camera-pass", HTTP: tplink.InsecureHTTP(5 * time.Second)}
	info, err := tplink.CamDeviceInfo(ctx, c)
	if err != nil || info["device_model"] != "C210" || info["device_type"] != "SMART.IPCAMERA" {
		t.Fatalf("device info %v %v", info, err)
	}
	if ev := event(t, p.expect(5*time.Second, "login", `"step": 2`)); ev["ok"] != true {
		t.Errorf("login %v", ev)
	}
	lm := map[string]any{"lens_mask": map[string]any{"name": []any{"lens_mask_info"}}}
	res, err := tplink.CamGet(ctx, c, "getLensMaskConfig", lm)
	if err != nil || res["lens_mask"].(map[string]any)["lens_mask_info"].(map[string]any)["enabled"] != "on" {
		t.Errorf("lens mask %v %v", res, err)
	}
	if _, err := tplink.CamGet(ctx, c, "setLensMaskConfig", map[string]any{"lens_mask": map[string]any{"lens_mask_info": map[string]any{"enabled": "off"}}}); err != nil {
		t.Fatal(err)
	}
	res, _ = tplink.CamGet(ctx, c, "getLensMaskConfig", lm)
	if res["lens_mask"].(map[string]any)["lens_mask_info"].(map[string]any)["enabled"] != "off" {
		t.Errorf("after set %v", res)
	}
	if _, err := tplink.CamGet(ctx, c, "getNoSuchConfig", map[string]any{"x": map[string]any{}}); !tplink.IsUnsupported(err) {
		t.Errorf("unknown method %v", err)
	}
	for i := 0; i < 4; i++ {
		if ev := event(t, p.expect(5*time.Second, "tag")); ev["ok"] != true {
			t.Fatalf("python-kasa's tag check failed: %v", ev)
		}
	}
	wrong := &tplink.SSLAESClient{Base: base, Username: "admin", Password: "other", HTTP: tplink.InsecureHTTP(5 * time.Second)}
	if err := wrong.Handshake(ctx); !errors.Is(err, tplink.ErrKLAPAuth) {
		t.Errorf("wrong password: %v", err)
	}
}

// An H200 hub on the camera transport: its recorded children.
func TestH200AgainstKasa(t *testing.T) {
	needDocker(t)
	base, _ := httpsDevice(t, "sslaes", "H200(EU)_1.0_1.3.6.json", "admin", "hub-pass")
	c := &tplink.SSLAESClient{Base: base, Username: "admin", Password: "hub-pass", HTTP: tplink.InsecureHTTP(5 * time.Second)}
	info, err := tplink.CamDeviceInfo(ctx, c)
	if err != nil || info["device_model"] != "H200" {
		t.Fatalf("device info %v %v", info, err)
	}
	kids, err := tplink.CamChildList(ctx, c)
	if err != nil || len(kids) == 0 || kids[0]["device_id"] != "SCRUBBED_CHILD_DEVICE_ID_1" {
		t.Errorf("children %d %v", len(kids), err)
	}
}

// KLAP v2 over HTTPS, with python-kasa's KLAP functions, against a P110.
func TestKLAPOverHTTPSAgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpsDevice(t, "klap2-https", "P110(UK)_1.0_1.3.0.json", user, pass)
	c := &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(user, pass), HTTP: tplink.InsecureHTTP(5 * time.Second)}
	info, err := c.Call(ctx, "get_device_info", nil)
	if err != nil || info["model"] != "P110" {
		t.Fatalf("get_device_info %v %v", info, err)
	}
	p.expect(5*time.Second, "handshake2")
	plain := &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(user, pass), HTTP: &http.Client{Timeout: 3 * time.Second}}
	if _, err := plain.Call(ctx, "get_device_info", nil); err == nil {
		t.Error("a client that checks certificates accepted the self-signed one")
	}
}

// The Kasa camera transport against a device that obscures with
// python-kasa's XorEncryption, answering from a recorded EC60 camera.
func TestLinkieAgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpsDevice(t, "linkie", "EC60(US)_4.0_2.3.22.json", "cam-user", "cam-pass")
	d, info, err := tplink.NewKasaDevice(ctx, &tplink.LinkieClient{Base: base, Username: "cam-user", Password: "cam-pass", HTTP: tplink.InsecureHTTP(5 * time.Second)})
	if err != nil || info["model"] != "EC60(US)" {
		t.Fatalf("sysinfo %v %v", info, err)
	}
	p.expect(5*time.Second, "request", "get_sysinfo")
	// The camera nests its sysinfo under "system" (read unnested), and its
	// recording refuses the light service with a module error.
	var me *tplink.KasaModuleError
	if _, err := d.LightState(ctx); !errors.As(err, &me) || me.Code != -10008 || d.Bulb || info["type"] != "IOT.IPCAMERA" {
		t.Errorf("light state %v, device %+v", err, d)
	}
	wrong := &tplink.LinkieClient{Base: base, Username: "cam-user", Password: "other", HTTP: tplink.InsecureHTTP(5 * time.Second)}
	if _, err := wrong.KasaCall(ctx, map[string]any{"system": map[string]any{"get_sysinfo": map[string]any{}}}); !errors.Is(err, tplink.ErrKLAPAuth) {
		t.Errorf("wrong password %v", err)
	}
}

// The plain HTTPS transport, the login checked with python-kasa's
// hashing, against a recorded RV30 robot vacuum.
func TestPlainHTTPSAgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpsDevice(t, "ssl", "RV30 Max(US)_1.0_1.2.0.json", user, pass)
	d := tplink.TapoDevice{Caller: &tplink.SSLClient{Base: base, Username: user, Password: pass, HTTP: tplink.InsecureHTTP(5 * time.Second)}}
	info, err := d.Info(ctx)
	if err != nil || info.Model != "RV30 Max" {
		t.Fatalf("info %+v %v", info, err)
	}
	if ev := event(t, p.expect(5*time.Second, "login")); ev["ok"] != true {
		t.Errorf("login %v", ev)
	}
	wrong := &tplink.SSLClient{Base: base, Username: user, Password: "other", HTTP: tplink.InsecureHTTP(5 * time.Second)}
	if _, err := wrong.Call(ctx, "get_device_info", nil); !errors.Is(err, tplink.ErrKLAPAuth) {
		t.Errorf("wrong password %v", err)
	}
}
