// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"reflect"
	"testing"
	"time"

	"github.com/cB-Sigma/tplink"
)

// The typed camera helpers against a device answering from python-kasa's
// recorded C220(EU) 1.2.5 camera over the camera transport (python-kasa's
// SslAesTransport functions): every reading compared with the recording,
// settings changed and read back, and the motor and siren requests as the
// device received them.
func TestCameraHelpersAgainstKasa(t *testing.T) {
	needDocker(t)
	base, p := httpsDevice(t, "sslaes", "C220(EU)_1.0_1.2.5.json", "admin", "camera-pass")
	c := tplink.TapoCamera{Caller: &tplink.SSLAESClient{Base: base, Username: "admin", Password: "camera-pass", HTTP: tplink.InsecureHTTP(5 * time.Second)}}

	ci, err := c.Info(ctx)
	if err != nil || ci.Model != "C220" || ci.HWVersion != "1.0" || ci.FWVersion != "1.2.5 Build 241224 Rel.40956n" {
		t.Fatalf("info %+v %v", ci, err)
	}
	if comp, err := c.Components(ctx); err != nil || comp["ptz"] != 1 || comp["lensMask"] != 2 || len(comp) != 48 {
		t.Errorf("components %d %v", len(comp), err)
	}
	if on, err := c.LED(ctx); err != nil || on {
		t.Errorf("LED %v %v", on, err)
	}
	if on, err := c.Privacy(ctx); err != nil || on {
		t.Errorf("privacy %v %v", on, err)
	}
	want := map[tplink.CamDetectionKind][2]any{
		tplink.DetectMotion: {false, "60"}, tplink.DetectPerson: {false, "60"}, tplink.DetectBabyCry: {false, "50"},
		tplink.DetectTamper: {true, "50"}, tplink.DetectLineCrossing: {true, ""},
	}
	for kind, w := range want {
		d, err := c.Detection(ctx, kind)
		if err != nil || d.Enabled != w[0] || d.Sensitivity != w[1] {
			t.Errorf("%s: %+v %v", kind, d, err)
		}
	}
	for _, kind := range []tplink.CamDetectionKind{tplink.DetectPet, tplink.DetectVehicle, tplink.DetectBark, tplink.DetectMeow, tplink.DetectGlassBreak} {
		if _, err := c.Detection(ctx, kind); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
	if m, err := c.NightVision(ctx); err != nil || m != tplink.NightVisionInfrared {
		t.Errorf("night vision %q %v", m, err)
	}
	if la, err := c.LastAlarm(ctx); err != nil || la.Type != "motion" || la.Time.Unix() != 1750109746 {
		t.Errorf("last alarm %+v %v", la, err)
	}
	if ct, err := c.Time(ctx); err != nil || ct.ZoneID != "Europe/Amsterdam" || ct.Timezone != "UTC+01:00" || ct.Time.Unix() != 1750110420 {
		t.Errorf("time %+v %v", ct, err)
	}
	if disks, err := c.SDCards(ctx); err != nil || len(disks) != 1 || disks[0].Status != "offline" || disks[0].Name != "1" {
		t.Errorf("disks %+v %v", disks, err)
	}
	if a, err := c.Alert(ctx); err != nil || a.Enabled || !reflect.DeepEqual(a.Modes, []string{"light", "sound"}) || a.Volume != "high" {
		t.Errorf("alert %+v %v", a, err)
	}
	if conn, err := c.Connection(ctx); err != nil || conn.Link != "wifi" || conn.RSSI != -54 || conn.Level != 3 {
		t.Errorf("connection %+v %v", conn, err)
	}
	if ps, err := c.Presets(ctx); err != nil || len(ps) != 0 {
		t.Errorf("presets %+v %v", ps, err)
	}
	if nets, err := c.WifiScan(ctx); err != nil || len(nets) == 0 {
		t.Errorf("scan %+v %v", nets, err)
	}

	// Settings changed and read back.
	if err := c.SetLED(ctx, true); err != nil {
		t.Fatal(err)
	}
	if on, _ := c.LED(ctx); !on {
		t.Error("LED not on")
	}
	if err := c.SetDetection(ctx, tplink.DetectPerson, true); err != nil {
		t.Fatal(err)
	}
	if d, _ := c.Detection(ctx, tplink.DetectPerson); !d.Enabled {
		t.Error("person detection not on")
	}
	if err := c.SetNightVision(ctx, tplink.NightVisionSmart); err != nil {
		t.Fatal(err)
	}
	if m, _ := c.NightVision(ctx); m != tplink.NightVisionSmart {
		t.Errorf("night vision after %q", m)
	}

	// Acting requests, as the device received them.
	if err := c.Move(ctx, 10, -5); err != nil {
		t.Fatal(err)
	}
	ev := event(t, p.expect(5*time.Second, "camaction", "motorMove"))
	if !reflect.DeepEqual(ev["params"], map[string]any{"motor": map[string]any{"move": map[string]any{"x_coord": "10", "y_coord": "-5"}}}) {
		t.Errorf("motorMove %v", ev)
	}
	if err := c.SavePreset(ctx, "Door"); err != nil {
		t.Fatal(err)
	}
	if ev := event(t, p.expect(5*time.Second, "camaction", "addMotorPostion")); ev["params"] == nil {
		t.Errorf("addMotorPostion %v", ev)
	}
	if err := c.ManualAlarm(ctx, true); err != nil {
		t.Fatal(err)
	}
	ev = event(t, p.expect(5*time.Second, "camsingle", "msg_alarm"))
	if !reflect.DeepEqual(ev["msg_alarm"], map[string]any{"manual_msg_alarm": map[string]any{"action": "start"}}) || ev["method"] != "do" {
		t.Errorf("manual alarm %v", ev)
	}
}

// The siren of a recorded H200(EU) 1.3.6 hub (its answers carry no module
// level).
func TestSirenAgainstKasa(t *testing.T) {
	needDocker(t)
	base, _ := httpsDevice(t, "sslaes", "H200(EU)_1.0_1.3.6.json", "admin", "hub-pass")
	c := tplink.TapoCamera{Caller: &tplink.SSLAESClient{Base: base, Username: "admin", Password: "hub-pass", HTTP: tplink.InsecureHTTP(5 * time.Second)}}
	s, err := c.Siren(ctx)
	if err != nil || s.Active || s.Sound != "Doorbell Ring 3" || s.Volume != 10 || s.Duration != 30 || len(s.Sounds) != 19 {
		t.Fatalf("siren %+v %v", s, err)
	}
	if err := c.SetSiren(ctx, "Alarm 1", 5, 0); err != nil {
		t.Fatal(err)
	}
	if s, _ := c.Siren(ctx); s.Sound != "Alarm 1" || s.Volume != 5 {
		t.Errorf("siren after %+v", s)
	}
	if err := c.SoundSiren(ctx, true); err != nil {
		t.Fatal(err)
	}
}
