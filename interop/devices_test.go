// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cB-Sigma/tplink"
)

// kasaDevice starts the peer in legacy mode with a fixture and returns a
// KasaDevice for it.
func kasaDevice(t *testing.T, fixture string) (*tplink.KasaDevice, map[string]any, *peer) {
	t.Helper()
	tcp, udp := freePort(t), freeUDPPort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:9999/tcp", tcp), "-p", fmt.Sprintf("127.0.0.1:%d:9999/udp", udp),
		image, "python", "-u", "device.py", "xor", fixture)
	p.expect(60*time.Second, "ready")
	c := tplink.KasaConn{Addr: fmt.Sprintf("127.0.0.1:%d", tcp), Timeout: 3 * time.Second}
	var d *tplink.KasaDevice
	var info map[string]any
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if d, info, err = tplink.NewKasaDevice(ctx, c); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return d, info, p
}

// The typed Kasa helpers read python-kasa's recorded answers: the older
// energy meter units, a dimmer's parameters, a bulb's cloud and firmware
// answers, a light strip's module names and a module the device lacks.
func TestKasaHelpersAgainstFixtures(t *testing.T) {
	needDocker(t)
	t.Run("HS110 older energy meter", func(t *testing.T) {
		d, _, _ := kasaDevice(t, "HS110(EU)_1.0_1.2.5.json")
		e, err := d.Emeter(ctx)
		// The fixture records V, A, W and kWh: 231.067823 V, 55.139 kWh.
		if err != nil || int(e.VoltageMV) != 231067 || int(e.TotalWh) != 55139 || d.Bulb {
			t.Errorf("emeter %+v %v", e, err)
		}
	})
	t.Run("HS220 dimmer", func(t *testing.T) {
		d, _, _ := kasaDevice(t, "HS220(US)_1.0_1.5.7.json")
		p, err := d.DimmerParameters(ctx)
		if err != nil || p["fadeOnTime"] != 1000.0 {
			t.Errorf("dimmer %v %v", p, err)
		}
		if _, err := d.Emeter(ctx); !tplink.IsKasaUnsupported(err) {
			t.Errorf("a dimmer without an energy meter: %v", err)
		}
	})
	t.Run("KL130 bulb cloud", func(t *testing.T) {
		d, _, _ := kasaDevice(t, "KL130(EU)_1.0_1.8.8.json")
		if !d.Bulb || d.LightStrip {
			t.Fatalf("kind %+v", d)
		}
		ci, err := d.CloudInfo(ctx)
		if err != nil || ci["binded"] != 1.0 {
			t.Errorf("cloud %v %v", ci, err)
		}
		if _, err := d.FirmwareList(ctx); err != nil {
			t.Errorf("firmware list %v", err)
		}
		ls, err := d.LightState(ctx)
		if err != nil || ls["on_off"] == nil {
			t.Errorf("light state %v %v", ls, err)
		}
	})
	t.Run("KL430 light strip", func(t *testing.T) {
		d, _, _ := kasaDevice(t, "KL430(US)_2.0_1.0.11.json")
		if !d.Bulb || !d.LightStrip {
			t.Fatalf("kind %+v", d)
		}
		e, err := d.Emeter(ctx) // smartlife.iot.common.emeter on bulbs
		if err != nil || e.PowerMW != 600 {
			t.Errorf("emeter %+v %v", e, err)
		}
		if ls, err := d.LightState(ctx); err != nil || ls["on_off"] == nil {
			t.Errorf("light state %v %v", ls, err)
		}
		if ld, err := d.LightDetails(ctx); err != nil || len(ld) == 0 {
			t.Errorf("light details %v %v", ld, err)
		}
		if _, err := d.Rules(ctx, tplink.KasaSchedule); err != nil { // smartlife.iot.common.schedule
			t.Errorf("schedule %v", err)
		}
		if _, err := d.NextAction(ctx); err != nil {
			t.Errorf("next action %v", err)
		}
	})
}

func klapDevice(t *testing.T, fixture string) (tplink.TapoDevice, *tplink.KLAPClient, *peer) {
	t.Helper()
	base, p := httpDevice(t, "klap2", fixture, user, pass)
	c := &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(user, pass), HTTP: &http.Client{Timeout: 5 * time.Second}}
	return tplink.TapoDevice{Caller: c}, c, p
}

// Batching, components and the typed Tapo helpers against python-kasa's
// recorded P110 answers.
func TestTapoPlugHelpersAgainstFixture(t *testing.T) {
	needDocker(t)
	d, c, p := klapDevice(t, "P110(AU)_1.0_1.3.1.json")
	res, err := tplink.MultiCall(ctx, c, []tplink.SmartRequest{{Method: "get_device_info"}, {Method: "get_energy_usage"}, {Method: "no_such_method"},
		{Method: "get_led_info"}, {Method: "get_auto_off_config"}, {Method: "get_device_usage"}}, 0)
	if err != nil || len(res) != 6 || res[0].Result["model"] != "P110" || !tplink.IsUnsupported(res[2].Err) || res[5].Err != nil {
		t.Fatalf("multi %+v %v", res, err)
	}
	p.expect(5*time.Second, "request", "multipleRequest")
	comp, err := tplink.Components(ctx, d)
	if err != nil || comp["energy_monitoring"] != 2 || comp["auto_off"] != 2 {
		t.Errorf("components %v %v", comp, err)
	}
	info, err := d.Info(ctx)
	if err != nil || info.Nickname != "#MASKED_NAME#" || info.FWVersion != "1.3.1 Build 240621 Rel.162048" {
		t.Errorf("info %+v %v", info, err)
	}
	if e, err := d.Emeter(ctx); err != nil || e.VoltageMV != 238609 {
		t.Errorf("emeter %+v %v", e, err)
	}
	if u, err := d.EnergyUsage(ctx); err != nil || u.MonthEnergy != 4 || u.MonthRuntime != 10 {
		t.Errorf("energy usage %+v %v", u, err)
	}
	if u, err := d.Usage(ctx); err != nil || u.Power.Past30 != 11 || u.Saved.Past7 != 8 {
		t.Errorf("device usage %+v %v", u, err)
	}
	if fw, err := d.LatestFirmware(ctx); err != nil || fw.Available() || fw.Version == "" {
		t.Errorf("latest firmware %+v %v", fw, err)
	}
	if st, err := d.FirmwareState(ctx); err != nil || st.Status != 0 || st.UpgradeTime != 5 {
		t.Errorf("firmware state %+v %v", st, err)
	}
	if au, err := d.AutoUpdate(ctx); err != nil || !au.Enable || au.Time != 180 {
		t.Errorf("auto update %+v %v", au, err)
	}
	if ao, err := d.AutoOff(ctx); err != nil || ao.DelayMin != 120 {
		t.Errorf("auto off %+v %v", ao, err)
	}
	if r, err := d.Rules(ctx, tplink.TapoSchedule); err != nil || r.Max != 32 {
		t.Errorf("schedule %+v %v", r, err)
	}
	if r, err := d.Rules(ctx, tplink.TapoCountdown); err != nil || r.Max != 1 {
		t.Errorf("countdown %+v %v", r, err)
	}
	nets, err := d.WifiScan(ctx)
	if err != nil || len(nets) != 3 || nets[0].SSID != "#MASKED_SSID#" || nets[0].KeyType != "wpa2_psk" {
		t.Errorf("scan %+v %v", nets, err)
	}
	if err := d.SetAutoOff(ctx, tplink.TapoAutoOff{Enable: true, DelayMin: 30}); err != nil {
		t.Fatal(err)
	}
	if ev := event(t, p.expect(5*time.Second, "request", "set_auto_off_config")); ev["params"].(map[string]any)["delay_min"] != 30.0 {
		t.Errorf("the device decoded %v", ev)
	}
}

// Light helpers against recorded L530E (transitions version 3, light
// effects, presets) and L900 (light strip effect) answers.
func TestTapoLightHelpersAgainstFixtures(t *testing.T) {
	needDocker(t)
	t.Run("L530E", func(t *testing.T) {
		d, _, _ := klapDevice(t, "L530E(EU)_3.0_1.1.6.json")
		tr, err := d.Transitions(ctx)
		if on, _ := tr["on_state"].(map[string]any); err != nil || on["max_duration"] != 60.0 {
			t.Errorf("transitions %v %v", tr, err)
		}
		ef, err := d.DynamicEffects(ctx)
		if err != nil || len(ef.Rules) != 2 || ef.Max != 2 || ef.Rules[0]["id"] != "L1" {
			t.Errorf("effects %+v %v", ef, err)
		}
		ps, err := d.Presets(ctx)
		if err != nil || len(ps) < 4 {
			t.Errorf("presets %v %v", ps, err)
		}
	})
	t.Run("L900", func(t *testing.T) {
		d, _, _ := klapDevice(t, "L900-5(EU)_1.0_1.1.0.json")
		ef, err := d.LightingEffect(ctx)
		if err != nil || ef["name"] != "station" {
			t.Errorf("effect %v %v", ef, err)
		}
		ps, err := d.Presets(ctx) // sum 7 with 4 recorded: the pages end at an empty page
		if err != nil || len(ps) != 4 {
			t.Errorf("presets %d %v", len(ps), err)
		}
	})
}

// A hub's children and their components, typed, against a recorded H100.
func TestTapoHubHelpersAgainstFixture(t *testing.T) {
	needDocker(t)
	d, _, _ := klapDevice(t, "H100(EU)_1.0_1.5.5.json")
	kids, err := d.Children(ctx)
	if err != nil || len(kids) != 1 || kids[0].Model != "T315" || kids[0].Temp == nil || *kids[0].Temp != 22.2 || *kids[0].Humidity != 56 || *kids[0].Battery != 100 {
		t.Fatalf("children %+v %v", kids, err)
	}
	cc, err := tplink.ChildComponents(ctx, d)
	if err != nil || cc[kids[0].DeviceID]["temp_humidity_record"] != 1 {
		t.Errorf("child components %v %v", cc, err)
	}
}

// The 20002 answer's encrypted part, sealed the way python-kasa reads it
// (the peer checks with python-kasa's own decryption first), decrypted by
// TapoDiscover.
func TestTapoDiscoveryDecryptsAgainstKasa(t *testing.T) {
	needDocker(t)
	udp := freeUDPPort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:20002/udp", udp), image, "python", "-u", "device.py", "tdp", "enc:P110(UK)_1.0_1.3.0.json")
	if ev := event(t, p.expect(60*time.Second, "seal-check")); ev["ok"] != true {
		t.Fatalf("python-kasa did not read the peer's encrypt_info: %v", ev)
	}
	p.expect(10*time.Second, "ready")
	found, err := tplink.TapoDiscover(ctx, fmt.Sprintf("127.0.0.1:%d", udp), 3*time.Second)
	if err != nil || len(found) != 1 || found[0].Decrypted["connect_ssid"] != "Demo-Home" || found[0].Protocol() != "klap" {
		t.Errorf("found %+v %v", found, err)
	}
}
