// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cB-Sigma/tplink"
)

var ctx = context.Background()

// fakeSmart answers Tapo requests from a function and records them.
type fakeSmart struct {
	answer func(method string, params map[string]any) (map[string]any, error)
	calls  []string
}

func (f *fakeSmart) Call(_ context.Context, method string, params any) (map[string]any, error) {
	f.calls = append(f.calls, method)
	var p map[string]any
	b, _ := json.Marshal(params)
	_ = json.Unmarshal(b, &p)
	return f.answer(method, p)
}

// multiDevice answers multipleRequest as a device does: in order, each
// with its error code, stopping at the first failing request when stop
// is set; batches larger than max are refused with -1003.
func multiDevice(stop bool, max int) *fakeSmart {
	f := &fakeSmart{}
	f.answer = func(method string, p map[string]any) (map[string]any, error) {
		one := func(m string) (map[string]any, int) {
			if m == "bad" {
				return nil, -1008
			}
			return map[string]any{"m": m}, 0
		}
		if method != "multipleRequest" {
			r, code := one(method)
			if code != 0 {
				return nil, &tplink.SmartError{Code: code, Method: method}
			}
			return r, nil
		}
		reqs, _ := p["requests"].([]any)
		if max > 0 && len(reqs) > max {
			return nil, &tplink.SmartError{Code: -1003, Method: method}
		}
		var out []any
		for _, x := range reqs {
			m := x.(map[string]any)["method"].(string)
			r, code := one(m)
			e := map[string]any{"method": m, "error_code": float64(code)}
			if r != nil {
				e["result"] = r
			}
			out = append(out, e)
			if code != 0 && stop {
				break
			}
		}
		return map[string]any{"responses": out}, nil
	}
	return f
}

func TestMultiCall(t *testing.T) {
	reqs := []tplink.SmartRequest{{Method: "a"}, {Method: "bad"}, {Method: "c", Params: map[string]any{"x": 1}}, {Method: "a"}, {Method: "e"}, {Method: "f"}}
	check := func(name string, res []tplink.SmartResult) {
		t.Helper()
		if len(res) != len(reqs) {
			t.Fatalf("%s: %d results", name, len(res))
		}
		for i, r := range res {
			if r.Method != reqs[i].Method {
				t.Errorf("%s: result %d is %s", name, i, r.Method)
			}
			if reqs[i].Method == "bad" {
				if se, ok := r.Err.(*tplink.SmartError); !ok || se.Code != -1008 {
					t.Errorf("%s: bad answered %v", name, r.Err)
				}
			} else if r.Err != nil || r.Result["m"] != reqs[i].Method {
				t.Errorf("%s: %s answered %v %v", name, reqs[i].Method, r.Result, r.Err)
			}
		}
	}
	// Batches of 5 then 1; the device stops at the failing request, so the
	// rest of the first batch is asked one by one.
	f := multiDevice(true, 0)
	res, err := tplink.MultiCall(ctx, f, reqs, 0)
	if err != nil {
		t.Fatal(err)
	}
	check("stopping device", res)
	if fmt.Sprint(f.calls) != "[multipleRequest multipleRequest c a e]" {
		t.Errorf("calls %v", f.calls)
	}
	// A device that refuses big batches is asked one by one.
	f = multiDevice(false, 2)
	res, err = tplink.MultiCall(ctx, f, reqs, 3)
	if err != nil {
		t.Fatal(err)
	}
	check("refusing device", res)
	if len(f.calls) != 1+len(reqs) {
		t.Errorf("calls %v", f.calls)
	}
}

func TestSmartListAndComponents(t *testing.T) {
	all := []any{}
	for i := 0; i < 7; i++ {
		all = append(all, map[string]any{"device_id": fmt.Sprint("c", i), "component_list": []any{map[string]any{"id": "device", "ver_code": float64(i)}}})
	}
	f := &fakeSmart{answer: func(method string, p map[string]any) (map[string]any, error) {
		switch method {
		case "component_nego":
			return map[string]any{"component_list": []any{map[string]any{"id": "energy_monitoring", "ver_code": 2.0}, map[string]any{"id": "countdown", "ver_code": 1.0}}}, nil
		case "get_child_device_component_list":
			s := int(p["start_index"].(float64))
			return map[string]any{"child_component_list": all[s:min(s+3, len(all))], "start_index": float64(s), "sum": float64(len(all))}, nil
		}
		return nil, &tplink.SmartError{Code: -1002, Method: method}
	}}
	comp, err := tplink.Components(ctx, f)
	if err != nil || !reflect.DeepEqual(comp, map[string]int{"energy_monitoring": 2, "countdown": 1}) {
		t.Errorf("components %v %v", comp, err)
	}
	kids, err := tplink.ChildComponents(ctx, f)
	if err != nil || len(kids) != 7 || kids["c6"]["device"] != 6 {
		t.Errorf("child components %v %v", kids, err)
	}
}

// A child is reached through control_child; typed answers are read.
func TestTapoDeviceChild(t *testing.T) {
	var sent map[string]any
	f := &fakeSmart{answer: func(method string, p map[string]any) (map[string]any, error) {
		sent = p
		rd := p["requestData"].(map[string]any)
		var r any = map[string]any{}
		switch rd["method"] {
		case "get_device_info":
			r = map[string]any{"device_id": "kid", "model": "T315", "current_temp": 21.5, "current_humidity": 40.0, "nickname": "S2l0Y2hlbg==", "battery_percentage": 90.0}
		case "get_trigger_logs":
			r = map[string]any{"logs": []any{map[string]any{"id": 3.0, "event": "singleClick", "timestamp": 100.0}}}
		}
		return map[string]any{"responseData": map[string]any{"error_code": 0.0, "result": r}}, nil
	}}
	kid := tplink.TapoDevice{Caller: f}.Child("kid")
	info, err := kid.Info(ctx)
	if err != nil || info.Model != "T315" || *info.Temp != 21.5 || info.Nickname != "Kitchen" || *info.Battery != 90 {
		t.Fatalf("info %+v %v", info, err)
	}
	if sent["device_id"] != "kid" {
		t.Errorf("sent %v", sent)
	}
	logs, err := kid.TriggerLogs(ctx, 5, 0)
	if err != nil || len(logs) != 1 || logs[0].Event != "singleClick" {
		t.Errorf("logs %v %v", logs, err)
	}
}

func TestTapoDeviceRequests(t *testing.T) {
	var got []string
	f := &fakeSmart{answer: func(method string, p map[string]any) (map[string]any, error) {
		b, _ := json.Marshal(p)
		got = append(got, method+" "+string(b))
		switch method {
		case "get_energy_data":
			return map[string]any{"local_time": "2026-10-11 10:00:00", "data": []any{1.0, 2.0, 3.0}, "start_timestamp": 1760000000.0, "interval": 60.0}, nil
		case "get_device_time":
			return map[string]any{"timestamp": 5.0, "time_diff": 330.0, "region": "Asia/Kolkata"}, nil
		case "get_led_info":
			return map[string]any{"led_rule": "always", "led_status": true}, nil
		case "get_schedule_rules":
			return map[string]any{"enable": true, "rule_list": []any{map[string]any{"id": "S1"}}, "schedule_rule_max_count": 32.0, "start_index": 0.0, "sum": 1.0}, nil
		case "get_latest_fw":
			return map[string]any{"type": 1.0, "need_to_upgrade": true, "fw_ver": "1.4.0"}, nil
		}
		return map[string]any{}, nil
	}}
	d := tplink.TapoDevice{Caller: f}
	start := time.Unix(1760000000, 0)
	ed, err := d.EnergyData(ctx, start, start.Add(24*time.Hour), tplink.EnergyHourly)
	if err != nil || len(ed.Wh) != 3 || ed.Interval != 60 || !ed.Start.Equal(start) {
		t.Errorf("energy data %+v %v", ed, err)
	}
	on, b, ct := true, 40, 2700
	if err := d.SetLight(ctx, tplink.TapoLight{On: &on, Brightness: &b, ColorTemp: &ct}); err != nil {
		t.Fatal(err)
	}
	if err := d.SetLEDRule(ctx, "never"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetTransitions(ctx, 2, true, 3, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.WifiJoin(ctx, "u@example.invalid", "pw", "Home", "wifi-pw", ""); err != nil {
		t.Fatal(err)
	}
	r, err := d.Rules(ctx, tplink.TapoSchedule)
	if err != nil || !r.Enable || r.Max != 32 || len(r.Rules) != 1 {
		t.Errorf("rules %+v %v", r, err)
	}
	fw, err := d.LatestFirmware(ctx)
	if err != nil || !fw.Available() || fw.Version != "1.4.0" {
		t.Errorf("firmware %+v %v", fw, err)
	}
	want := []string{
		`get_energy_data {"end_timestamp":1760086400,"interval":60,"start_timestamp":1760000000}`,
		`set_device_info {"brightness":40,"color_temp":2700,"device_on":true}`,
		`get_led_info null`,
		`set_led_info {"led_rule":"never","led_status":true}`,
		`set_on_off_gradually_info {"on_state":{"duration":3,"enable":true}}`,
		`set_on_off_gradually_info {"off_state":{"enable":false}}`,
		`get_device_time null`,
		`set_qs_info {"account":{"password":"cHc=","username":"dUBleGFtcGxlLmludmFsaWQ="},"time":{"region":"Asia/Kolkata","time_diff":330,"timestamp":5},"wireless":{"key_type":"wpa2_psk","password":"d2lmaS1wdw==","ssid":"SG9tZQ=="}}`,
		`get_schedule_rules {"start_index":0}`,
		`get_latest_fw null`,
	}
	if !reflect.DeepEqual(got, want) {
		for i := range got {
			t.Logf("%d %s", i, got[i])
		}
		t.Errorf("requests differ")
	}
}

// The 20002 answer's encrypt_info: sealed to a probe key as a device
// does, decrypted with the private key.
func TestTapoAnswerDecryption(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	ei, err := tplink.SealTapoDiscovery(pub, map[string]any{"connect_ssid": "home", "connect_type": "wireless"})
	if err != nil {
		t.Fatal(err)
	}
	f := tplink.TapoFound{Result: map[string]any{"encrypt_info": ei}}
	if err := tplink.DecryptTapoAnswer(&f, k); err != nil || f.Decrypted["connect_ssid"] != "home" {
		t.Errorf("decrypted %v %v", f.Decrypted, err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := tplink.DecryptTapoAnswer(&tplink.TapoFound{Result: map[string]any{"encrypt_info": ei}}, other); err == nil {
		t.Error("another key decrypted it")
	}
}

// fakeKasa answers legacy requests from a function and records them.
type fakeKasa struct {
	answer func(req map[string]any) map[string]any
	reqs   []string
}

func (f *fakeKasa) KasaCall(_ context.Context, req any) (map[string]any, error) {
	b, _ := json.Marshal(req)
	f.reqs = append(f.reqs, string(b))
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return f.answer(m), nil
}

func TestKasaDevice(t *testing.T) {
	f := &fakeKasa{answer: func(req map[string]any) map[string]any {
		for mod, v := range req {
			if mod == "context" {
				continue
			}
			if mod == "count_down" { // this firmware names the module countdown
				return map[string]any{"count_down": map[string]any{"err_code": -1.0, "err_msg": "module not support"}}
			}
			for meth := range v.(map[string]any) {
				var r map[string]any
				switch mod + "." + meth {
				case "system.get_sysinfo":
					r = map[string]any{"mic_type": "IOT.SMARTBULB", "length": 30.0}
				case "smartlife.iot.common.emeter.get_realtime":
					r = map[string]any{"voltage": 230.5, "current": 0.1, "power": 5.0, "total": 1.5} // older firmware: V, A, W, kWh
				case "smartlife.iot.common.emeter.get_daystat":
					r = map[string]any{"day_list": []any{map[string]any{"year": 2026.0, "month": 10.0, "day": 1.0, "energy": 0.25}}}
				case "countdown.add_rule":
					r = map[string]any{"id": "CD1"}
				case "smartlife.iot.lightStrip.set_light_state":
					r = map[string]any{"on_off": 1.0}
				default:
					r = map[string]any{}
				}
				r["err_code"] = 0.0
				return map[string]any{mod: map[string]any{meth: r}}
			}
		}
		return nil
	}}
	d, _, err := tplink.NewKasaDevice(ctx, f)
	if err != nil || !d.Bulb || !d.LightStrip {
		t.Fatalf("device %+v %v", d, err)
	}
	e, err := d.Emeter(ctx)
	if err != nil || e.VoltageMV != 230500 || e.PowerMW != 5000 || e.TotalWh != 1500 {
		t.Errorf("emeter %+v %v", e, err)
	}
	days, err := d.EmeterDays(ctx, 2026, 10)
	if err != nil || len(days) != 1 || days[0].Value != 250 || days[0].Day != 1 {
		t.Errorf("days %+v %v", days, err)
	}
	// The countdown module is asked under both names devices use.
	if _, err := d.Rules(ctx, tplink.KasaCountdown); err != nil {
		t.Errorf("countdown rules %v", err)
	}
	id, err := d.Child("8006A200").AddRule(ctx, tplink.KasaCountdown, tplink.KasaRule{Name: "off soon", Enable: true, Delay: 60, Action: tplink.KasaActionOff})
	if err != nil || id != "CD1" {
		t.Errorf("add rule %q %v", id, err)
	}
	bri := 30
	if _, err := d.SetLight(ctx, tplink.KasaLight{Brightness: &bri, TransitionMS: 500}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"system":{"get_sysinfo":{}}}`,
		`{"smartlife.iot.common.emeter":{"get_realtime":{}}}`,
		`{"smartlife.iot.common.emeter":{"get_daystat":{"month":10,"year":2026}}}`,
		`{"count_down":{"get_rules":{}}}`,
		`{"countdown":{"get_rules":{}}}`,
		`{"context":{"child_ids":["8006A200"]},"count_down":{"add_rule":{"act":0,"delay":60,"enable":1,"name":"off soon"}}}`,
		`{"context":{"child_ids":["8006A200"]},"countdown":{"add_rule":{"act":0,"delay":60,"enable":1,"name":"off soon"}}}`,
		`{"smartlife.iot.lightStrip":{"set_light_state":{"brightness":30,"ignore_default":1,"on_off":1,"transition_period":500}}}`,
	}
	if !reflect.DeepEqual(f.reqs, want) {
		for i := range f.reqs {
			t.Logf("%d %s", i, f.reqs[i])
		}
		t.Errorf("requests differ")
	}
}

func TestKasaScheduleRuleParams(t *testing.T) {
	var sent map[string]any
	f := &fakeKasa{answer: func(req map[string]any) map[string]any {
		sent = req["schedule"].(map[string]any)["add_rule"].(map[string]any)
		return map[string]any{"schedule": map[string]any{"add_rule": map[string]any{"err_code": 0.0, "id": "R1"}}}
	}}
	d := &tplink.KasaDevice{Caller: f}
	r := tplink.KasaRule{Name: "evening", Enable: true, Repeat: true, SAction: tplink.KasaActionOn, STime: tplink.KasaTimeSunset, EAction: -1, ETime: -1}
	r.WDay[1], r.WDay[5] = true, true
	if _, err := d.AddRule(ctx, tplink.KasaSchedule, r); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sent["wday"]) != "[0 1 0 0 0 1 0]" || sent["sact"] != 1.0 || sent["stime_opt"] != 2.0 || sent["repeat"] != 1.0 || sent["etime_opt"] != -1.0 {
		t.Errorf("sent %v", sent)
	}
}

// Kasa cameras nest their sysinfo once more; it is read unnested.
func TestKasaCameraSysinfo(t *testing.T) {
	f := &fakeKasa{answer: func(map[string]any) map[string]any {
		return map[string]any{"system": map[string]any{"get_sysinfo": map[string]any{"err_code": 0.0, "system": map[string]any{"model": "EC60(US)", "type": "IOT.IPCAMERA"}}}}
	}}
	d, info, err := tplink.NewKasaDevice(ctx, f)
	if err != nil || info["model"] != "EC60(US)" || d.Bulb {
		t.Errorf("sysinfo %v %v", info, err)
	}
}
