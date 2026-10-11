// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink_test

import (
	"reflect"
	"testing"

	"github.com/cB-Sigma/tplink"
)

// The camera requests carry the shapes the open clients send, inside a
// multipleRequest.
func TestTapoCameraRequests(t *testing.T) {
	var got []map[string]any
	f := &fakeSmart{answer: func(method string, p map[string]any) (map[string]any, error) {
		reqs, _ := p["requests"].([]any)
		out := []any{}
		for _, r := range reqs {
			m := r.(map[string]any)
			got = append(got, m)
			out = append(out, map[string]any{"method": m["method"], "error_code": 0.0, "result": map[string]any{}})
		}
		return map[string]any{"responses": out}, nil
	}}
	c := tplink.TapoCamera{Caller: f}
	_ = c.Move(ctx, 10, -5)
	_ = c.GotoPreset(ctx, "2")
	_ = c.SavePreset(ctx, "Door")
	_ = c.DeletePreset(ctx, "2")
	_ = c.SetPrivacy(ctx, true)
	_ = c.SetLED(ctx, false)
	_ = c.SetDetection(ctx, tplink.DetectBabyCry, true)
	_ = c.SetDetection(ctx, tplink.DetectTamper, false)
	_ = c.SoundSiren(ctx, true)
	_ = c.SetNightVision(ctx, tplink.NightVisionFullColor)
	want := []map[string]any{
		{"method": "motorMove", "params": map[string]any{"motor": map[string]any{"move": map[string]any{"x_coord": "10", "y_coord": "-5"}}}},
		{"method": "motorMoveToPreset", "params": map[string]any{"preset": map[string]any{"goto_preset": map[string]any{"id": "2"}}}},
		{"method": "addMotorPostion", "params": map[string]any{"preset": map[string]any{"set_preset": map[string]any{"name": "Door", "save_ptz": "1"}}}},
		{"method": "deletePreset", "params": map[string]any{"preset": map[string]any{"remove_preset": map[string]any{"id": []any{"2"}}}}},
		{"method": "setLensMaskConfig", "params": map[string]any{"lens_mask": map[string]any{"lens_mask_info": map[string]any{"enabled": "on"}}}},
		{"method": "setLedStatus", "params": map[string]any{"led": map[string]any{"config": map[string]any{"enabled": "off"}}}},
		{"method": "setBCDConfig", "params": map[string]any{"sound_detection": map[string]any{"bcd": map[string]any{"enabled": "on"}}}},
		{"method": "setTamperDetectionConfig", "params": map[string]any{"tamper_detection": map[string]any{"tamper_det": map[string]any{"enabled": "off"}}}},
		{"method": "setSirenStatus", "params": map[string]any{"siren": map[string]any{"status": "on"}}},
		{"method": "setNightVisionModeConfig", "params": map[string]any{"image": map[string]any{"switch": map[string]any{"night_vision_mode": "wtl_night_vision"}}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
	if len(tplink.CamDetectionKinds()) != 10 {
		t.Error("detection kinds")
	}
}
