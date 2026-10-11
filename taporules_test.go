// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink_test

import (
	"reflect"
	"testing"

	"github.com/cB-Sigma/tplink"
)

// The rule requests carry the fields the open clients send (the tapo
// crate's wire shape: every field present, the date fields fixed).
func TestTapoRuleRequests(t *testing.T) {
	var got []map[string]any
	f := &fakeSmart{answer: func(method string, p map[string]any) (map[string]any, error) {
		got = append(got, map[string]any{"method": method, "params": p})
		return map[string]any{"id": "S7"}, nil
	}}
	d := tplink.TapoDevice{Caller: f}
	id, err := d.AddScheduleRule(ctx, tplink.TapoScheduleRule{ID: "ignored", Enable: true, Minute: 23*60 + 30, Days: tplink.Monday | tplink.Wednesday})
	if err != nil || id != "S7" {
		t.Fatalf("%q %v", id, err)
	}
	want := map[string]any{"enable": true, "year": 1970.0, "month": 1.0, "day": 1.0, "time_offset": 0.0, "week_day": 10.0, "s_min": 1410.0, "e_min": 0.0,
		"s_type": "normal", "e_type": "normal", "e_action": "none", "mode": "repeat", "desired_states": map[string]any{"on": false}}
	if !reflect.DeepEqual(got[0]["params"], want) || got[0]["method"] != "add_schedule_rule" {
		t.Errorf("add %v", got[0])
	}
	if err := d.EditScheduleRule(ctx, tplink.TapoScheduleRule{ID: "S7", Start: tplink.ScheduleSunrise, Offset: -30, On: true}); err != nil {
		t.Fatal(err)
	}
	p := got[1]["params"].(map[string]any)
	if got[1]["method"] != "edit_schedule_rule" || p["id"] != "S7" || p["s_type"] != "sunrise" || p["time_offset"] != -30.0 || p["s_min"] != 0.0 || p["mode"] != "once" {
		t.Errorf("edit %v", got[1])
	}
	_ = d.RemoveScheduleRules(ctx, "S1", "S2")
	_ = d.RemoveScheduleRules(ctx)
	if !reflect.DeepEqual(got[2]["params"], map[string]any{"remove_all": false, "rule_list": []any{map[string]any{"id": "S1"}, map[string]any{"id": "S2"}}}) ||
		!reflect.DeepEqual(got[3]["params"], map[string]any{"remove_all": true}) || got[3]["method"] != "remove_schedule_rules" {
		t.Errorf("remove %v %v", got[2], got[3])
	}
	_, _ = d.AddCountdown(ctx, 90, true)
	_ = d.RemoveCountdowns(ctx)
	if !reflect.DeepEqual(got[4], map[string]any{"method": "add_countdown_rule", "params": map[string]any{"delay": 90.0, "enable": true, "desired_states": map[string]any{"on": true}}}) ||
		!reflect.DeepEqual(got[5], map[string]any{"method": "remove_countdown_rules", "params": map[string]any{"remove_all": true}}) {
		t.Errorf("countdown %v %v", got[4], got[5])
	}
}
