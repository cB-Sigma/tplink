// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"context"
	"errors"
	"fmt"
)

// Changing Tapo schedules and countdowns. The requests follow the open
// clients that send them (the tapo Rust crate and plugp100, see
// PROVENANCE.md): add_schedule_rule and edit_schedule_rule carry one rule,
// remove_schedule_rules a list of ids or remove_all, add_countdown_rule a
// delay with the state to switch to, remove_countdown_rules remove_all.
// The device gives each new rule its id. Away (antitheft) rules have no
// open description of their write requests and are only read (Rules).

// Schedule start kinds (s_type): a clock time, or an offset from sunrise
// or sunset.
const (
	ScheduleAtTime   = "normal"
	ScheduleSunrise  = "sunrise"
	ScheduleSunset   = "sunset"
	scheduleOnce     = "once"
	scheduleRepeat   = "repeat"
	scheduleNoAction = "none"
)

// Weekdays of a repeating schedule (week_day), Sunday the lowest bit.
const (
	Sunday uint8 = 1 << iota
	Monday
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday

	Weekdays = Monday | Tuesday | Wednesday | Thursday | Friday
	Weekend  = Saturday | Sunday
	EveryDay = Weekdays | Weekend
)

// TapoScheduleRule is one rule of a plug's or light's schedule.
type TapoScheduleRule struct {
	ID     string // given by the device; empty for a new rule
	Enable bool
	// Start is ScheduleAtTime (Minute is the minute of the day, 0-1439) or
	// ScheduleSunrise / ScheduleSunset (Offset is minutes from the event,
	// negative before it).
	Start  string
	Minute int
	Offset int
	// Days are the weekdays a repeating rule runs on (Sunday, Monday, ...);
	// 0 runs the rule once.
	Days uint8
	On   bool // the state the rule switches to
	// Raw is the rule as the device gave it (ParseTapoScheduleRule); its
	// other fields are sent back unchanged by EditScheduleRule.
	Raw map[string]any
}

// ParseTapoScheduleRule reads a rule of get_schedule_rules. Older firmware
// gives the state as s_action ("on", "off") instead of desired_states.
func ParseTapoScheduleRule(m map[string]any) TapoScheduleRule {
	r := TapoScheduleRule{ID: str(m["id"]), Start: str(m["s_type"]), Raw: m}
	r.Enable, _ = m["enable"].(bool)
	if v, ok := num(m["s_min"]); ok {
		r.Minute = int(v)
	}
	if v, ok := num(m["time_offset"]); ok {
		r.Offset = int(v)
	}
	if str(m["mode"]) == scheduleRepeat {
		if v, ok := num(m["week_day"]); ok {
			r.Days = uint8(v)
		}
	}
	ds, _ := m["desired_states"].(map[string]any)
	if on, ok := ds["on"].(bool); ok {
		r.On = on
	} else {
		r.On = str(m["s_action"]) == "on"
	}
	if r.Start == "" {
		r.Start = ScheduleAtTime
	}
	return r
}

func (r TapoScheduleRule) check() error {
	switch r.Start {
	case "", ScheduleAtTime:
		if r.Minute < 0 || r.Minute >= 24*60 {
			return fmt.Errorf("schedule minute %d is not a minute of the day", r.Minute)
		}
	case ScheduleSunrise, ScheduleSunset:
	default:
		return fmt.Errorf("unknown schedule start %q", r.Start)
	}
	if r.Days&^EveryDay != 0 {
		return fmt.Errorf("schedule days %#x name no weekday", r.Days)
	}
	return nil
}

// params is the rule as the device takes it. The date fields are required
// but not used by the device.
func (r TapoScheduleRule) params() map[string]any {
	p := map[string]any{}
	for k, v := range r.Raw {
		p[k] = v
	}
	start := r.Start
	if start == "" {
		start = ScheduleAtTime
	}
	p["enable"] = r.Enable
	p["s_type"] = start
	p["s_min"], p["time_offset"] = 0, 0
	if start == ScheduleAtTime {
		p["s_min"] = r.Minute
	} else {
		p["time_offset"] = r.Offset
	}
	p["mode"], p["week_day"] = scheduleOnce, 0
	if r.Days != 0 {
		p["mode"], p["week_day"] = scheduleRepeat, int(r.Days)
	}
	p["desired_states"] = map[string]any{"on": r.On}
	for k, v := range map[string]any{"year": 1970, "month": 1, "day": 1, "e_min": 0, "e_type": ScheduleAtTime, "e_action": scheduleNoAction} {
		if _, ok := p[k]; !ok {
			p[k] = v
		}
	}
	delete(p, "s_action")
	delete(p, "id")
	if r.ID != "" {
		p["id"] = r.ID
	}
	return p
}

// ScheduleRules reads the schedule, typed (get_schedule_rules, paged).
func (d TapoDevice) ScheduleRules(ctx context.Context) ([]TapoScheduleRule, error) {
	rs, err := d.Rules(ctx, TapoSchedule)
	if err != nil {
		return nil, err
	}
	out := make([]TapoScheduleRule, len(rs.Rules))
	for i, m := range rs.Rules {
		out[i] = ParseTapoScheduleRule(m)
	}
	return out, nil
}

// AddScheduleRule adds a rule (add_schedule_rule) and returns the id the
// device gave it. A full schedule is refused with error -1802, a rule at
// the time of another with -1803.
func (d TapoDevice) AddScheduleRule(ctx context.Context, r TapoScheduleRule) (string, error) {
	if err := r.check(); err != nil {
		return "", err
	}
	r.ID = ""
	res, err := d.Call(ctx, "add_schedule_rule", r.params())
	if err != nil {
		return "", err
	}
	id := str(res["id"])
	if id == "" {
		return "", errNoResult("add_schedule_rule", "id")
	}
	return id, nil
}

// EditScheduleRule replaces the rule with r.ID (edit_schedule_rule).
func (d TapoDevice) EditScheduleRule(ctx context.Context, r TapoScheduleRule) error {
	if r.ID == "" {
		return errors.New("edit_schedule_rule needs the rule's id")
	}
	if err := r.check(); err != nil {
		return err
	}
	_, err := d.Call(ctx, "edit_schedule_rule", r.params())
	return err
}

// RemoveScheduleRules removes the rules with the ids, or every rule when
// none is given (remove_schedule_rules).
func (d TapoDevice) RemoveScheduleRules(ctx context.Context, ids ...string) error {
	p := map[string]any{"remove_all": len(ids) == 0}
	if len(ids) > 0 {
		list := make([]any, len(ids))
		for i, id := range ids {
			list[i] = map[string]any{"id": id}
		}
		p["rule_list"] = list
	}
	_, err := d.Call(ctx, "remove_schedule_rules", p)
	return err
}

// TapoCountdownRule is a countdown: switch to On after Delay seconds;
// Remain is what is left of a running one.
type TapoCountdownRule struct {
	ID     string
	Enable bool
	Delay  int
	Remain int
	On     bool
}

// CountdownRules reads the countdowns, typed (get_countdown_rules).
func (d TapoDevice) CountdownRules(ctx context.Context) ([]TapoCountdownRule, error) {
	rs, err := d.Rules(ctx, TapoCountdown)
	if err != nil {
		return nil, err
	}
	out := make([]TapoCountdownRule, len(rs.Rules))
	for i, m := range rs.Rules {
		c := TapoCountdownRule{ID: str(m["id"])}
		c.Enable, _ = m["enable"].(bool)
		if v, ok := num(m["delay"]); ok {
			c.Delay = int(v)
		}
		if v, ok := num(m["remain"]); ok {
			c.Remain = int(v)
		}
		ds, _ := m["desired_states"].(map[string]any)
		if on, ok := ds["on"].(bool); ok {
			c.On = on
		} else {
			c.On = str(m["action"]) == "on"
		}
		out[i] = c
	}
	return out, nil
}

// AddCountdown starts a countdown that switches the device to on after
// delay seconds (add_countdown_rule) and returns its id. Plugs hold one
// countdown: a second is refused (error -1902) until the first is removed
// (RemoveCountdowns); ReplaceCountdown does both.
func (d TapoDevice) AddCountdown(ctx context.Context, delay int, on bool) (string, error) {
	if delay <= 0 {
		return "", fmt.Errorf("countdown delay %d is not positive", delay)
	}
	res, err := d.Call(ctx, "add_countdown_rule", map[string]any{"delay": delay, "desired_states": map[string]any{"on": on}, "enable": true})
	if err != nil {
		return "", err
	}
	return str(res["id"]), nil
}

// RemoveCountdowns removes every countdown (remove_countdown_rules).
func (d TapoDevice) RemoveCountdowns(ctx context.Context) error {
	_, err := d.Call(ctx, "remove_countdown_rules", map[string]any{"remove_all": true})
	return err
}

// ReplaceCountdown removes any countdown and starts a new one.
func (d TapoDevice) ReplaceCountdown(ctx context.Context, delay int, on bool) (string, error) {
	if err := d.RemoveCountdowns(ctx); err != nil {
		return "", err
	}
	return d.AddCountdown(ctx, delay, on)
}
