// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// A Kasa request names modules and their methods,
// {"<module>": {"<method>": params}}, and the answer mirrors it with an
// err_code in each method's answer. Plugs and strips call their modules
// "emeter", "schedule", "anti_theft", "cnCloud" and "time"; bulbs and light
// strips "smartlife.iot.common.emeter", "smartlife.iot.common.schedule",
// "smartlife.iot.common.anti_theft", "smartlife.iot.common.cloud" and
// "smartlife.iot.common.timesetting". A strip's outlet is addressed with
// {"context": {"child_ids": [id]}} beside the module.

// KasaCaller sends one legacy Kasa request: KasaConn (TCP 9999) or
// KLAPClient (Kasa devices on KLAP firmware).
type KasaCaller interface {
	KasaCall(ctx context.Context, req any) (map[string]any, error)
}

// KasaConn is a Kasa device on the legacy protocol (TCP port 9999).
type KasaConn struct {
	Addr    string        // host:port
	Timeout time.Duration // per request; 0 means 5 s
}

// KasaCall sends one request with KasaRequest.
func (k KasaConn) KasaCall(ctx context.Context, req any) (map[string]any, error) {
	t := k.Timeout
	if t == 0 {
		t = 5 * time.Second
	}
	return KasaRequest(ctx, k.Addr, req, t)
}

// KasaDevice is a Kasa device on the legacy JSON, or one outlet of a strip
// (ChildID), with typed helpers for its modules. Bulb selects the bulb
// module names; LightStrip the light-strip lighting service (KL4xx).
// NewKasaDevice sets both from the device's sysinfo.
type KasaDevice struct {
	Caller     KasaCaller
	ChildID    string
	Bulb       bool
	LightStrip bool
}

// NewKasaDevice reads the sysinfo and returns the device with Bulb and
// LightStrip set, and the sysinfo.
func NewKasaDevice(ctx context.Context, c KasaCaller) (*KasaDevice, map[string]any, error) {
	d := &KasaDevice{Caller: c}
	info, err := d.Sysinfo(ctx)
	if err != nil {
		return nil, nil, err
	}
	t := strings.ToUpper(str(info["mic_type"]) + str(info["type"]))
	d.Bulb = strings.Contains(t, "SMARTBULB")
	_, d.LightStrip = info["length"]
	return d, info, nil
}

// Child is the KasaDevice of one strip outlet.
func (d *KasaDevice) Child(id string) *KasaDevice {
	return &KasaDevice{Caller: d.Caller, ChildID: id, Bulb: d.Bulb, LightStrip: d.LightStrip}
}

// KasaModuleError is a module answer with an err_code that is not 0.
type KasaModuleError struct {
	Module, Method string
	Code           int
	Msg            string
}

func (e *KasaModuleError) Error() string {
	return fmt.Sprintf("the device refused %s.%s: error %d %s", e.Module, e.Method, e.Code, e.Msg)
}

// IsKasaUnsupported reports whether err is a Kasa module or method the
// device does not have (codes -1 and -2).
func IsKasaUnsupported(err error) bool {
	var e *KasaModuleError
	return errors.As(err, &e) && (e.Code == -1 || e.Code == -2)
}

// Query sends one module method and returns its answer without err_code.
func (d *KasaDevice) Query(ctx context.Context, module, method string, params any) (map[string]any, error) {
	if params == nil {
		params = map[string]any{}
	}
	req := map[string]any{module: map[string]any{method: params}}
	if d.ChildID != "" {
		req["context"] = map[string]any{"child_ids": []string{d.ChildID}}
	}
	m, err := d.Caller.KasaCall(ctx, req)
	if err != nil {
		return nil, err
	}
	mod, _ := m[module].(map[string]any)
	if mod == nil {
		return nil, fmt.Errorf("the device's answer has no %s module", module)
	}
	if c, ok := num(mod["err_code"]); ok && c != 0 { // the module itself is unknown
		return nil, &KasaModuleError{module, method, int(c), str(mod["err_msg"])}
	}
	res, _ := mod[method].(map[string]any)
	if res == nil {
		return nil, fmt.Errorf("the device's answer has no %s.%s", module, method)
	}
	if c, ok := num(res["err_code"]); ok && c != 0 {
		return nil, &KasaModuleError{module, method, int(c), str(res["err_msg"])}
	}
	out := map[string]any{}
	for k, v := range res {
		if k != "err_code" && k != "err_msg" {
			out[k] = v
		}
	}
	return out, nil
}

func (d *KasaDevice) mod(plug, bulb string) string {
	if d.Bulb {
		return bulb
	}
	return plug
}

// Sysinfo asks system.get_sysinfo. Kasa cameras nest their answer once
// more under "system"; it is returned unnested.
func (d *KasaDevice) Sysinfo(ctx context.Context) (map[string]any, error) {
	info, err := d.Query(ctx, "system", "get_sysinfo", nil)
	if inner, ok := info["system"].(map[string]any); ok && err == nil {
		return inner, nil
	}
	return info, err
}

// SetRelay switches a plug, switch or outlet (system.set_relay_state).
func (d *KasaDevice) SetRelay(ctx context.Context, on bool) error {
	_, err := d.Query(ctx, "system", "set_relay_state", map[string]any{"state": b2i(on)})
	return err
}

// SetAlias renames the device or outlet (set_dev_alias).
func (d *KasaDevice) SetAlias(ctx context.Context, alias string) error {
	_, err := d.Query(ctx, d.mod("system", "smartlife.iot.common.system"), "set_dev_alias", map[string]any{"alias": alias})
	return err
}

// SetLED switches the status light (system.set_led_off).
func (d *KasaDevice) SetLED(ctx context.Context, on bool) error {
	_, err := d.Query(ctx, "system", "set_led_off", map[string]any{"off": b2i(!on)})
	return err
}

// Reboot restarts the device after delay seconds (reboot).
func (d *KasaDevice) Reboot(ctx context.Context, delay int) error {
	_, err := d.Query(ctx, d.mod("system", "smartlife.iot.common.system"), "reboot", map[string]any{"delay": delay})
	return err
}

// FactoryReset resets the device (reset).
func (d *KasaDevice) FactoryReset(ctx context.Context) error {
	_, err := d.Query(ctx, d.mod("system", "smartlife.iot.common.system"), "reset", map[string]any{"delay": 1})
	return err
}

// Time asks the device clock (get_time), in the device's zone.
func (d *KasaDevice) Time(ctx context.Context) (time.Time, error) {
	r, err := d.Query(ctx, d.mod("time", "smartlife.iot.common.timesetting"), "get_time", nil)
	if err != nil {
		return time.Time{}, err
	}
	g := func(k string) int { v, _ := num(r[k]); return int(v) }
	return time.Date(g("year"), time.Month(g("month")), g("mday"), g("hour"), g("min"), g("sec"), 0, time.UTC), nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- Energy meter ---------------------------------------------------------

// KasaEmeter is a real-time reading, in the units newer firmware uses
// (older firmware's V, A, W and kWh are converted).
type KasaEmeter struct {
	VoltageMV float64
	CurrentMA float64
	PowerMW   float64
	TotalWh   float64
}

// ParseKasaEmeter reads a get_realtime answer of either firmware
// generation.
func ParseKasaEmeter(r map[string]any) KasaEmeter {
	pick := func(newKey, oldKey string, scale float64) float64 {
		if v, ok := num(r[newKey]); ok {
			return v
		}
		v, _ := num(r[oldKey])
		return v * scale
	}
	return KasaEmeter{VoltageMV: pick("voltage_mv", "voltage", 1000), CurrentMA: pick("current_ma", "current", 1000),
		PowerMW: pick("power_mw", "power", 1000), TotalWh: pick("total_wh", "total", 1000)}
}

func (d *KasaDevice) emeter() string { return d.mod("emeter", "smartlife.iot.common.emeter") }

// Emeter asks get_realtime.
func (d *KasaDevice) Emeter(ctx context.Context) (KasaEmeter, error) {
	r, err := d.Query(ctx, d.emeter(), "get_realtime", nil)
	if err != nil {
		return KasaEmeter{}, err
	}
	return ParseKasaEmeter(r), nil
}

// KasaStat is one day's or month's figure: Wh for the energy meter,
// minutes for the runtime statistics.
type KasaStat struct {
	Year, Month, Day int // Day is 0 in monthly statistics
	Value            float64
}

func parseStats(r map[string]any, listKey string, keys ...string) []KasaStat {
	list, _ := r[listKey].([]any)
	out := make([]KasaStat, 0, len(list))
	for _, x := range list {
		m, _ := x.(map[string]any)
		s := KasaStat{}
		if v, ok := num(m["year"]); ok {
			s.Year = int(v)
		}
		if v, ok := num(m["month"]); ok {
			s.Month = int(v)
		}
		if v, ok := num(m["day"]); ok {
			s.Day = int(v)
		}
		for i, k := range keys {
			if v, ok := num(m[k]); ok {
				if i == 1 { // older firmware: kWh
					v *= 1000
				}
				s.Value = v
				break
			}
		}
		out = append(out, s)
	}
	return out
}

// EmeterDays asks the energy per day of a month, in Wh (get_daystat).
func (d *KasaDevice) EmeterDays(ctx context.Context, year, month int) ([]KasaStat, error) {
	r, err := d.Query(ctx, d.emeter(), "get_daystat", map[string]any{"year": year, "month": month})
	if err != nil {
		return nil, err
	}
	return parseStats(r, "day_list", "energy_wh", "energy"), nil
}

// EmeterMonths asks the energy per month of a year, in Wh (get_monthstat).
func (d *KasaDevice) EmeterMonths(ctx context.Context, year int) ([]KasaStat, error) {
	r, err := d.Query(ctx, d.emeter(), "get_monthstat", map[string]any{"year": year})
	if err != nil {
		return nil, err
	}
	return parseStats(r, "month_list", "energy_wh", "energy"), nil
}

// EraseEmeter clears the energy statistics (erase_emeter_stat).
func (d *KasaDevice) EraseEmeter(ctx context.Context) error {
	_, err := d.Query(ctx, d.emeter(), "erase_emeter_stat", nil)
	return err
}

func (d *KasaDevice) schedule() string { return d.mod("schedule", "smartlife.iot.common.schedule") }

// RuntimeDays asks the minutes on per day of a month (the schedule
// module's get_daystat).
func (d *KasaDevice) RuntimeDays(ctx context.Context, year, month int) ([]KasaStat, error) {
	r, err := d.Query(ctx, d.schedule(), "get_daystat", map[string]any{"year": year, "month": month})
	if err != nil {
		return nil, err
	}
	return parseStats(r, "day_list", "time"), nil
}

// RuntimeMonths asks the minutes on per month of a year (get_monthstat).
func (d *KasaDevice) RuntimeMonths(ctx context.Context, year int) ([]KasaStat, error) {
	r, err := d.Query(ctx, d.schedule(), "get_monthstat", map[string]any{"year": year})
	if err != nil {
		return nil, err
	}
	return parseStats(r, "month_list", "time"), nil
}

// EraseRuntime clears the runtime statistics (erase_runtime_stat).
func (d *KasaDevice) EraseRuntime(ctx context.Context) error {
	_, err := d.Query(ctx, d.schedule(), "erase_runtime_stat", nil)
	return err
}

// --- Rules ----------------------------------------------------------------

// KasaRuleKind names a Kasa rule module.
type KasaRuleKind int

// The rule modules: timed actions, a countdown, and the away mode that
// switches at random within a window.
const (
	KasaSchedule KasaRuleKind = iota
	KasaCountdown
	KasaAntiTheft
)

// modules are the names tried in order: devices disagree on the
// countdown module's name.
func (d *KasaDevice) ruleModules(k KasaRuleKind) []string {
	switch k {
	case KasaCountdown:
		return []string{"count_down", "countdown"}
	case KasaAntiTheft:
		return []string{d.mod("anti_theft", "smartlife.iot.common.anti_theft")}
	}
	return []string{d.schedule()}
}

func (d *KasaDevice) ruleQuery(ctx context.Context, k KasaRuleKind, method string, params any) (map[string]any, error) {
	var err error
	for _, m := range d.ruleModules(k) {
		var r map[string]any
		if r, err = d.Query(ctx, m, method, params); err == nil || !IsKasaUnsupported(err) {
			return r, err
		}
	}
	return nil, err
}

// Rule actions and time options.
const (
	KasaActionNone = -1
	KasaActionOff  = 0
	KasaActionOn   = 1

	KasaTimeNone    = -1
	KasaTimeMinutes = 0 // minutes after midnight
	KasaTimeSunrise = 1
	KasaTimeSunset  = 2
)

// KasaRule is one rule. Schedule and away-mode rules use the start (and,
// for away mode, end) action and time and the weekdays; countdown rules
// Delay and Action. Light is a bulb's light state for the start action.
type KasaRule struct {
	ID      string
	Name    string
	Enable  bool
	WDay    [7]bool // Sunday first
	Repeat  bool
	SAction int // KasaAction*
	STime   int // KasaTime*
	SMin    int
	EAction int
	ETime   int
	EMin    int
	Delay   int // seconds (countdown)
	Action  int // countdown action
	Light   map[string]any
	Raw     map[string]any // the rule as the device gave it
}

func parseKasaRule(m map[string]any) KasaRule {
	g := func(k string, def int) int {
		if v, ok := num(m[k]); ok {
			return int(v)
		}
		return def
	}
	r := KasaRule{ID: str(m["id"]), Name: str(m["name"]), Enable: g("enable", 0) == 1, Repeat: g("repeat", 0) == 1,
		SAction: g("sact", -1), STime: g("stime_opt", -1), SMin: g("smin", 0), EAction: g("eact", -1), ETime: g("etime_opt", -1),
		EMin: g("emin", 0), Delay: g("delay", 0), Action: g("act", -1), Raw: m}
	r.Light, _ = m["s_light"].(map[string]any)
	if wd, ok := m["wday"].([]any); ok {
		for i := 0; i < 7 && i < len(wd); i++ {
			v, _ := num(wd[i])
			r.WDay[i] = v == 1
		}
	}
	return r
}

func (r KasaRule) params(k KasaRuleKind) map[string]any {
	p := map[string]any{"name": r.Name, "enable": b2i(r.Enable)}
	if r.ID != "" {
		p["id"] = r.ID
	}
	if k == KasaCountdown {
		p["delay"], p["act"] = r.Delay, r.Action
		return p
	}
	wd := make([]int, 7)
	for i, on := range r.WDay {
		wd[i] = b2i(on)
	}
	p["wday"], p["repeat"] = wd, b2i(r.Repeat)
	p["sact"], p["stime_opt"], p["smin"] = r.SAction, r.STime, r.SMin
	p["eact"], p["etime_opt"], p["emin"] = r.EAction, r.ETime, r.EMin
	p["year"], p["month"], p["day"], p["force"], p["latitude"], p["longitude"] = 0, 0, 0, 0, 0, 0
	if r.Light != nil {
		p["s_light"] = r.Light
	}
	return p
}

// KasaRules is a rule module's list and whether the module is on.
type KasaRules struct {
	Enable bool
	Rules  []KasaRule
}

// Rules reads a rule module (get_rules).
func (d *KasaDevice) Rules(ctx context.Context, k KasaRuleKind) (KasaRules, error) {
	r, err := d.ruleQuery(ctx, k, "get_rules", nil)
	if err != nil {
		return KasaRules{}, err
	}
	out := KasaRules{}
	if v, ok := num(r["enable"]); ok {
		out.Enable = v == 1
	}
	list, _ := r["rule_list"].([]any)
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out.Rules = append(out.Rules, parseKasaRule(m))
		}
	}
	return out, nil
}

// AddRule adds a rule (add_rule) and returns its ID.
func (d *KasaDevice) AddRule(ctx context.Context, k KasaRuleKind, r KasaRule) (string, error) {
	r.ID = ""
	res, err := d.ruleQuery(ctx, k, "add_rule", r.params(k))
	if err != nil {
		return "", err
	}
	return str(res["id"]), nil
}

// EditRule replaces the rule with r.ID (edit_rule).
func (d *KasaDevice) EditRule(ctx context.Context, k KasaRuleKind, r KasaRule) error {
	if r.ID == "" {
		return errors.New("a rule to edit needs its ID")
	}
	_, err := d.ruleQuery(ctx, k, "edit_rule", r.params(k))
	return err
}

// DeleteRule deletes one rule (delete_rule).
func (d *KasaDevice) DeleteRule(ctx context.Context, k KasaRuleKind, id string) error {
	_, err := d.ruleQuery(ctx, k, "delete_rule", map[string]any{"id": id})
	return err
}

// DeleteAllRules empties a rule module (delete_all_rules).
func (d *KasaDevice) DeleteAllRules(ctx context.Context, k KasaRuleKind) error {
	_, err := d.ruleQuery(ctx, k, "delete_all_rules", nil)
	return err
}

// SetRulesEnabled switches a whole rule module on or off
// (set_overall_enable).
func (d *KasaDevice) SetRulesEnabled(ctx context.Context, k KasaRuleKind, on bool) error {
	_, err := d.ruleQuery(ctx, k, "set_overall_enable", map[string]any{"enable": b2i(on)})
	return err
}

// NextAction asks the next scheduled action (get_next_action).
func (d *KasaDevice) NextAction(ctx context.Context) (map[string]any, error) {
	return d.Query(ctx, d.schedule(), "get_next_action", nil)
}

// --- Dimmers --------------------------------------------------------------

const dimmer = "smartlife.iot.dimmer"

// SetBrightness sets a dimmer's brightness, 1-100 (set_brightness).
func (d *KasaDevice) SetBrightness(ctx context.Context, b int) error {
	_, err := d.Query(ctx, dimmer, "set_brightness", map[string]any{"brightness": b})
	return err
}

// DimTo moves a dimmer to brightness over ms milliseconds
// (set_dimmer_transition); brightness 0 fades it off.
func (d *KasaDevice) DimTo(ctx context.Context, brightness, ms int) error {
	_, err := d.Query(ctx, dimmer, "set_dimmer_transition", map[string]any{"brightness": brightness, "duration": ms})
	return err
}

// DimmerParameters asks get_dimmer_parameters (fade and gentle times in
// ms, ramp rate, minimum threshold, ...).
func (d *KasaDevice) DimmerParameters(ctx context.Context) (map[string]any, error) {
	return d.Query(ctx, dimmer, "get_dimmer_parameters", nil)
}

// Dimmer fade settings for SetDimmerFade.
const (
	FadeOn    = "set_fade_on_time"
	FadeOff   = "set_fade_off_time"
	GentleOn  = "set_gentle_on_time"
	GentleOff = "set_gentle_off_time"
)

// SetDimmerFade sets one of the dimmer's fade times, in ms (FadeOn,
// FadeOff, GentleOn, GentleOff).
func (d *KasaDevice) SetDimmerFade(ctx context.Context, which string, ms int) error {
	key := "fadeTime"
	if which == GentleOn || which == GentleOff {
		key = "duration"
	}
	_, err := d.Query(ctx, dimmer, which, map[string]any{key: ms})
	return err
}

// SetRampRate sets how fast the dimmer's buttons dim (set_button_ramp_rate).
func (d *KasaDevice) SetRampRate(ctx context.Context, rate int) error {
	_, err := d.Query(ctx, dimmer, "set_button_ramp_rate", map[string]any{"rampRate": rate})
	return err
}

// --- Bulbs and light strips ---------------------------------------------

func (d *KasaDevice) light() (module, set string) {
	if d.LightStrip {
		return "smartlife.iot.lightStrip", "set_light_state"
	}
	return "smartlife.iot.smartbulb.lightingservice", "transition_light_state"
}

// KasaLight is a light change; nil fields are left as they are.
type KasaLight struct {
	On         *bool
	Brightness *int // 0-100
	Hue        *int // 0-360
	Saturation *int // 0-100
	ColorTemp  *int // Kelvin; 0 selects the colour
	// TransitionMS is the transition time; 0 lets the device choose.
	TransitionMS int
}

// LightState asks get_light_state.
func (d *KasaDevice) LightState(ctx context.Context) (map[string]any, error) {
	m, _ := d.light()
	return d.Query(ctx, m, "get_light_state", nil)
}

// SetLight changes a bulb or light strip and returns its new light state.
// A change without a colour, temperature or brightness turns the light
// on to its last state; one with them sets ignore_default so the light
// takes them.
func (d *KasaDevice) SetLight(ctx context.Context, l KasaLight) (map[string]any, error) {
	p := map[string]any{}
	on := true
	if l.On != nil {
		on = *l.On
	}
	p["on_off"] = b2i(on)
	mode := false
	for k, v := range map[string]*int{"brightness": l.Brightness, "hue": l.Hue, "saturation": l.Saturation, "color_temp": l.ColorTemp} {
		if v != nil {
			p[k] = *v
			if k != "brightness" {
				mode = true
			}
		}
	}
	if l.Hue != nil && l.ColorTemp == nil {
		p["color_temp"] = 0
	}
	p["ignore_default"] = b2i(!on || mode || l.Brightness != nil)
	if l.TransitionMS > 0 {
		p["transition_period"] = l.TransitionMS
	}
	m, set := d.light()
	return d.Query(ctx, m, set, p)
}

// LightDetails asks get_light_details (lamp ratings and colour rendering).
func (d *KasaDevice) LightDetails(ctx context.Context) (map[string]any, error) {
	m, _ := d.light()
	return d.Query(ctx, m, "get_light_details", nil)
}

// SetPreferredState saves a light preset (set_preferred_state with index
// and the state fields).
func (d *KasaDevice) SetPreferredState(ctx context.Context, state map[string]any) error {
	m, _ := d.light()
	_, err := d.Query(ctx, m, "set_preferred_state", state)
	return err
}

// SetLightingEffect sends a light strip effect (set_lighting_effect): the
// device's own description (name, id, type, brightness, transition,
// colours or sequence, enable). This module ships no effect definitions;
// an effect with enable 0 stops the running one.
func (d *KasaDevice) SetLightingEffect(ctx context.Context, effect map[string]any) error {
	_, err := d.Query(ctx, "smartlife.iot.lighting_effect", "set_lighting_effect", effect)
	return err
}

// --- Cloud, firmware, Wi-Fi -----------------------------------------------

func (d *KasaDevice) cloud() string { return d.mod("cnCloud", "smartlife.iot.common.cloud") }

// CloudInfo asks the cloud binding (get_info: username, binded, cld_connection, server, fwDlPage).
func (d *KasaDevice) CloudInfo(ctx context.Context) (map[string]any, error) {
	return d.Query(ctx, d.cloud(), "get_info", nil)
}

// FirmwareList asks the firmware updates the cloud offers the device
// (get_intl_fw_list); empty when there is none or no cloud connection.
func (d *KasaDevice) FirmwareList(ctx context.Context) ([]map[string]any, error) {
	r, err := d.Query(ctx, d.cloud(), "get_intl_fw_list", nil)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	list, _ := r["fw_list"].([]any)
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// wifiModules are tried in order: netif, then the set-up module some
// devices use instead.
var wifiModules = []string{"netif", "smartlife.iot.common.softaponboarding"}

func (d *KasaDevice) wifiQuery(ctx context.Context, method string, params any) (map[string]any, error) {
	var err error
	for _, m := range wifiModules {
		var r map[string]any
		if r, err = d.Query(ctx, m, method, params); err == nil || !IsKasaUnsupported(err) {
			return r, err
		}
	}
	return nil, err
}

// WifiScan asks the networks the device sees (get_scaninfo with refresh).
func (d *KasaDevice) WifiScan(ctx context.Context) ([]WifiNetwork, error) {
	r, err := d.wifiQuery(ctx, "get_scaninfo", map[string]any{"refresh": 1})
	if err != nil {
		return nil, err
	}
	list, _ := r["ap_list"].([]any)
	out := make([]WifiNetwork, 0, len(list))
	for _, x := range list {
		m, _ := x.(map[string]any)
		n := WifiNetwork{SSID: str(m["ssid"])}
		if v, ok := num(m["key_type"]); ok {
			n.KeyType = fmt.Sprint(int(v))
		}
		if v, ok := num(m["rssi"]); ok {
			n.SignalLevel = int(v)
		}
		out = append(out, n)
	}
	return out, nil
}

// WifiJoin sets a device in its set-up mode (its own access point) onto a
// Wi-Fi network (set_stainfo); keyType is the scan's key_type (3 for WPA2
// when 0). The device leaves its access point without answering, so a
// transport error after sending is returned as nil.
func (d *KasaDevice) WifiJoin(ctx context.Context, ssid, password string, keyType int) error {
	if keyType == 0 {
		keyType = 3
	}
	_, err := d.wifiQuery(ctx, "set_stainfo", map[string]any{"ssid": ssid, "password": password, "key_type": keyType})
	return leftNetwork(err)
}

// leftNetwork drops the error of a request the device did not answer
// because it left for another network: a read or write failure after the
// connection was made. A refused or failed connection is still an error.
func leftNetwork(err error) error {
	var me *KasaModuleError
	var oe *net.OpError
	if err == nil || errors.As(err, &me) || (errors.As(err, &oe) && oe.Op == "dial") {
		return err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &oe) {
		return nil
	}
	return err
}
