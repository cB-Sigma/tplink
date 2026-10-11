// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"time"
)

// TapoDevice is a Tapo device, or one child of a hub or strip, with typed
// helpers for the requests open-source clients describe: device
// information, switching and lights, energy and use, schedules and other
// rules, firmware, Wi-Fi and account set-up. Each helper is one request
// (see the method); Call and MultiCall reach anything else.
//
// A child is reached through its parent with control_child: set ChildID
// to its device_id. The zero ChildID is the device itself. TapoDevice is a
// SmartCaller, so it can be passed to ChildList, SmartList, Components
// and MultiCall.
type TapoDevice struct {
	Caller  SmartCaller // a KLAPClient or AESClient
	ChildID string
}

// Call sends one request to the device, or to the child through
// control_child.
func (d TapoDevice) Call(ctx context.Context, method string, params any) (map[string]any, error) {
	if d.ChildID == "" {
		return d.Caller.Call(ctx, method, params)
	}
	return ControlChild(ctx, d.Caller, d.ChildID, method, params)
}

// call decodes a result into out.
func (d TapoDevice) call(ctx context.Context, method string, params any, out any) error {
	res, err := d.Call(ctx, method, params)
	if err != nil {
		return err
	}
	return remarshal(res, out)
}

func remarshal(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// TapoInfo is the common part of get_device_info. Raw holds every field.
type TapoInfo struct {
	DeviceID   string         `json:"device_id"`
	Model      string         `json:"model"`
	Type       string         `json:"type"`
	Category   string         `json:"category"` // children: plug.powerstrip.sub-plug, subg.trigger.temp-hmdt-sensor, ...
	FWVersion  string         `json:"fw_ver"`
	HWVersion  string         `json:"hw_ver"`
	MAC        string         `json:"mac"`
	IP         string         `json:"ip"`
	On         *bool          `json:"device_on"`
	Brightness *int           `json:"brightness"`
	Hue        *int           `json:"hue"`
	Saturation *int           `json:"saturation"`
	ColorTemp  *int           `json:"color_temp"`
	OnTime     int            `json:"on_time"`
	Overheated bool           `json:"overheated"`
	RSSI       int            `json:"rssi"`
	Region     string         `json:"region"`
	Status     string         `json:"status"` // children of a hub: online, offline
	Battery    *int           `json:"battery_percentage"`
	LowBattery bool           `json:"at_low_battery"`
	Temp       *float64       `json:"current_temp"`
	Humidity   *float64       `json:"current_humidity"`
	TempUnit   string         `json:"temp_unit"`
	Open       *bool          `json:"open"`     // contact sensors
	Detected   *bool          `json:"detected"` // motion sensors
	InAlarm    *bool          `json:"in_alarm"` // water-leak sensors
	Nickname   string         `json:"-"`        // decoded from base64
	Raw        map[string]any `json:"-"`
}

// ParseTapoInfo reads a get_device_info answer (or a child list entry).
func ParseTapoInfo(m map[string]any) TapoInfo {
	var i TapoInfo
	_ = remarshal(m, &i)
	i.Raw = m
	i.Nickname = DecodeNickname(str(m["nickname"]))
	return i
}

// DecodeNickname decodes a base64 nickname; a value that is not base64 is
// returned as it is.
func DecodeNickname(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(b)
}

// Info asks get_device_info.
func (d TapoDevice) Info(ctx context.Context) (TapoInfo, error) {
	res, err := d.Call(ctx, "get_device_info", nil)
	if err != nil {
		return TapoInfo{}, err
	}
	return ParseTapoInfo(res), nil
}

// SetOn switches the device (set_device_info device_on).
func (d TapoDevice) SetOn(ctx context.Context, on bool) error {
	_, err := d.Call(ctx, "set_device_info", map[string]any{"device_on": on})
	return err
}

// SetNickname renames the device (set_device_info nickname, base64).
func (d TapoDevice) SetNickname(ctx context.Context, name string) error {
	_, err := d.Call(ctx, "set_device_info", map[string]any{"nickname": base64.StdEncoding.EncodeToString([]byte(name))})
	return err
}

// TapoLight is a light change for SetLight; nil fields are left as they
// are. A colour (Hue, Saturation) is set with ColorTemp 0; a colour
// temperature replaces the colour.
type TapoLight struct {
	On         *bool
	Brightness *int // 1-100
	Hue        *int // 0-360
	Saturation *int // 0-100
	ColorTemp  *int // Kelvin; 0 selects the colour
}

// SetLight changes a bulb or light strip in one set_device_info.
func (d TapoDevice) SetLight(ctx context.Context, l TapoLight) error {
	p := map[string]any{}
	if l.On != nil {
		p["device_on"] = *l.On
	}
	if l.Brightness != nil {
		p["brightness"] = *l.Brightness
	}
	if l.Hue != nil || l.Saturation != nil {
		if l.Hue != nil {
			p["hue"] = *l.Hue
		}
		if l.Saturation != nil {
			p["saturation"] = *l.Saturation
		}
		if l.ColorTemp == nil {
			p["color_temp"] = 0
		}
	}
	if l.ColorTemp != nil {
		p["color_temp"] = *l.ColorTemp
	}
	_, err := d.Call(ctx, "set_device_info", p)
	return err
}

// Reboot restarts the device after delay seconds (device_reboot). A delay
// of 0 makes the device restart without answering.
func (d TapoDevice) Reboot(ctx context.Context, delay int) error {
	_, err := d.Call(ctx, "device_reboot", map[string]any{"delay": delay})
	return err
}

// FactoryReset resets the device to its factory settings (device_reset).
func (d TapoDevice) FactoryReset(ctx context.Context) error {
	_, err := d.Call(ctx, "device_reset", nil)
	return err
}

// TapoTime is get_device_time.
type TapoTime struct {
	Timestamp int64  `json:"timestamp"` // Unix seconds
	TimeDiff  int    `json:"time_diff"` // minutes from UTC
	Region    string `json:"region"`
}

// Time asks the device clock (get_device_time).
func (d TapoDevice) Time(ctx context.Context) (TapoTime, error) {
	var t TapoTime
	return t, d.call(ctx, "get_device_time", nil, &t)
}

// --- Energy -------------------------------------------------------------

// TapoEnergyUsage is get_energy_usage: energy in Wh, runtimes in minutes;
// CurrentPower is in mW on the firmware that reports it here.
type TapoEnergyUsage struct {
	TodayRuntime int     `json:"today_runtime"`
	MonthRuntime int     `json:"month_runtime"`
	TodayEnergy  int     `json:"today_energy"`
	MonthEnergy  int     `json:"month_energy"`
	CurrentPower float64 `json:"current_power"`
	LocalTime    string  `json:"local_time"`
}

// EnergyUsage asks get_energy_usage.
func (d TapoDevice) EnergyUsage(ctx context.Context) (TapoEnergyUsage, error) {
	var u TapoEnergyUsage
	return u, d.call(ctx, "get_energy_usage", nil, &u)
}

// CurrentPower asks get_current_power, in W.
func (d TapoDevice) CurrentPower(ctx context.Context) (float64, error) {
	res, err := d.Call(ctx, "get_current_power", nil)
	if err != nil {
		return 0, err
	}
	p, ok := num(res["current_power"])
	if !ok {
		return 0, errNoResult("get_current_power", "current_power")
	}
	return p, nil
}

// TapoEmeter is get_emeter_data (newer energy-monitoring firmware).
type TapoEmeter struct {
	VoltageMV float64 `json:"voltage_mv"`
	CurrentMA float64 `json:"current_ma"`
	PowerMW   float64 `json:"power_mw"`
	EnergyWh  float64 `json:"energy_wh"`
}

// Emeter asks get_emeter_data: voltage, current, power and energy.
func (d TapoDevice) Emeter(ctx context.Context) (TapoEmeter, error) {
	var e TapoEmeter
	return e, d.call(ctx, "get_emeter_data", nil, &e)
}

// EnergyInterval is the bucket of an energy history.
type EnergyInterval int

// The buckets get_energy_data takes, in minutes.
const (
	EnergyHourly  EnergyInterval = 60
	EnergyDaily   EnergyInterval = 1440
	EnergyMonthly EnergyInterval = 43200
)

// TapoEnergyData is an energy history: Wh per bucket from Start.
type TapoEnergyData struct {
	Start     time.Time
	Interval  EnergyInterval
	Wh        []float64
	LocalTime string
	Raw       map[string]any
}

// EnergyData asks get_energy_data for the energy history between start
// and end. Devices answer a day of hours (EnergyHourly), a quarter of
// days from its first day (EnergyDaily) and a year of months
// (EnergyMonthly); start and end are sent as Unix seconds as given.
func (d TapoDevice) EnergyData(ctx context.Context, start, end time.Time, interval EnergyInterval) (TapoEnergyData, error) {
	res, err := d.Call(ctx, "get_energy_data", map[string]any{"start_timestamp": start.Unix(), "end_timestamp": end.Unix(), "interval": int(interval)})
	if err != nil {
		return TapoEnergyData{}, err
	}
	out := TapoEnergyData{Start: start, Interval: interval, LocalTime: str(res["local_time"]), Raw: res}
	if s, ok := num(res["start_timestamp"]); ok {
		out.Start = time.Unix(int64(s), 0)
	}
	if iv, ok := num(res["interval"]); ok && iv > 0 {
		out.Interval = EnergyInterval(iv)
	}
	list, _ := res["data"].([]any)
	for _, x := range list {
		v, _ := num(x)
		out.Wh = append(out.Wh, v)
	}
	return out, nil
}

// TapoPeriods is a today, past 7 days and past 30 days triple.
type TapoPeriods struct {
	Today  int `json:"today"`
	Past7  int `json:"past7"`
	Past30 int `json:"past30"`
}

// TapoUsage is get_device_usage: minutes on, energy used and saved (Wh).
type TapoUsage struct {
	Time  TapoPeriods `json:"time_usage"`
	Power TapoPeriods `json:"power_usage"`
	Saved TapoPeriods `json:"saved_power"`
}

// Usage asks get_device_usage.
func (d TapoDevice) Usage(ctx context.Context) (TapoUsage, error) {
	var u TapoUsage
	return u, d.call(ctx, "get_device_usage", nil, &u)
}

// --- Rules --------------------------------------------------------------

// TapoRuleKind names a Tapo rule list.
type TapoRuleKind string

// The rule lists of plugs and lights.
const (
	TapoSchedule  TapoRuleKind = "schedule"
	TapoCountdown TapoRuleKind = "countdown"
	TapoAntitheft TapoRuleKind = "antitheft"
)

// TapoRules is a rule list: whether it is on, its rules as the device
// gives them, and how many it holds at most.
type TapoRules struct {
	Enable bool
	Max    int
	Rules  []map[string]any
}

// Rules reads a rule list (get_schedule_rules paged, get_countdown_rules,
// get_antitheft_rules). ScheduleRules and CountdownRules read them typed;
// AddScheduleRule, EditScheduleRule, RemoveScheduleRules, AddCountdown and
// RemoveCountdowns change them (taporules.go). Away rules are read only.
func (d TapoDevice) Rules(ctx context.Context, kind TapoRuleKind) (TapoRules, error) {
	method := "get_" + string(kind) + "_rules"
	list, first, err := SmartList(ctx, d, method, "rule_list", nil)
	if err != nil {
		return TapoRules{}, err
	}
	out := TapoRules{Rules: list}
	out.Enable, _ = first["enable"].(bool)
	if n, ok := num(first[string(kind)+"_rule_max_count"]); ok {
		out.Max = int(n)
	}
	return out, nil
}

// TapoAutoOff is get_auto_off_config: switch off DelayMin minutes after
// switching on.
type TapoAutoOff struct {
	Enable   bool `json:"enable"`
	DelayMin int  `json:"delay_min"`
}

// AutoOff asks get_auto_off_config.
func (d TapoDevice) AutoOff(ctx context.Context) (TapoAutoOff, error) {
	var a TapoAutoOff
	return a, d.call(ctx, "get_auto_off_config", nil, &a)
}

// SetAutoOff sends set_auto_off_config.
func (d TapoDevice) SetAutoOff(ctx context.Context, a TapoAutoOff) error {
	_, err := d.Call(ctx, "set_auto_off_config", map[string]any{"enable": a.Enable, "delay_min": a.DelayMin})
	return err
}

// LED asks get_led_info: led_rule (always, never, auto) and the rest.
func (d TapoDevice) LED(ctx context.Context) (map[string]any, error) {
	return d.Call(ctx, "get_led_info", nil)
}

// SetLEDRule sets the status light's rule (always, never or auto),
// keeping the other LED settings (get_led_info, then set_led_info).
func (d TapoDevice) SetLEDRule(ctx context.Context, rule string) error {
	cur, err := d.LED(ctx)
	if err != nil {
		return err
	}
	p := map[string]any{}
	for k, v := range cur {
		p[k] = v
	}
	p["led_rule"] = rule
	_, err = d.Call(ctx, "set_led_info", p)
	return err
}

// --- Lights -------------------------------------------------------------

// Transitions asks get_on_off_gradually_info: {"enable"} on firmware of
// component version 1, {"on_state", "off_state"} with durations in
// seconds on later ones.
func (d TapoDevice) Transitions(ctx context.Context) (map[string]any, error) {
	return d.Call(ctx, "get_on_off_gradually_info", nil)
}

// SetTransitions sends set_on_off_gradually_info. On firmware whose
// on_off_gradually component is version 1 only enable counts (onSecs and
// offSecs are ignored); later firmware takes the durations, 0 for off.
func (d TapoDevice) SetTransitions(ctx context.Context, version int, enable bool, onSecs, offSecs int) error {
	if version <= 1 {
		_, err := d.Call(ctx, "set_on_off_gradually_info", map[string]any{"enable": enable})
		return err
	}
	state := func(secs int) map[string]any {
		m := map[string]any{"enable": enable && secs > 0}
		if secs > 0 {
			m["duration"] = secs
		}
		return m
	}
	if _, err := d.Call(ctx, "set_on_off_gradually_info", map[string]any{"on_state": state(onSecs)}); err != nil {
		return err
	}
	_, err := d.Call(ctx, "set_on_off_gradually_info", map[string]any{"off_state": state(offSecs)})
	return err
}

// Presets reads a light's saved states (get_preset_rules, paged).
func (d TapoDevice) Presets(ctx context.Context) ([]map[string]any, error) {
	list, _, err := SmartList(ctx, d, "get_preset_rules", "states", nil)
	return list, err
}

// EditPreset replaces one saved state (edit_preset_rules).
func (d TapoDevice) EditPreset(ctx context.Context, index int, state map[string]any) error {
	_, err := d.Call(ctx, "edit_preset_rules", map[string]any{"index": index, "state": state})
	return err
}

// LightingEffect asks a light strip's current effect (get_lighting_effect).
func (d TapoDevice) LightingEffect(ctx context.Context) (map[string]any, error) {
	return d.Call(ctx, "get_lighting_effect", nil)
}

// SetLightingEffect sends a light strip effect (set_lighting_effect). The
// effect is the device's own description (name, type, sequence, colours,
// brightness, enable, ...); this module ships no effect definitions.
func (d TapoDevice) SetLightingEffect(ctx context.Context, effect map[string]any) error {
	_, err := d.Call(ctx, "set_lighting_effect", effect)
	return err
}

// DynamicEffects reads a bulb's light effects (get_dynamic_light_effect_rules,
// paged), with whether one is running.
func (d TapoDevice) DynamicEffects(ctx context.Context) (TapoRules, error) {
	list, first, err := SmartList(ctx, d, "get_dynamic_light_effect_rules", "rule_list", nil)
	if err != nil {
		return TapoRules{}, err
	}
	out := TapoRules{Rules: list}
	out.Enable, _ = first["enable"].(bool)
	if n, ok := num(first["max_count"]); ok {
		out.Max = int(n)
	}
	return out, nil
}

// SetDynamicEffect starts (enable) or stops a bulb's light effect by its
// id (set_dynamic_light_effect_rule_enable).
func (d TapoDevice) SetDynamicEffect(ctx context.Context, id string, enable bool) error {
	p := map[string]any{"enable": enable}
	if enable {
		p["id"] = id
	}
	_, err := d.Call(ctx, "set_dynamic_light_effect_rule_enable", p)
	return err
}

// --- Firmware -----------------------------------------------------------

// TapoFirmware is get_latest_fw. The device asks TP-Link's cloud, so a
// device without a cloud connection answers no update.
type TapoFirmware struct {
	Type        int    `json:"type"` // 0: no update
	NeedUpgrade bool   `json:"need_to_upgrade"`
	Version     string `json:"fw_ver"`
	ReleaseDate string `json:"release_date"`
	ReleaseNote string `json:"release_note"`
	Size        int    `json:"fw_size"`
}

// Available reports whether an update is offered.
func (f TapoFirmware) Available() bool { return f.Type != 0 || f.NeedUpgrade }

// LatestFirmware asks get_latest_fw.
func (d TapoDevice) LatestFirmware(ctx context.Context) (TapoFirmware, error) {
	var f TapoFirmware
	return f, d.call(ctx, "get_latest_fw", nil, &f)
}

// StartFirmwareUpdate tells the device to download and install the
// latest firmware (fw_download); follow it with FirmwareState.
func (d TapoDevice) StartFirmwareUpdate(ctx context.Context) error {
	_, err := d.Call(ctx, "fw_download", nil)
	return err
}

// TapoFirmwareState is get_fw_download_state. Status 0 is idle, 2
// downloading, 3 flashing (wait UpgradeTime seconds), negative an error.
type TapoFirmwareState struct {
	Status      int  `json:"status"`
	Progress    int  `json:"download_progress"`
	RebootTime  int  `json:"reboot_time"`
	UpgradeTime int  `json:"upgrade_time"`
	AutoUpgrade bool `json:"auto_upgrade"`
}

// FirmwareState asks get_fw_download_state.
func (d TapoDevice) FirmwareState(ctx context.Context) (TapoFirmwareState, error) {
	var s TapoFirmwareState
	return s, d.call(ctx, "get_fw_download_state", nil, &s)
}

// TapoAutoUpdate is get_auto_update_info: automatic updates and their
// time (minutes after midnight) with a random spread (minutes).
type TapoAutoUpdate struct {
	Enable      bool `json:"enable"`
	Time        int  `json:"time"`
	RandomRange int  `json:"random_range"`
}

// AutoUpdate asks get_auto_update_info.
func (d TapoDevice) AutoUpdate(ctx context.Context) (TapoAutoUpdate, error) {
	var a TapoAutoUpdate
	return a, d.call(ctx, "get_auto_update_info", nil, &a)
}

// SetAutoUpdate sends set_auto_update_info.
func (d TapoDevice) SetAutoUpdate(ctx context.Context, a TapoAutoUpdate) error {
	_, err := d.Call(ctx, "set_auto_update_info", map[string]any{"enable": a.Enable, "time": a.Time, "random_range": a.RandomRange})
	return err
}

// --- Set-up -------------------------------------------------------------

// WifiNetwork is a network a device sees.
type WifiNetwork struct {
	SSID        string
	BSSID       string
	KeyType     string // Tapo: wpa2_psk, ...; Kasa: a number as text
	CipherType  int
	Channel     int
	SignalLevel int // Tapo: 1-3; Kasa: RSSI
}

// WifiScan asks the networks the device sees (get_wireless_scan_info,
// paged; SSIDs are base64 on the wire).
func (d TapoDevice) WifiScan(ctx context.Context) ([]WifiNetwork, error) {
	list, _, err := SmartList(ctx, d, "get_wireless_scan_info", "ap_list", nil)
	if err != nil {
		return nil, err
	}
	out := make([]WifiNetwork, 0, len(list))
	for _, m := range list {
		n := WifiNetwork{SSID: DecodeNickname(str(m["ssid"])), BSSID: str(m["bssid"]), KeyType: str(m["key_type"])}
		if v, ok := num(m["cipher_type"]); ok {
			n.CipherType = int(v)
		}
		if v, ok := num(m["channel"]); ok {
			n.Channel = int(v)
		}
		if v, ok := num(m["signal_level"]); ok {
			n.SignalLevel = int(v)
		}
		out = append(out, n)
	}
	return out, nil
}

// qsTime is the device time set_qs_info carries: the device's own
// get_device_time answer.
func (d TapoDevice) qsTime(ctx context.Context) (map[string]any, error) {
	return d.Call(ctx, "get_device_time", nil)
}

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// WifiJoin sets a device up on a Wi-Fi network and binds it to the TP-Link
// account (username, password), as the app does for a new device in its
// set-up mode (set_qs_info with the account, the network and the device's
// own time). keyType is the network's security as WifiScan reports it
// ("wpa2_psk" when ""). The device usually switches networks without
// answering, so a transport error after sending is expected and returned
// as nil.
func (d TapoDevice) WifiJoin(ctx context.Context, username, password, ssid, wifiPassword, keyType string) error {
	if keyType == "" {
		keyType = "wpa2_psk"
	}
	t, err := d.qsTime(ctx)
	if err != nil {
		return err
	}
	_, err = d.Call(ctx, "set_qs_info", map[string]any{
		"account":  map[string]any{"username": b64s(username), "password": b64s(password)},
		"wireless": map[string]any{"key_type": keyType, "password": b64s(wifiPassword), "ssid": b64s(ssid)},
		"time":     t,
	})
	var ue *url.Error
	var oe *net.OpError
	if errors.As(err, &ue) && !(errors.As(err, &oe) && oe.Op == "dial") {
		return nil // the device left for the new network before answering
	}
	return err
}

// SetAccount replaces the TP-Link account the device knows (set_qs_info
// with the account and the device's time); clients must then use the new
// account.
func (d TapoDevice) SetAccount(ctx context.Context, username, password string) error {
	t, err := d.qsTime(ctx)
	if err != nil {
		return err
	}
	_, err = d.Call(ctx, "set_qs_info", map[string]any{"account": map[string]any{"username": b64s(username), "password": b64s(password)}, "time": t})
	return err
}

// --- Hubs ---------------------------------------------------------------

// Children reads a hub's or strip's children, typed.
func (d TapoDevice) Children(ctx context.Context) ([]TapoInfo, error) {
	list, err := ChildList(ctx, d)
	if err != nil {
		return nil, err
	}
	out := make([]TapoInfo, len(list))
	for i, m := range list {
		out[i] = ParseTapoInfo(m)
	}
	return out, nil
}

// Child is the TapoDevice of one child.
func (d TapoDevice) Child(deviceID string) TapoDevice {
	return TapoDevice{Caller: d.Caller, ChildID: deviceID}
}

// TriggerLog is one entry of a button's or sensor's log.
type TriggerLog struct {
	ID        int            `json:"id"`
	Event     string         `json:"event"` // singleClick, doubleClick, rotation, open, close, motion, ...
	EventID   string         `json:"eventId"`
	Timestamp int64          `json:"timestamp"`
	Params    map[string]any `json:"params"`
}

// TriggerLogs reads a child's log, newest first (get_trigger_logs with
// page_size and start_id; 0 starts at the newest).
func (d TapoDevice) TriggerLogs(ctx context.Context, pageSize, startID int) ([]TriggerLog, error) {
	res, err := d.Call(ctx, "get_trigger_logs", map[string]any{"page_size": pageSize, "start_id": startID})
	if err != nil {
		return nil, err
	}
	var out []TriggerLog
	return out, remarshal(res["logs"], &out)
}
