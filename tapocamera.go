// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TapoCamera is a Tapo camera or doorbell, or one camera behind an H200
// hub (ChildID), with typed helpers for the camera requests open clients
// describe: device information, name, pan and tilt with presets, privacy
// (the lens mask), status light, detection settings, siren and alarm,
// night vision, clock, SD card, recordings list, Wi-Fi scan and reboot.
// Video and pictures are not part of this module.
//
// Caller is the transport: an SSLAESClient (or any SmartCaller whose
// device takes camera requests in a multipleRequest). Each helper names the
// request it sends; Call and CamSingle reach anything else.
type TapoCamera struct {
	Caller  SmartCaller
	ChildID string // a camera behind an H200 hub: its device_id
}

// Call sends one camera request (in a multipleRequest, or through the hub
// with controlChild) and returns its result.
func (c TapoCamera) Call(ctx context.Context, method string, params any) (map[string]any, error) {
	if c.ChildID != "" {
		return CamControlChild(ctx, c.Caller, c.ChildID, method, params)
	}
	p, _ := params.(map[string]any)
	if p == nil && params != nil {
		if err := remarshal(params, &p); err != nil {
			return nil, err
		}
	}
	return CamGet(ctx, c.Caller, method, p)
}

// rawSender is a transport that sends request objects as they are.
type rawSender interface {
	Send(ctx context.Context, req any) (map[string]any, error)
}

// ErrNoSingleRequests is returned for a camera request that only has the
// single form ({"method": "do", ...}) on a transport or path that cannot
// send it (a camera behind a hub, or a transport without Send).
var ErrNoSingleRequests = errors.New("this camera path does not take single requests")

// CamSingle sends the single form of a camera request: {"method": verb,
// module: body}, with verb "get", "set" or "do" (some requests exist only
// in this form). c must send raw requests (SSLAESClient does). The answer
// is returned without its error_code; an error code is a *SmartError.
func CamSingle(ctx context.Context, c SmartCaller, verb, module string, body any) (map[string]any, error) {
	rs, ok := c.(rawSender)
	if !ok {
		return nil, ErrNoSingleRequests
	}
	m, err := rs.Send(ctx, map[string]any{"method": verb, module: body})
	if err != nil {
		return nil, err
	}
	if code := errorCode(m); code != 0 {
		return nil, &SmartError{Code: code, Method: verb + " " + module}
	}
	delete(m, "error_code")
	return m, nil
}

func (c TapoCamera) single(ctx context.Context, verb, module string, body any) (map[string]any, error) {
	if c.ChildID != "" {
		return nil, ErrNoSingleRequests
	}
	return CamSingle(ctx, c.Caller, verb, module, body)
}

// section asks a getter for module.sections and returns the module's part
// of the answer. Some firmware answers without the module level; that is
// accepted.
func (c TapoCamera) section(ctx context.Context, method, module string, sections ...string) (map[string]any, error) {
	p := map[string]any{}
	if len(sections) > 0 {
		names := make([]any, len(sections))
		for i, s := range sections {
			names[i] = s
		}
		p["name"] = names
	}
	res, err := c.Call(ctx, method, map[string]any{module: p})
	if err != nil {
		return nil, err
	}
	if m, ok := res[module].(map[string]any); ok {
		return m, nil
	}
	return res, nil
}

// sub returns m[key] as a map (never nil).
func sub(m map[string]any, key string) map[string]any {
	s, _ := m[key].(map[string]any)
	if s == nil {
		s = map[string]any{}
	}
	return s
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// atoi reads a number the cameras give as text or as a number.
func atoi(v any) int {
	if n, ok := num(v); ok {
		return int(n)
	}
	n, _ := strconv.Atoi(strings.TrimSpace(str(v)))
	return n
}

// --- Device -------------------------------------------------------------

// CamInfo is the camera's basic_info. Raw holds every field.
type CamInfo struct {
	Model     string // device_model
	Type      string // device_type: SMART.IPCAMERA, SMART.TAPODOORBELL, ...
	Alias     string // device_alias
	FWVersion string // sw_version
	HWVersion string // hw_version
	MAC       string
	DeviceID  string // dev_id
	// Battery cameras: the charge in percent, low battery, charging and
	// the power source (power: BATTERY or another value).
	Battery    *int
	LowBattery bool
	Charging   bool
	Power      string
	Raw        map[string]any
}

// ParseCamInfo reads a basic_info answer.
func ParseCamInfo(bi map[string]any) CamInfo {
	i := CamInfo{Model: str(bi["device_model"]), Type: str(bi["device_type"]), Alias: str(bi["device_alias"]), FWVersion: str(bi["sw_version"]),
		HWVersion: str(bi["hw_version"]), MAC: str(bi["mac"]), DeviceID: str(bi["dev_id"]), Power: str(bi["power"]), Raw: bi}
	if n, ok := num(bi["battery_percent"]); ok {
		b := int(n)
		i.Battery = &b
	}
	i.LowBattery, _ = bi["low_battery"].(bool)
	switch v := bi["battery_charging"].(type) {
	case bool:
		i.Charging = v
	case string:
		switch strings.ToLower(v) {
		case "yes", "true", "1", "charging", "on":
			i.Charging = true
		}
	}
	return i
}

// Info asks getDeviceInfo (device_info.basic_info).
func (c TapoCamera) Info(ctx context.Context) (CamInfo, error) {
	di, err := c.section(ctx, "getDeviceInfo", "device_info", "basic_info")
	if err != nil {
		return CamInfo{}, err
	}
	bi, ok := di["basic_info"].(map[string]any)
	if !ok {
		return CamInfo{}, errNoResult("getDeviceInfo", "device_info.basic_info")
	}
	return ParseCamInfo(bi), nil
}

// Components asks getAppComponentList: the camera's features with their
// versions (ptz, lensMask, detection, personDetection, siren, ...).
func (c TapoCamera) Components(ctx context.Context) (map[string]int, error) {
	ac, err := c.Call(ctx, "getAppComponentList", map[string]any{"app_component": map[string]any{"name": "app_component_list"}})
	if err != nil {
		return nil, err
	}
	list, _ := sub(ac, "app_component")["app_component_list"].([]any)
	out := map[string]int{}
	for _, x := range list {
		m, _ := x.(map[string]any)
		if name := str(m["name"]); name != "" {
			out[name] = atoi(m["version"])
		}
	}
	return out, nil
}

// SetAlias renames the camera (setDeviceAlias).
func (c TapoCamera) SetAlias(ctx context.Context, name string) error {
	_, err := c.Call(ctx, "setDeviceAlias", map[string]any{"system": map[string]any{"sys": map[string]any{"dev_alias": name}}})
	return err
}

// Reboot restarts the camera (rebootDevice).
func (c TapoCamera) Reboot(ctx context.Context) error {
	_, err := c.Call(ctx, "rebootDevice", map[string]any{"system": map[string]any{"reboot": "null"}})
	return err
}

// CamConnection is getConnectionType: link, signal level (0-4) and RSSI.
type CamConnection struct {
	Link  string // wifi, ethernet
	Level int
	RSSI  int
	SSID  string // decoded from base64
}

// Connection asks getConnectionType.
func (c TapoCamera) Connection(ctx context.Context) (CamConnection, error) {
	res, err := c.Call(ctx, "getConnectionType", map[string]any{"network": map[string]any{"get_connection_type": map[string]any{}}})
	if err != nil {
		return CamConnection{}, err
	}
	if n, ok := res["network"].(map[string]any); ok && res["link_type"] == nil {
		res = n
	}
	return CamConnection{Link: str(res["link_type"]), Level: atoi(res["rssi"]), RSSI: atoi(res["rssiValue"]), SSID: DecodeNickname(str(res["ssid"]))}, nil
}

// WifiScan asks the networks the camera sees (scanApList).
func (c TapoCamera) WifiScan(ctx context.Context) ([]WifiNetwork, error) {
	res, err := c.Call(ctx, "scanApList", map[string]any{"onboarding": map[string]any{"scan": map[string]any{}}})
	if err != nil {
		return nil, err
	}
	list, _ := sub(sub(res, "onboarding"), "scan")["ap_list"].([]any)
	var out []WifiNetwork
	for _, x := range list {
		m, _ := x.(map[string]any)
		out = append(out, WifiNetwork{SSID: str(m["ssid"]), BSSID: str(m["bssid"]), KeyType: fmt.Sprint(m["auth"]), CipherType: atoi(m["encryption"]),
			SignalLevel: atoi(m["rssi"])})
	}
	return out, nil
}

// --- Pan and tilt -------------------------------------------------------

// Move turns the camera by x (pan) and y (tilt) steps (motorMove). A
// camera that refuses it is sent the single form {"method": "do",
// "motor": {"move": ...}} where the transport allows.
func (c TapoCamera) Move(ctx context.Context, x, y int) error {
	mv := map[string]any{"motor": map[string]any{"move": map[string]any{"x_coord": strconv.Itoa(x), "y_coord": strconv.Itoa(y)}}}
	_, err := c.Call(ctx, "motorMove", mv)
	var se *SmartError
	if errors.As(err, &se) {
		if _, err2 := c.single(ctx, "do", "motor", mv["motor"]); err2 == nil {
			return nil
		}
	}
	return err
}

// MoveStep turns the camera one step towards angle degrees (0-359;
// relativeMove).
func (c TapoCamera) MoveStep(ctx context.Context, angle int) error {
	if angle < 0 || angle >= 360 {
		return fmt.Errorf("angle %d is not in 0-359", angle)
	}
	_, err := c.Call(ctx, "relativeMove", map[string]any{"motor": map[string]any{"movestep": map[string]any{"direction": strconv.Itoa(angle)}}})
	return err
}

// Calibrate runs the motor calibration (manualCalibrate).
func (c TapoCamera) Calibrate(ctx context.Context) error {
	_, err := c.Call(ctx, "manualCalibrate", map[string]any{"motor": map[string]any{"manual_cali": ""}})
	return err
}

// CamPreset is a saved camera position.
type CamPreset struct {
	ID   string
	Name string
}

// Presets reads the saved positions (getPresetConfig).
func (c TapoCamera) Presets(ctx context.Context) ([]CamPreset, error) {
	p, err := c.section(ctx, "getPresetConfig", "preset", "preset")
	if err != nil {
		return nil, err
	}
	pr := sub(p, "preset")
	ids, _ := pr["id"].([]any)
	names, _ := pr["name"].([]any)
	out := make([]CamPreset, 0, len(ids))
	for i, id := range ids {
		cp := CamPreset{ID: fmt.Sprint(id)}
		if i < len(names) {
			cp.Name = fmt.Sprint(names[i])
		}
		out = append(out, cp)
	}
	return out, nil
}

// GotoPreset turns the camera to a saved position (motorMoveToPreset).
func (c TapoCamera) GotoPreset(ctx context.Context, id string) error {
	_, err := c.Call(ctx, "motorMoveToPreset", map[string]any{"preset": map[string]any{"goto_preset": map[string]any{"id": id}}})
	return err
}

// SavePreset saves the current position under name (addMotorPostion, the
// device's spelling).
func (c TapoCamera) SavePreset(ctx context.Context, name string) error {
	_, err := c.Call(ctx, "addMotorPostion", map[string]any{"preset": map[string]any{"set_preset": map[string]any{"name": name, "save_ptz": "1"}}})
	return err
}

// DeletePreset removes saved positions (deletePreset).
func (c TapoCamera) DeletePreset(ctx context.Context, ids ...string) error {
	list := make([]any, len(ids))
	for i, id := range ids {
		list[i] = id
	}
	_, err := c.Call(ctx, "deletePreset", map[string]any{"preset": map[string]any{"remove_preset": map[string]any{"id": list}}})
	return err
}

// --- Privacy and status light -------------------------------------------

// Privacy reports whether the lens mask (privacy mode) is on
// (getLensMaskConfig). With it on the camera does not film.
func (c TapoCamera) Privacy(ctx context.Context) (bool, error) {
	m, err := c.section(ctx, "getLensMaskConfig", "lens_mask", "lens_mask_info")
	if err != nil {
		return false, err
	}
	return sub(m, "lens_mask_info")["enabled"] == "on", nil
}

// SetPrivacy switches the lens mask (setLensMaskConfig).
func (c TapoCamera) SetPrivacy(ctx context.Context, on bool) error {
	_, err := c.Call(ctx, "setLensMaskConfig", map[string]any{"lens_mask": map[string]any{"lens_mask_info": map[string]any{"enabled": onOff(on)}}})
	return err
}

// LED reports whether the status light is on (getLedStatus).
func (c TapoCamera) LED(ctx context.Context) (bool, error) {
	m, err := c.section(ctx, "getLedStatus", "led", "config")
	if err != nil {
		return false, err
	}
	return sub(m, "config")["enabled"] == "on", nil
}

// SetLED switches the status light (setLedStatus).
func (c TapoCamera) SetLED(ctx context.Context, on bool) error {
	_, err := c.Call(ctx, "setLedStatus", map[string]any{"led": map[string]any{"config": map[string]any{"enabled": onOff(on)}}})
	return err
}

// --- Detection ----------------------------------------------------------

// CamDetectionKind names a detection setting.
type CamDetectionKind string

// The detections cameras offer (each behind its own app component).
const (
	DetectMotion       CamDetectionKind = "motion"
	DetectPerson       CamDetectionKind = "person"
	DetectPet          CamDetectionKind = "pet"
	DetectVehicle      CamDetectionKind = "vehicle"
	DetectBabyCry      CamDetectionKind = "baby_cry"
	DetectBark         CamDetectionKind = "bark"
	DetectMeow         CamDetectionKind = "meow"
	DetectGlassBreak   CamDetectionKind = "glass_break"
	DetectTamper       CamDetectionKind = "tamper"
	DetectLineCrossing CamDetectionKind = "line_crossing"
)

// camDetection is the request naming of one detection: the getter and
// setter, the module and the section.
type camDetection struct{ get, set, module, section string }

var camDetections = map[CamDetectionKind]camDetection{
	DetectMotion:       {"getDetectionConfig", "setDetectionConfig", "motion_detection", "motion_det"},
	DetectPerson:       {"getPersonDetectionConfig", "setPersonDetectionConfig", "people_detection", "detection"},
	DetectPet:          {"getPetDetectionConfig", "setPetDetectionConfig", "pet_detection", "detection"},
	DetectVehicle:      {"getVehicleDetectionConfig", "setVehicleDetectionConfig", "vehicle_detection", "detection"},
	DetectBabyCry:      {"getBCDConfig", "setBCDConfig", "sound_detection", "bcd"},
	DetectBark:         {"getBarkDetectionConfig", "setBarkDetectionConfig", "bark_detection", "detection"},
	DetectMeow:         {"getMeowDetectionConfig", "setMeowDetectionConfig", "meow_detection", "detection"},
	DetectGlassBreak:   {"getGlassDetectionConfig", "setGlassDetectionConfig", "glass_detection", "detection"},
	DetectTamper:       {"getTamperDetectionConfig", "setTamperDetectionConfig", "tamper_detection", "tamper_det"},
	DetectLineCrossing: {"getLinecrossingDetectionConfig", "setLinecrossingDetectionConfig", "linecrossing_detection", "detection"},
}

// CamDetectionKinds lists every detection kind the helpers know.
func CamDetectionKinds() []CamDetectionKind {
	return []CamDetectionKind{DetectMotion, DetectPerson, DetectPet, DetectVehicle, DetectBabyCry, DetectBark, DetectMeow, DetectGlassBreak,
		DetectTamper, DetectLineCrossing}
}

// CamDetection is one detection setting: on or off, the sensitivity as
// the camera gives it (a level such as "medium", or a number as text;
// "digital_sensitivity" when present), and every field in Raw.
type CamDetection struct {
	Enabled     bool
	Sensitivity string
	Raw         map[string]any
}

func detectionOf(kind CamDetectionKind) (camDetection, error) {
	d, ok := camDetections[kind]
	if !ok {
		return d, fmt.Errorf("unknown detection %q", kind)
	}
	return d, nil
}

// Detection reads a detection setting (getDetectionConfig,
// getPersonDetectionConfig, ...; see CamDetectionKind).
func (c TapoCamera) Detection(ctx context.Context, kind CamDetectionKind) (CamDetection, error) {
	d, err := detectionOf(kind)
	if err != nil {
		return CamDetection{}, err
	}
	m, err := c.section(ctx, d.get, d.module, d.section)
	if err != nil {
		return CamDetection{}, err
	}
	s := sub(m, d.section)
	out := CamDetection{Enabled: s["enabled"] == "on", Raw: s}
	if v := str(s["digital_sensitivity"]); v != "" {
		out.Sensitivity = v
	} else if v, ok := s["sensitivity"]; ok {
		out.Sensitivity = fmt.Sprint(v)
	}
	return out, nil
}

// SetDetection switches a detection on or off.
func (c TapoCamera) SetDetection(ctx context.Context, kind CamDetectionKind, on bool) error {
	return c.SetDetectionConfig(ctx, kind, map[string]any{"enabled": onOff(on)})
}

// SetDetectionConfig changes a detection's fields as the camera names them
// (enabled "on"/"off", sensitivity, digital_sensitivity, ...).
func (c TapoCamera) SetDetectionConfig(ctx context.Context, kind CamDetectionKind, fields map[string]any) error {
	d, err := detectionOf(kind)
	if err != nil {
		return err
	}
	_, err = c.Call(ctx, d.set, map[string]any{d.module: map[string]any{d.section: fields}})
	return err
}

// CamLastAlarm is the last detection the camera alarmed on
// (getLastAlarmInfo).
type CamLastAlarm struct {
	Time time.Time // zero when there was none
	Type string    // motion, ...
}

// LastAlarm asks getLastAlarmInfo.
func (c TapoCamera) LastAlarm(ctx context.Context) (CamLastAlarm, error) {
	m, err := c.section(ctx, "getLastAlarmInfo", "system", "last_alarm_info")
	if err != nil {
		return CamLastAlarm{}, err
	}
	la := sub(m, "last_alarm_info")
	out := CamLastAlarm{Type: str(la["last_alarm_type"])}
	if ts := atoi(la["last_alarm_time"]); ts > 0 {
		out.Time = time.Unix(int64(ts), 0)
	}
	return out, nil
}

// --- Siren and alarm ----------------------------------------------------

// CamSiren is a siren's state and settings (doorbells, hubs, newer
// cameras): sounding or not, the sound, volume and duration in seconds,
// and the sounds it offers.
type CamSiren struct {
	Active   bool
	Sound    string
	Volume   int
	Duration int
	Sounds   []string
}

// sirenPart returns an answer's siren part, with or without the module
// level.
func sirenPart(res map[string]any) map[string]any {
	if s, ok := res["siren"].(map[string]any); ok {
		return s
	}
	return res
}

// Siren asks getSirenStatus, getSirenConfig and getSirenTypeList.
func (c TapoCamera) Siren(ctx context.Context) (CamSiren, error) {
	p := map[string]any{"siren": map[string]any{}}
	var out CamSiren
	for _, m := range []string{"getSirenStatus", "getSirenConfig", "getSirenTypeList"} {
		res, err := c.Call(ctx, m, p)
		if err != nil {
			return CamSiren{}, err
		}
		s := sirenPart(res)
		switch m {
		case "getSirenStatus":
			out.Active = str(s["status"]) != "" && str(s["status"]) != "off"
		case "getSirenConfig":
			out.Sound, out.Volume, out.Duration = str(s["siren_type"]), atoi(s["volume"]), atoi(s["duration"])
		default:
			list, _ := s["siren_type_list"].([]any)
			for _, x := range list {
				out.Sounds = append(out.Sounds, fmt.Sprint(x))
			}
		}
	}
	return out, nil
}

// SetSiren changes the siren's sound, volume (1-10) and duration in
// seconds (setSirenConfig); empty or zero values are left as they are.
func (c TapoCamera) SetSiren(ctx context.Context, sound string, volume, duration int) error {
	cfg := map[string]any{}
	if sound != "" {
		cfg["siren_type"] = sound
	}
	if volume > 0 {
		cfg["volume"] = strconv.Itoa(volume)
	}
	if duration > 0 {
		cfg["duration"] = duration
	}
	_, err := c.Call(ctx, "setSirenConfig", map[string]any{"siren": cfg})
	return err
}

// SoundSiren starts or stops the siren (setSirenStatus).
func (c TapoCamera) SoundSiren(ctx context.Context, on bool) error {
	_, err := c.Call(ctx, "setSirenStatus", map[string]any{"siren": map[string]any{"status": onOff(on)}})
	return err
}

// CamAlert is a camera's alarm on detection (msg_alarm
// chn1_msg_alarm_info): on or off, the alarm kinds (sound, light), the
// volume and duration as the camera gives them; Raw holds every field.
type CamAlert struct {
	Enabled  bool
	Modes    []string
	Volume   string
	Duration string
	Raw      map[string]any
}

// Alert asks getAlertConfig.
func (c TapoCamera) Alert(ctx context.Context) (CamAlert, error) {
	m, err := c.section(ctx, "getAlertConfig", "msg_alarm", "chn1_msg_alarm_info", "capability")
	if err != nil {
		return CamAlert{}, err
	}
	a := sub(m, "chn1_msg_alarm_info")
	out := CamAlert{Enabled: a["enabled"] == "on", Volume: str(a["alarm_volume"]), Duration: fmt.Sprint(a["alarm_duration"]), Raw: a}
	list, _ := a["alarm_mode"].([]any)
	for _, x := range list {
		out.Modes = append(out.Modes, fmt.Sprint(x))
	}
	return out, nil
}

// SetAlert changes the alarm on detection with the camera's field names
// (enabled "on"/"off", alarm_mode, alarm_volume, ...), as the single set
// request {"method": "set", "msg_alarm": {"chn1_msg_alarm_info": ...}}.
func (c TapoCamera) SetAlert(ctx context.Context, fields map[string]any) error {
	_, err := c.single(ctx, "set", "msg_alarm", map[string]any{"chn1_msg_alarm_info": fields})
	return err
}

// ManualAlarm starts or stops the alarm by hand ({"method": "do",
// "msg_alarm": {"manual_msg_alarm": {"action": "start"|"stop"}}}).
func (c TapoCamera) ManualAlarm(ctx context.Context, start bool) error {
	action := "stop"
	if start {
		action = "start"
	}
	_, err := c.single(ctx, "do", "msg_alarm", map[string]any{"manual_msg_alarm": map[string]any{"action": action}})
	return err
}

// --- Image --------------------------------------------------------------

// Night vision modes (night_vision_mode): infrared, full colour with the
// white light, and smart (infrared that switches to colour on motion).
const (
	NightVisionInfrared  = "inf_night_vision"
	NightVisionFullColor = "wtl_night_vision"
	NightVisionSmart     = "md_night_vision"
)

// NightVision asks the night vision mode (getNightVisionModeConfig,
// image.switch.night_vision_mode).
func (c TapoCamera) NightVision(ctx context.Context) (string, error) {
	m, err := c.section(ctx, "getNightVisionModeConfig", "image", "switch")
	if err != nil {
		return "", err
	}
	return str(sub(m, "switch")["night_vision_mode"]), nil
}

// SetNightVision sets the night vision mode (setNightVisionModeConfig).
func (c TapoCamera) SetNightVision(ctx context.Context, mode string) error {
	_, err := c.Call(ctx, "setNightVisionModeConfig", map[string]any{"image": map[string]any{"switch": map[string]any{"night_vision_mode": mode}}})
	return err
}

// DayNight asks the day and night switching of older firmware
// (getDayNightModeConfig, image.common.inf_type: auto, on, off).
func (c TapoCamera) DayNight(ctx context.Context) (string, error) {
	m, err := c.section(ctx, "getDayNightModeConfig", "image", "common")
	if err != nil {
		return "", err
	}
	return str(sub(m, "common")["inf_type"]), nil
}

// SetDayNight sets it (setDayNightModeConfig).
func (c TapoCamera) SetDayNight(ctx context.Context, mode string) error {
	_, err := c.Call(ctx, "setDayNightModeConfig", map[string]any{"image": map[string]any{"common": map[string]any{"inf_type": mode}}})
	return err
}

// --- Clock --------------------------------------------------------------

// CamTime is the camera's clock and time zone.
type CamTime struct {
	Time     time.Time // the clock, in the camera's zone when Go knows it
	ZoneID   string    // zone_id, an IANA name
	Timezone string    // timezone, "UTC+01:00"
}

// Time asks getClockStatus and getTimezone.
func (c TapoCamera) Time(ctx context.Context) (CamTime, error) {
	cs, err := c.section(ctx, "getClockStatus", "system", "clock_status")
	if err != nil {
		return CamTime{}, err
	}
	tz, err := c.section(ctx, "getTimezone", "system", "basic")
	if err != nil {
		return CamTime{}, err
	}
	b := sub(tz, "basic")
	out := CamTime{ZoneID: str(b["zone_id"]), Timezone: str(b["timezone"])}
	out.Time = time.Unix(int64(atoi(sub(cs, "clock_status")["seconds_from_1970"])), 0)
	if loc, err := time.LoadLocation(out.ZoneID); err == nil && out.ZoneID != "" {
		out.Time = out.Time.In(loc)
	}
	return out, nil
}

// SetTimezone sets the time zone (setTimezone): an IANA zone_id and its
// offset as "UTC+HH:MM". The camera keeps its clock by NTP; it takes no
// clock time.
func (c TapoCamera) SetTimezone(ctx context.Context, zoneID, offset string) error {
	_, err := c.Call(ctx, "setTimezone", map[string]any{"system": map[string]any{"basic": map[string]any{"zone_id": zoneID, "timezone": offset}}})
	return err
}

// TimezoneOffset formats an offset from UTC as cameras write it
// ("UTC+05:30").
func TimezoneOffset(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign, d = "-", -d
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, int(d.Hours()), int(d.Minutes())%60)
}

// --- Storage and recordings ---------------------------------------------

// CamDisk is one storage card (getSdCardStatus harddisk_manage.hd_info):
// its status (normal, offline, ...), sizes as the camera writes them
// ("29.7GB") and every field in Raw.
type CamDisk struct {
	Name       string
	Status     string
	TotalSpace string
	FreeSpace  string
	Raw        map[string]any
}

// SDCards asks getSdCardStatus.
func (c TapoCamera) SDCards(ctx context.Context) ([]CamDisk, error) {
	res, err := c.Call(ctx, "getSdCardStatus", map[string]any{"harddisk_manage": map[string]any{"table": []any{"hd_info"}}})
	if err != nil {
		return nil, err
	}
	list, _ := sub(res, "harddisk_manage")["hd_info"].([]any)
	var out []CamDisk
	for _, x := range list {
		m, _ := x.(map[string]any)
		for _, v := range m {
			d, _ := v.(map[string]any)
			if d == nil {
				continue
			}
			out = append(out, CamDisk{Name: str(d["disk_name"]), Status: str(d["status"]), TotalSpace: str(d["total_space"]), FreeSpace: str(d["free_space"]), Raw: d})
		}
	}
	return out, nil
}

// FormatSDCard erases the storage card (formatSdCard).
func (c TapoCamera) FormatSDCard(ctx context.Context) error {
	_, err := c.Call(ctx, "formatSdCard", map[string]any{"harddisk_manage": map[string]any{"format_hd": "1"}})
	return err
}

// RecordingDays lists the days between from and to (inclusive, as
// YYYYMMDD) that have recordings (searchDateWithVideo). For a camera
// behind a hub, childID is its device_id; "" otherwise.
func (c TapoCamera) RecordingDays(ctx context.Context, from, to time.Time, childID string) ([]string, error) {
	q := map[string]any{"channel": []any{0}, "start_date": from.Format("20060102"), "end_date": to.Format("20060102")}
	if childID != "" {
		q["child_device_id"] = childID
	}
	res, err := c.Call(ctx, "searchDateWithVideo", map[string]any{"playback": map[string]any{"search_year_utility": q}})
	if err != nil {
		return nil, err
	}
	list, _ := sub(res, "playback")["search_results"].([]any)
	var out []string
	for _, x := range list {
		m, _ := x.(map[string]any)
		for _, v := range m {
			if d := str(sub(map[string]any{"v": v}, "v")["date"]); d != "" {
				out = append(out, d)
			}
		}
	}
	return out, nil
}

// CamRecording is one recorded clip.
type CamRecording struct {
	Start, End time.Time
	Type       int // video_type: 1 timed, 2 motion, ... as the camera numbers them
}

// Recordings lists the clips between from and to (searchVideoWithUTC),
// entries start to end (0 and 0: the first 100). childID as for
// RecordingDays.
func (c TapoCamera) Recordings(ctx context.Context, from, to time.Time, start, end int, childID string) ([]CamRecording, error) {
	if end <= 0 {
		end = start + 99
	}
	q := map[string]any{"channel": 0, "start_time": from.Unix(), "end_time": to.Unix(), "start_index": start, "end_index": end}
	if childID != "" {
		q["child_device_id"] = childID
	}
	res, err := c.Call(ctx, "searchVideoWithUTC", map[string]any{"playback": map[string]any{"search_video_with_utc": q}})
	if err != nil {
		return nil, err
	}
	list, _ := sub(res, "playback")["search_video_results"].([]any)
	var out []CamRecording
	for _, x := range list {
		m, _ := x.(map[string]any)
		for _, v := range m {
			r, _ := v.(map[string]any)
			if r == nil {
				continue
			}
			rec := CamRecording{Type: atoi(r["video_type"])}
			rec.Start = time.Unix(int64(atoi(firstOf(r, "startTime", "start_time"))), 0)
			rec.End = time.Unix(int64(atoi(firstOf(r, "endTime", "end_time"))), 0)
			out = append(out, rec)
		}
	}
	return out, nil
}

func firstOf(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}
