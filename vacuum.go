// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Tapo robot vacuums (device type SMART.TAPOROBOVAC) take the Tapo request
// family with their own camel-case methods: getVacStatus, getCleanInfo,
// setSwitchClean and so on. Older firmware speaks the plain HTTPS
// transport (SSLClient); newer firmware KLAP or securePassthrough. The
// helpers below are each one request, or one MultiCall, named in their
// documentation; Caller.Call reaches anything else.

// TapoVacuum is a Tapo robot vacuum over any Tapo transport.
type TapoVacuum struct {
	Caller SmartCaller // an SSLClient, KLAPClient or AESClient
}

// VacuumStatusCode is the state getVacStatus reports.
type VacuumStatusCode int

// The states a vacuum reports.
const (
	VacuumIdle      VacuumStatusCode = 0
	VacuumCleaning  VacuumStatusCode = 1
	VacuumMapping   VacuumStatusCode = 2
	VacuumGoingHome VacuumStatusCode = 4
	VacuumCharging  VacuumStatusCode = 5
	VacuumCharged   VacuumStatusCode = 6
	VacuumPaused    VacuumStatusCode = 7
	VacuumUndocked  VacuumStatusCode = 8
	VacuumFault     VacuumStatusCode = 100
)

var vacuumStatusNames = map[VacuumStatusCode]string{
	VacuumIdle: "idle", VacuumCleaning: "cleaning", VacuumMapping: "mapping", VacuumGoingHome: "going home",
	VacuumCharging: "charging", VacuumCharged: "charged", VacuumPaused: "paused", VacuumUndocked: "undocked", VacuumFault: "error",
}

// String names the state ("status 3" for a code not known).
func (s VacuumStatusCode) String() string {
	if n, ok := vacuumStatusNames[s]; ok {
		return n
	}
	return "status " + itoa(int(s))
}

// VacuumSuction is the fan power (getCleanAttr suction).
type VacuumSuction int

// The suction levels, weakest first.
const (
	SuctionQuiet    VacuumSuction = 1
	SuctionStandard VacuumSuction = 2
	SuctionTurbo    VacuumSuction = 3
	SuctionMax      VacuumSuction = 4
	SuctionUltra    VacuumSuction = 5
)

// VacuumWater is the mop's water flow (getCleanAttr cistern).
type VacuumWater int

// The water levels.
const (
	WaterOff    VacuumWater = 0
	WaterLow    VacuumWater = 1
	WaterMedium VacuumWater = 2
	WaterHigh   VacuumWater = 3
)

// VacuumCleanMode is what a clean covers (setSwitchClean clean_mode,
// getCleanStatus clean_status).
type VacuumCleanMode int

// The clean modes.
const (
	VacuumModeHome       VacuumCleanMode = 0 // every room alike
	VacuumModeHomeCustom VacuumCleanMode = 1 // every room with its own settings and order
	VacuumModeSpot       VacuumCleanMode = 2 // around where it stands
	VacuumModeRooms      VacuumCleanMode = 3 // the rooms named
	VacuumModeZones      VacuumCleanMode = 4 // drawn zones
	VacuumModePreset     VacuumCleanMode = 5 // a saved preset
)

// VacuumStatus is a vacuum's state from one MultiCall of getVacStatus,
// getBatteryInfo, getCleanInfo, getCleanAttr and getCleanStatus. A
// request the device does not answer leaves its fields zero (Raw lacks
// it).
type VacuumStatus struct {
	Status       VacuumStatusCode
	Errors       []int // err_status codes other than 0
	Battery      int   // percent
	CleanArea    int   // of the current or last clean, in AreaUnit
	CleanMinutes int
	CleanPercent int
	Suction      VacuumSuction
	Water        VacuumWater
	CleanCount   int // passes per clean
	Mode         VacuumCleanMode
	Mapping      bool
	Working      bool
	Relocating   bool
	Raw          map[string]map[string]any // the answers by method
}

// Faulted reports whether the vacuum reports an error.
func (s VacuumStatus) Faulted() bool { return s.Status == VacuumFault || len(s.Errors) > 0 }

func intOf(v any) int {
	if n, ok := num(v); ok {
		return int(n)
	}
	switch x := v.(type) {
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

func boolOf(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	}
	return false
}

func itoa(n int) string { return strconv.Itoa(n) }

// unnest returns m[key] when the device nests its answer under the method
// name (some firmware does for getCleanStatus and getMapData), else m.
func unnest(m map[string]any, key string) map[string]any {
	if in, ok := m[key].(map[string]any); ok {
		return in
	}
	return m
}

var globalAttr = map[string]any{"type": "global"}

// Status asks getVacStatus, getBatteryInfo, getCleanInfo, getCleanAttr
// {"type": "global"} and getCleanStatus in one MultiCall. The error is set
// only when the transport failed.
func (v TapoVacuum) Status(ctx context.Context) (VacuumStatus, error) {
	reqs := []SmartRequest{{Method: "getVacStatus"}, {Method: "getBatteryInfo"}, {Method: "getCleanInfo"},
		{Method: "getCleanAttr", Params: globalAttr}, {Method: "getCleanStatus"}}
	res, err := MultiCall(ctx, v.Caller, reqs, len(reqs))
	if err != nil {
		return VacuumStatus{}, err
	}
	out := VacuumStatus{Raw: map[string]map[string]any{}}
	for _, r := range res {
		if r.Err != nil || r.Result == nil {
			continue
		}
		m := r.Result
		out.Raw[r.Method] = m
		switch r.Method {
		case "getVacStatus":
			out.Status = VacuumStatusCode(intOf(m["status"]))
			list, _ := m["err_status"].([]any)
			for _, e := range list {
				if c := intOf(e); c != 0 {
					out.Errors = append(out.Errors, c)
				}
			}
		case "getBatteryInfo":
			out.Battery = intOf(m["battery_percentage"])
		case "getCleanInfo":
			out.CleanArea, out.CleanMinutes, out.CleanPercent = intOf(m["clean_area"]), intOf(m["clean_time"]), intOf(m["clean_percent"])
		case "getCleanAttr":
			out.Suction, out.Water, out.CleanCount = VacuumSuction(intOf(m["suction"])), VacuumWater(intOf(m["cistern"])), intOf(m["clean_number"])
		case "getCleanStatus":
			m = unnest(m, "getCleanStatus")
			out.Mode = VacuumCleanMode(intOf(m["clean_status"]))
			out.Mapping, out.Working, out.Relocating = boolOf(m["is_mapping"]), boolOf(m["is_working"]), boolOf(m["is_relocating"])
		}
	}
	return out, nil
}

func (v TapoVacuum) send(ctx context.Context, method string, params any) error {
	_, err := v.Caller.Call(ctx, method, params)
	return err
}

// Start cleans the whole home (setSwitchClean with clean_mode 0, clean_on,
// clean_order and force_clean false). A paused clean is continued with
// Resume.
func (v TapoVacuum) Start(ctx context.Context) error {
	return v.send(ctx, "setSwitchClean", map[string]any{"clean_mode": int(VacuumModeHome), "clean_on": true, "clean_order": true, "force_clean": false})
}

// CleanRooms cleans the rooms (ids from Rooms) of a map (setSwitchClean
// with clean_mode 3, map_id, room_list and start_type 1), with the global
// suction, water and pass count.
func (v TapoVacuum) CleanRooms(ctx context.Context, mapID int64, rooms []int) error {
	if len(rooms) == 0 {
		return errors.New("tplink: no rooms to clean")
	}
	return v.send(ctx, "setSwitchClean", map[string]any{"clean_mode": int(VacuumModeRooms), "clean_on": true, "clean_order": true, "force_clean": false,
		"map_id": mapID, "room_list": rooms, "start_type": 1})
}

// Pause pauses a clean (setRobotPause {"pause": true}).
func (v TapoVacuum) Pause(ctx context.Context) error {
	return v.send(ctx, "setRobotPause", map[string]any{"pause": true})
}

// Resume continues a paused clean (setRobotPause {"pause": false}).
func (v TapoVacuum) Resume(ctx context.Context) error {
	return v.send(ctx, "setRobotPause", map[string]any{"pause": false})
}

// ReturnHome sends the vacuum to its dock (setSwitchCharge
// {"switch_charge": true}).
func (v TapoVacuum) ReturnHome(ctx context.Context) error {
	return v.send(ctx, "setSwitchCharge", map[string]any{"switch_charge": true})
}

// StopReturn stops the way to the dock (setSwitchCharge
// {"switch_charge": false}).
func (v TapoVacuum) StopReturn(ctx context.Context) error {
	return v.send(ctx, "setSwitchCharge", map[string]any{"switch_charge": false})
}

func (v TapoVacuum) setAttr(ctx context.Context, name string, value int) error {
	return v.send(ctx, "setCleanAttr", map[string]any{name: value, "type": "global"})
}

// SetSuction sets the fan power (setCleanAttr suction, type global).
func (v TapoVacuum) SetSuction(ctx context.Context, s VacuumSuction) error {
	return v.setAttr(ctx, "suction", int(s))
}

// SetWaterLevel sets the mop's water flow (setCleanAttr cistern, type
// global).
func (v TapoVacuum) SetWaterLevel(ctx context.Context, w VacuumWater) error {
	return v.setAttr(ctx, "cistern", int(w))
}

// SetCleanCount sets the passes per clean, 1 to 3 on known firmware
// (setCleanAttr clean_number, type global).
func (v TapoVacuum) SetCleanCount(ctx context.Context, n int) error {
	return v.setAttr(ctx, "clean_number", n)
}

// The consumable names ResetConsumable takes (the getConsumablesInfo
// field without "_time").
const (
	ConsumableMainBrush      = "roll_brush"
	ConsumableSideBrush      = "edge_brush"
	ConsumableFilter         = "filter"
	ConsumableSensor         = "sensor"
	ConsumableChargeContacts = "charge_contact"
	ConsumableMainBrushLid   = "main_brush_lid"
	ConsumableMop            = "rag"
)

// VacuumConsumables is getConsumablesInfo: minutes of use since each part
// was last reset. Used holds every *_time field by consumable name.
type VacuumConsumables struct {
	MainBrush      int
	SideBrush      int
	Filter         int
	Sensor         int
	ChargeContacts int
	MainBrushLid   int
	Mop            int
	Used           map[string]int
}

// Consumables asks getConsumablesInfo.
func (v TapoVacuum) Consumables(ctx context.Context) (VacuumConsumables, error) {
	res, err := v.Caller.Call(ctx, "getConsumablesInfo", nil)
	if err != nil {
		return VacuumConsumables{}, err
	}
	out := VacuumConsumables{Used: map[string]int{}}
	for k, x := range res {
		if name, ok := strings.CutSuffix(k, "_time"); ok {
			out.Used[name] = intOf(x)
		}
	}
	out.MainBrush, out.SideBrush, out.Filter = out.Used[ConsumableMainBrush], out.Used[ConsumableSideBrush], out.Used[ConsumableFilter]
	out.Sensor, out.ChargeContacts = out.Used[ConsumableSensor], out.Used[ConsumableChargeContacts]
	out.MainBrushLid, out.Mop = out.Used[ConsumableMainBrushLid], out.Used[ConsumableMop]
	return out, nil
}

// ResetConsumable zeroes a part's use after it was replaced
// (resetConsumablesTime {"reset_list": [name]}); name is a Consumable*
// constant (a trailing "_time" is dropped).
func (v TapoVacuum) ResetConsumable(ctx context.Context, name string) error {
	return v.send(ctx, "resetConsumablesTime", map[string]any{"reset_list": []string{strings.TrimSuffix(name, "_time")}})
}

// VacuumRecord is one clean of the history.
type VacuumRecord struct {
	Timestamp      int64 `json:"timestamp"` // Unix seconds of the start
	Minutes        int   `json:"clean_time"`
	Area           int   `json:"clean_area"`
	DustCollection bool  `json:"dust_collection"`
	Error          int   `json:"error"`
	MapID          int64 `json:"map_id"`
	StartType      int   `json:"start_type"`
	TaskType       int   `json:"task_type"`
	Index          int   `json:"record_index"`
}

// VacuumRecords is getCleanRecords: totals, the recent cleans and the
// latest day's clean.
type VacuumRecords struct {
	TotalMinutes int
	TotalArea    int
	TotalCount   int
	Records      []VacuumRecord
	Last         *VacuumRecord // lastest_day_record; nil when absent
	Raw          map[string]any
}

// CleanRecords asks getCleanRecords.
func (v TapoVacuum) CleanRecords(ctx context.Context) (VacuumRecords, error) {
	res, err := v.Caller.Call(ctx, "getCleanRecords", nil)
	if err != nil {
		return VacuumRecords{}, err
	}
	out := VacuumRecords{TotalMinutes: intOf(res["total_time"]), TotalArea: intOf(res["total_area"]), TotalCount: intOf(res["total_number"]), Raw: res}
	list, _ := res["record_list"].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		out.Records = append(out.Records, VacuumRecord{Timestamp: int64(intOf(m["timestamp"])), Minutes: intOf(m["clean_time"]), Area: intOf(m["clean_area"]),
			DustCollection: boolOf(m["dust_collection"]), Error: intOf(m["error"]), MapID: int64(intOf(m["map_id"])), StartType: intOf(m["start_type"]),
			TaskType: intOf(m["task_type"]), Index: intOf(m["record_index"])})
	}
	// The latest day's clean is an array: timestamp, minutes, area, dust
	// collection.
	if a, ok := res["lastest_day_record"].([]any); ok && len(a) >= 4 {
		out.Last = &VacuumRecord{Timestamp: int64(intOf(a[0])), Minutes: intOf(a[1]), Area: intOf(a[2]), DustCollection: boolOf(a[3])}
	}
	return out, nil
}

// VacuumMap is one saved map.
type VacuumMap struct {
	ID      int64
	Name    string // decoded from base64
	Saved   bool
	Locked  bool
	Updated int64 // Unix seconds
}

// VacuumMaps is getMapInfo.
type VacuumMaps struct {
	Current    int64 // current_map_id; 0 before the first map
	AutoChange bool
	Maps       []VacuumMap
}

// Maps asks getMapInfo.
func (v TapoVacuum) Maps(ctx context.Context) (VacuumMaps, error) {
	res, err := v.Caller.Call(ctx, "getMapInfo", nil)
	if err != nil {
		return VacuumMaps{}, err
	}
	out := VacuumMaps{Current: int64(intOf(res["current_map_id"])), AutoChange: boolOf(res["auto_change_map"])}
	list, _ := res["map_list"].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		out.Maps = append(out.Maps, VacuumMap{ID: int64(intOf(m["map_id"])), Name: DecodeNickname(str(m["map_name"])), Saved: boolOf(m["is_saved"]),
			Locked: boolOf(m["map_locked"]), Updated: int64(intOf(m["update_time"]))})
	}
	return out, nil
}

// VacuumRoom is a room of a map, with its own settings (zero when the
// room has none).
type VacuumRoom struct {
	ID         int
	Name       string // decoded from base64
	Color      int
	Suction    VacuumSuction
	Water      VacuumWater
	CleanCount int
}

// Rooms reads the rooms of a map (getMapData {"map_id", "type": 0}, the
// area_list entries of type "room").
func (v TapoVacuum) Rooms(ctx context.Context, mapID int64) ([]VacuumRoom, error) {
	res, err := v.Caller.Call(ctx, "getMapData", map[string]any{"map_id": mapID, "type": 0})
	if err != nil {
		return nil, err
	}
	res = unnest(res, "getMapData")
	list, _ := res["area_list"].([]any)
	out := []VacuumRoom{}
	for _, x := range list {
		m, _ := x.(map[string]any)
		if str(m["type"]) != "room" {
			continue
		}
		out = append(out, VacuumRoom{ID: intOf(m["id"]), Name: DecodeNickname(str(m["name"])), Color: intOf(m["color"]),
			Suction: VacuumSuction(intOf(m["suction"])), Water: VacuumWater(intOf(m["cistern"])), CleanCount: intOf(m["clean_number"])})
	}
	return out, nil
}

func (v TapoVacuum) field(ctx context.Context, method, key string) (any, error) {
	res, err := v.Caller.Call(ctx, method, nil)
	if err != nil {
		return nil, err
	}
	x, ok := res[key]
	if !ok {
		return nil, errNoResult(method, key)
	}
	return x, nil
}

// MopAttached asks getMopState.
func (v TapoVacuum) MopAttached(ctx context.Context) (bool, error) {
	x, err := v.field(ctx, "getMopState", "mop_state")
	return boolOf(x), err
}

// DustMode is how hard a dock empties the dustbin.
type DustMode int

// The emptying modes.
const (
	DustSmart    DustMode = 0
	DustLight    DustMode = 1
	DustBalanced DustMode = 2
	DustMax      DustMode = 3
)

// VacuumDustCollection is a self-emptying dock's setting
// (getDustCollectionInfo).
type VacuumDustCollection struct {
	Auto bool     // empty after each clean
	Mode DustMode // dust_collection_mode
}

// DustCollection asks getDustCollectionInfo; firmware without it is asked
// getAutoDustCollection (Mode then stays DustSmart).
func (v TapoVacuum) DustCollection(ctx context.Context) (VacuumDustCollection, error) {
	res, err := v.Caller.Call(ctx, "getDustCollectionInfo", nil)
	if IsUnsupported(err) {
		x, err := v.field(ctx, "getAutoDustCollection", "auto_dust_collection")
		return VacuumDustCollection{Auto: boolOf(x)}, err
	}
	if err != nil {
		return VacuumDustCollection{}, err
	}
	return VacuumDustCollection{Auto: boolOf(res["auto_dust_collection"]), Mode: DustMode(intOf(res["dust_collection_mode"]))}, nil
}

// SetDustCollection sends setDustCollectionInfo.
func (v TapoVacuum) SetDustCollection(ctx context.Context, d VacuumDustCollection) error {
	return v.send(ctx, "setDustCollectionInfo", map[string]any{"auto_dust_collection": d.Auto, "dust_collection_mode": int(d.Mode)})
}

// EmptyDustbin makes the dock empty the dustbin now
// (setSwitchDustCollection {"switch_dust_collection": true}).
func (v TapoVacuum) EmptyDustbin(ctx context.Context) error {
	return v.send(ctx, "setSwitchDustCollection", map[string]any{"switch_dust_collection": true})
}

// Volume asks getVolume (percent).
func (v TapoVacuum) Volume(ctx context.Context) (int, error) {
	x, err := v.field(ctx, "getVolume", "volume")
	return intOf(x), err
}

// SetVolume sends setVolume (0 to 100).
func (v TapoVacuum) SetVolume(ctx context.Context, volume int) error {
	if volume < 0 || volume > 100 {
		return errors.New("tplink: volume is 0 to 100")
	}
	return v.send(ctx, "setVolume", map[string]any{"volume": volume})
}

// Locate makes the vacuum call out (playSelectAudio {"audio_type":
// "seek_me"}).
func (v TapoVacuum) Locate(ctx context.Context) error {
	return v.send(ctx, "playSelectAudio", map[string]any{"audio_type": "seek_me"})
}

// CarpetBoost asks getCarpetClean: whether suction rises on carpet
// (carpet_clean_prefer "boost" rather than "normal").
func (v TapoVacuum) CarpetBoost(ctx context.Context) (bool, error) {
	x, err := v.field(ctx, "getCarpetClean", "carpet_clean_prefer")
	return str(x) == "boost", err
}

// SetCarpetBoost sends setCarpetClean with "boost" or "normal".
func (v TapoVacuum) SetCarpetBoost(ctx context.Context, on bool) error {
	mode := "normal"
	if on {
		mode = "boost"
	}
	return v.send(ctx, "setCarpetClean", map[string]any{"carpet_clean_prefer": mode})
}

// VacuumAreaUnit is the unit the vacuum reports areas in.
type VacuumAreaUnit int

// The area units.
const (
	AreaSquareMetres VacuumAreaUnit = 0
	AreaSquareFeet   VacuumAreaUnit = 1
	AreaPing         VacuumAreaUnit = 2 // the Taiwanese unit, about 3.3 m²
)

// AreaUnit asks getAreaUnit.
func (v TapoVacuum) AreaUnit(ctx context.Context) (VacuumAreaUnit, error) {
	x, err := v.field(ctx, "getAreaUnit", "area_unit")
	return VacuumAreaUnit(intOf(x)), err
}
