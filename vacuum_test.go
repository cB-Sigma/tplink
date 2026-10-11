// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/cB-Sigma/tplink"
)

// The vacuum helpers send the requests open-source clients describe and
// read the answers' shapes, including the nested getCleanStatus some
// firmware sends and a request the device lacks.
func TestTapoVacuumRequests(t *testing.T) {
	var got []string
	answers := map[string]map[string]any{
		"getVacStatus":       {"err_status": []any{0.0, 22.0}, "status": 7.0},
		"getBatteryInfo":     {"battery_percentage": 64.0},
		"getCleanInfo":       {"clean_area": 12.0, "clean_time": 15.0, "clean_percent": 40.0},
		"getCleanAttr":       {"suction": 3.0, "cistern": 2.0, "clean_number": 2.0},
		"getCleanStatus":     {"getCleanStatus": map[string]any{"clean_status": 3.0, "is_mapping": false, "is_working": true, "is_relocating": false}},
		"getConsumablesInfo": {"roll_brush_time": 100.0, "edge_brush_time": 50.0, "filter_time": 20.0, "sensor_time": 5.0, "charge_contact_time": 4.0, "rag_time": 0.0},
		"getCleanRecords": {"total_time": 300.0, "total_area": 200.0, "total_number": 6.0, "lastest_day_record": []any{1760000000.0, 30.0, 25.0, 1.0},
			"record_list": []any{map[string]any{"timestamp": 1759990000.0, "clean_time": 40.0, "clean_area": 33.0, "dust_collection": true, "map_id": 77.0, "record_index": 0.0}}},
		"getMapInfo": {"current_map_id": 77.0, "auto_change_map": true, "map_list": []any{map[string]any{"map_id": 77.0, "map_name": "SG9tZQ==", "is_saved": true, "map_locked": 0.0}}},
		"getMapData": {"area_list": []any{map[string]any{"id": 2.0, "name": "S2l0Y2hlbg==", "type": "room", "suction": 2.0, "cistern": 1.0, "clean_number": 1.0},
			map[string]any{"id": 401.0, "type": "virtual_wall"}}},
		"getMopState":    {"mop_state": true},
		"getVolume":      {"volume": 60.0},
		"getCarpetClean": {"carpet_clean_prefer": "boost"},
		"getAreaUnit":    {"area_unit": 1.0},
	}
	f := &fakeSmart{answer: func(method string, p map[string]any) (map[string]any, error) {
		b, _ := json.Marshal(p)
		got = append(got, method+" "+string(b))
		if method == "multipleRequest" {
			var out []any
			for _, x := range p["requests"].([]any) {
				m := x.(map[string]any)["method"].(string)
				if a, ok := answers[m]; ok {
					out = append(out, map[string]any{"method": m, "error_code": 0.0, "result": a})
				} else {
					out = append(out, map[string]any{"method": m, "error_code": -1002.0})
				}
			}
			return map[string]any{"responses": out}, nil
		}
		if method == "getDustCollectionInfo" {
			return nil, &tplink.SmartError{Code: -1002, Method: method}
		}
		if method == "getAutoDustCollection" {
			return map[string]any{"auto_dust_collection": 1.0}, nil
		}
		if a, ok := answers[method]; ok {
			return a, nil
		}
		return map[string]any{}, nil
	}}
	v := tplink.TapoVacuum{Caller: f}

	st, err := v.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != tplink.VacuumPaused || !reflect.DeepEqual(st.Errors, []int{22}) || !st.Faulted() || st.Battery != 64 || st.CleanArea != 12 ||
		st.CleanMinutes != 15 || st.CleanPercent != 40 || st.Suction != tplink.SuctionTurbo || st.Water != tplink.WaterMedium || st.CleanCount != 2 ||
		st.Mode != tplink.VacuumModeRooms || !st.Working || st.Mapping || st.Status.String() != "paused" {
		t.Errorf("status %+v", st)
	}
	steps := []func() error{
		func() error { return v.Start(ctx) },
		func() error { return v.CleanRooms(ctx, 77, []int{2, 3}) },
		func() error { return v.Pause(ctx) },
		func() error { return v.Resume(ctx) },
		func() error { return v.ReturnHome(ctx) },
		func() error { return v.StopReturn(ctx) },
		func() error { return v.SetSuction(ctx, tplink.SuctionMax) },
		func() error { return v.SetWaterLevel(ctx, tplink.WaterHigh) },
		func() error { return v.SetCleanCount(ctx, 3) },
		func() error { return v.ResetConsumable(ctx, "filter_time") },
		func() error {
			return v.SetDustCollection(ctx, tplink.VacuumDustCollection{Auto: true, Mode: tplink.DustBalanced})
		},
		func() error { return v.EmptyDustbin(ctx) },
		func() error { return v.SetVolume(ctx, 30) },
		func() error { return v.Locate(ctx) },
		func() error { return v.SetCarpetBoost(ctx, false) },
	}
	for i, s := range steps {
		if err := s(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if err := v.CleanRooms(ctx, 77, nil); err == nil {
		t.Error("no rooms accepted")
	}
	if err := v.SetVolume(ctx, 101); err == nil {
		t.Error("volume 101 accepted")
	}
	c, err := v.Consumables(ctx)
	if err != nil || c.MainBrush != 100 || c.SideBrush != 50 || c.Filter != 20 || c.Sensor != 5 || c.ChargeContacts != 4 || len(c.Used) != 6 {
		t.Errorf("consumables %+v %v", c, err)
	}
	r, err := v.CleanRecords(ctx)
	if err != nil || r.TotalMinutes != 300 || r.TotalArea != 200 || r.TotalCount != 6 || len(r.Records) != 1 || !r.Records[0].DustCollection ||
		r.Records[0].MapID != 77 || r.Last == nil || *r.Last != (tplink.VacuumRecord{Timestamp: 1760000000, Minutes: 30, Area: 25, DustCollection: true}) {
		t.Errorf("records %+v %v", r, err)
	}
	m, err := v.Maps(ctx)
	if err != nil || m.Current != 77 || !m.AutoChange || len(m.Maps) != 1 || m.Maps[0].Name != "Home" || !m.Maps[0].Saved {
		t.Errorf("maps %+v %v", m, err)
	}
	rooms, err := v.Rooms(ctx, 77)
	if err != nil || !reflect.DeepEqual(rooms, []tplink.VacuumRoom{{ID: 2, Name: "Kitchen", Suction: 2, Water: 1, CleanCount: 1}}) {
		t.Errorf("rooms %+v %v", rooms, err)
	}
	if mop, err := v.MopAttached(ctx); err != nil || !mop {
		t.Errorf("mop %v %v", mop, err)
	}
	if d, err := v.DustCollection(ctx); err != nil || !d.Auto {
		t.Errorf("dust %+v %v", d, err)
	}
	if vol, err := v.Volume(ctx); err != nil || vol != 60 {
		t.Errorf("volume %v %v", vol, err)
	}
	if b, err := v.CarpetBoost(ctx); err != nil || !b {
		t.Errorf("carpet %v %v", b, err)
	}
	if u, err := v.AreaUnit(ctx); err != nil || u != tplink.AreaSquareFeet {
		t.Errorf("area unit %v %v", u, err)
	}
	want := []string{
		`multipleRequest {"requests":[{"method":"getVacStatus"},{"method":"getBatteryInfo"},{"method":"getCleanInfo"},{"method":"getCleanAttr","params":{"type":"global"}},{"method":"getCleanStatus"}]}`,
		`setSwitchClean {"clean_mode":0,"clean_on":true,"clean_order":true,"force_clean":false}`,
		`setSwitchClean {"clean_mode":3,"clean_on":true,"clean_order":true,"force_clean":false,"map_id":77,"room_list":[2,3],"start_type":1}`,
		`setRobotPause {"pause":true}`,
		`setRobotPause {"pause":false}`,
		`setSwitchCharge {"switch_charge":true}`,
		`setSwitchCharge {"switch_charge":false}`,
		`setCleanAttr {"suction":4,"type":"global"}`,
		`setCleanAttr {"cistern":3,"type":"global"}`,
		`setCleanAttr {"clean_number":3,"type":"global"}`,
		`resetConsumablesTime {"reset_list":["filter"]}`,
		`setDustCollectionInfo {"auto_dust_collection":true,"dust_collection_mode":2}`,
		`setSwitchDustCollection {"switch_dust_collection":true}`,
		`setVolume {"volume":30}`,
		`playSelectAudio {"audio_type":"seek_me"}`,
		`setCarpetClean {"carpet_clean_prefer":"normal"}`,
		`getConsumablesInfo null`,
		`getCleanRecords null`,
		`getMapInfo null`,
		`getMapData {"map_id":77,"type":0}`,
		`getMopState null`,
		`getDustCollectionInfo null`,
		`getAutoDustCollection null`,
		`getVolume null`,
		`getCarpetClean null`,
		`getAreaUnit null`,
	}
	if !reflect.DeepEqual(got, want) {
		for i := range got {
			t.Logf("%d %s", i, got[i])
		}
		t.Errorf("requests differ")
	}
}

// A transport failure fails Status; a request the device lacks leaves its
// fields zero.
func TestTapoVacuumStatusPartial(t *testing.T) {
	f := &fakeSmart{answer: func(method string, p map[string]any) (map[string]any, error) {
		if method == "multipleRequest" {
			return nil, &tplink.SmartError{Code: -1002, Method: method} // asked one by one
		}
		if method == "getVacStatus" {
			return map[string]any{"status": 6.0, "err_status": []any{0.0}}, nil
		}
		return nil, &tplink.SmartError{Code: -1002, Method: method}
	}}
	st, err := tplink.TapoVacuum{Caller: f}.Status(ctx)
	if err != nil || st.Status != tplink.VacuumCharged || st.Faulted() || st.Battery != 0 || len(st.Raw) != 1 {
		t.Errorf("status %+v %v", st, err)
	}
	bad := &fakeSmart{answer: func(string, map[string]any) (map[string]any, error) { return nil, errTransport }}
	if _, err := (tplink.TapoVacuum{Caller: bad}).Status(ctx); err == nil {
		t.Error("transport failure not reported")
	}
}

var errTransport = errors.New("connection refused")
