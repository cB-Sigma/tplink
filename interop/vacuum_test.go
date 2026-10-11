// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"testing"
	"time"

	"github.com/cB-Sigma/tplink"
)

// The vacuum helpers over the plain HTTPS transport against a device that
// answers from python-kasa's recorded RV30 Max(US) 1.2.0, compared with
// the recorded values.
func TestVacuumAgainstKasa(t *testing.T) {
	needDocker(t)
	base, _ := httpsDevice(t, "ssl", "RV30 Max(US)_1.0_1.2.0.json", user, pass)
	v := tplink.TapoVacuum{Caller: &tplink.SSLClient{Base: base, Username: user, Password: pass, HTTP: tplink.InsecureHTTP(5 * time.Second)}}

	st, err := v.Status(ctx)
	if err != nil || st.Status != tplink.VacuumCharged || st.Faulted() || st.Battery != 100 || st.CleanArea != 59 || st.CleanMinutes != 56 ||
		st.CleanPercent != 100 || st.Suction != tplink.SuctionStandard || st.Water != tplink.WaterLow || st.CleanCount != 1 ||
		st.Mode != tplink.VacuumModeHome || st.Working || st.Mapping || len(st.Raw) != 5 {
		t.Errorf("status %+v %v", st, err)
	}
	rec, err := v.CleanRecords(ctx)
	if err != nil || rec.TotalMinutes != 2510 || rec.TotalArea != 2304 || rec.TotalCount != 85 || len(rec.Records) != 15 ||
		rec.Last == nil || *rec.Last != (tplink.VacuumRecord{Timestamp: 1737387294, Minutes: 56, Area: 59, DustCollection: true}) {
		t.Errorf("records %+v %v", rec, err)
	}
	if r := rec.Records[12]; r.Timestamp != 1736881428 || r.Minutes != 68 || r.Area != 58 || !r.DustCollection || r.Error != 1 || r.MapID != 1736541042 || r.TaskType != 1 {
		t.Errorf("record 12 %+v", r)
	}
	c, err := v.Consumables(ctx)
	if err != nil || c.MainBrush != 2719 || c.SideBrush != 2743 || c.Filter != 287 || c.Sensor != 935 || c.ChargeContacts != 660 ||
		c.MainBrushLid != 2462 || c.Mop != 0 || len(c.Used) != 7 {
		t.Errorf("consumables %+v %v", c, err)
	}
	maps, err := v.Maps(ctx)
	if err != nil || maps.Current != 1734727686 || !maps.AutoChange || len(maps.Maps) != 3 || maps.Maps[0].Name != "#MASKED_NAME#" ||
		maps.Maps[1].ID != 1734742958 || !maps.Maps[0].Saved || maps.Maps[0].Updated != 1737387285 {
		t.Errorf("maps %+v %v", maps, err)
	}
	rooms, err := v.Rooms(ctx, maps.Current)
	if err != nil || len(rooms) != 5 || rooms[0] != (tplink.VacuumRoom{ID: 5, Name: "#MASKED_NAME#", Color: 3, Suction: 2, Water: 1, CleanCount: 1}) {
		t.Errorf("rooms %+v %v", rooms, err)
	}
	if vol, err := v.Volume(ctx); err != nil || vol != 60 {
		t.Errorf("volume %v %v", vol, err)
	}
	if mop, err := v.MopAttached(ctx); err != nil || mop {
		t.Errorf("mop %v %v", mop, err)
	}
	if b, err := v.CarpetBoost(ctx); err != nil || !b {
		t.Errorf("carpet boost %v %v", b, err)
	}
	if u, err := v.AreaUnit(ctx); err != nil || u != tplink.AreaSquareFeet {
		t.Errorf("area unit %v %v", u, err)
	}
	// The RV30 has no self-emptying dock: both requests are unknown.
	if _, err := v.DustCollection(ctx); !tplink.IsUnsupported(err) {
		t.Errorf("dust collection %v", err)
	}
}
