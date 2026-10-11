package tplink

import "strings"

// Colour-temperature ranges. A Kasa bulb does not report its range and
// answers an error for a value outside it, so the range comes from its
// model (facts as open-source clients publish them); a model not listed
// gets the narrowest common range. A Tapo bulb reports color_temp_range
// in get_device_info; without it 2500-6500 K is used.

type kelvinRange struct{ lo, hi float64 }

// kasaKelvin is matched by model prefix, longest first; the region in
// brackets matters for the KL120.
var kasaKelvin = []struct {
	prefix string
	r      kelvinRange
}{
	{"KL120(US)", kelvinRange{2700, 5000}},
	{"KL120", kelvinRange{2700, 6500}},
	{"KL125", kelvinRange{2500, 6500}},
	{"KL130", kelvinRange{2500, 9000}},
	{"KL135", kelvinRange{2500, 9000}},
	{"KL400", kelvinRange{2500, 9000}},
	{"KL420", kelvinRange{2500, 9000}},
	{"KL430", kelvinRange{2500, 9000}},
	{"LB120", kelvinRange{2700, 6500}},
	{"LB130", kelvinRange{2500, 9000}},
	{"LB230", kelvinRange{2500, 9000}},
	{"KB130", kelvinRange{2500, 9000}},
}

// fallbackKasaKelvin is the range for a Kasa model not listed.
var fallbackKasaKelvin = kelvinRange{2700, 5000}

// KasaKelvinRange is a Kasa bulb's colour-temperature range by model
// ("KL120(EU)"); known reports whether the model is listed.
func KasaKelvinRange(model string) (lo, hi float64, known bool) {
	m := strings.ToUpper(strings.ReplaceAll(model, " ", ""))
	for _, k := range kasaKelvin {
		if strings.HasPrefix(m, k.prefix) {
			return k.r.lo, k.r.hi, true
		}
	}
	return fallbackKasaKelvin.lo, fallbackKasaKelvin.hi, false
}

// TapoKelvinRange is a Tapo bulb's range from its get_device_info.
func TapoKelvinRange(info map[string]any) (lo, hi float64) {
	if r, ok := info["color_temp_range"].([]any); ok && len(r) == 2 {
		a, ok1 := num(r[0])
		b, ok2 := num(r[1])
		if ok1 && ok2 && a > 0 && b >= a {
			return a, b
		}
	}
	return 2500, 6500
}
