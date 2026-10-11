// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"regexp"
	"strings"
)

func str(v any) string { s, _ := v.(string); return s }

func num(v any) (float64, bool) { f, ok := v.(float64); return f, ok }

var macRE = regexp.MustCompile(`[^0-9a-f]`)

// NormaliseMAC gives a MAC address as 12 lower-case hexadecimal digits,
// dropping separators ("" if it is not one).
func NormaliseMAC(s string) string {
	m := macRE.ReplaceAllString(strings.ToLower(s), "")
	if len(m) != 12 {
		return ""
	}
	return m
}
