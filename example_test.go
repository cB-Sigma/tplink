// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cB-Sigma/tplink"
)

// Find Tapo devices and switch the first one on over KLAP or
// securePassthrough, whichever it asks for. It needs devices on the LAN,
// so it is not run; github.com/cB-Sigma/tplink-sim runs the same steps
// against simulated devices.
func Example() {
	ctx := context.Background()
	const email, password = "user@example.invalid", "the TP-Link account's password"

	found, err := tplink.TapoDiscover(ctx, "255.255.255.255:20002", 3*time.Second)
	if err != nil || len(found) == 0 {
		fmt.Println(found, err)
		return
	}
	f := found[0]
	base := "http://" + f.Host
	if f.HTTPPort != 0 && f.HTTPPort != 80 {
		base = fmt.Sprintf("http://%s:%d", f.Host, f.HTTPPort)
	}
	var c tplink.SmartCaller
	if f.Protocol() == "aes" {
		c = &tplink.AESClient{Base: base, Logins: tplink.AESLogins(email, password, f.LoginVersion), HTTP: &http.Client{Timeout: 5 * time.Second}}
	} else {
		c = &tplink.KLAPClient{Base: base, Auths: tplink.KLAPAuths(email, password), HTTP: &http.Client{Timeout: 5 * time.Second}}
	}
	if _, err := c.Call(ctx, "set_device_info", map[string]any{"device_on": true}); err != nil {
		fmt.Println(err)
		return
	}
	info, _ := c.Call(ctx, "get_device_info", nil)
	fmt.Println(f.Model, info["device_on"])
}

// Read a Kasa plug on the legacy protocol, which needs no account. It
// needs a device, so it is not run.
func ExampleKasaRequest() {
	m, err := tplink.KasaRequest(context.Background(), "192.168.1.40:9999",
		map[string]any{"system": map[string]any{"get_sysinfo": map[string]any{}}}, 3*time.Second)
	if err != nil {
		fmt.Println(err)
		return
	}
	info := m["system"].(map[string]any)["get_sysinfo"].(map[string]any)
	fmt.Println(info["alias"], info["relay_state"])
}

func ExampleEncrypt() {
	fmt.Printf("% x\n", tplink.Encrypt([]byte(`{"a":1}`)))
	fmt.Println(string(tplink.Decrypt(tplink.Encrypt([]byte(`{"a":1}`)))))
	// Output:
	// d0 f2 93 b1 8b ba c7
	// {"a":1}
}
