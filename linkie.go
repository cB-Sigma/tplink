// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Two smaller HTTPS transports:
//
// Kasa cameras (KC series) take the legacy Kasa JSON over HTTPS, port
// 10443: POST /data/LINKIE2.json with HTTP basic authentication and a
// form field "content" holding the base64 of the JSON obscured with the
// legacy XOR (without the length prefix); the answer is the base64 of the
// obscured JSON. LinkieClient does that and is a KasaCaller.
//
// Tapo robot vacuums on older firmware take the Tapo request family as
// plain JSON over HTTPS, port 4433: POST /app {"method": "login",
// "params": {"username", "password": MD5 of the password, upper-case
// hexadecimal}} returns a token; later requests go to /app?token=…
// unencrypted. SSLClient does that and is a SmartCaller.

// LinkiePort is the port of the Kasa camera transport.
const LinkiePort = 10443

// LinkieClient talks to a Kasa camera. The device's user and password
// are its local ones; this module ships no default.
type LinkieClient struct {
	Base     string // https://host[:port], port 10443 when not given
	Username string
	Password string
	HTTP     *http.Client // InsecureHTTP for the self-signed certificate
}

// KasaCall sends one legacy Kasa request and returns the answer.
func (l *LinkieClient) KasaCall(ctx context.Context, req any) (map[string]any, error) {
	plain, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	content := base64.StdEncoding.EncodeToString(Encrypt(plain))
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.Base, "/")+"/data/LINKIE2.json",
		strings.NewReader("content="+url.QueryEscape(content)))
	if err != nil {
		return nil, err
	}
	r.SetBasicAuth(l.Username, l.Password)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := l.HTTP.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrKLAPAuth
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the camera answered HTTP %d", resp.StatusCode)
	}
	var out map[string]any
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err == nil {
		if json.Unmarshal(Decrypt(raw), &out) == nil {
			return out, nil
		}
	}
	if json.Unmarshal(b, &out) == nil {
		return nil, fmt.Errorf("the camera refused the request: %v", out)
	}
	return nil, fmt.Errorf("the camera's answer could not be read")
}

// SSLClient talks to a Tapo device on the plain HTTPS transport (older
// robot vacuum firmware), keeping its token.
type SSLClient struct {
	Base     string // https://host[:port], port 4433 when not given
	Username string
	Password string
	HTTP     *http.Client // InsecureHTTP for the self-signed certificate

	mu    sync.Mutex
	token string
	until time.Time
}

func (s *SSLClient) post(ctx context.Context, body any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	u := strings.TrimRight(s.Base, "/") + "/app"
	if s.token != "" {
		u += "?token=" + url.QueryEscape(s.token)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the device answered HTTP %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.Unmarshal(rb, &m); err != nil {
		return nil, fmt.Errorf("the device's answer is not JSON: %w", err)
	}
	return m, nil
}

// login logs in. The caller holds s.mu.
func (s *SSLClient) login(ctx context.Context) error {
	s.token = ""
	m, err := s.post(ctx, map[string]any{"method": "login", "params": map[string]any{"username": s.Username, "password": md5HexUp(s.Password)}})
	if err != nil {
		return err
	}
	switch c := errorCode(m); c {
	case 0:
	case aesErrLogin, -1003, sslErrInvalidNonce, 1111:
		return ErrKLAPAuth
	default:
		return fmt.Errorf("the device answered error %d to login", c)
	}
	res, _ := m["result"].(map[string]any)
	if s.token = str(res["token"]); s.token == "" {
		return fmt.Errorf("the device's login answer has no token")
	}
	s.until = time.Now().Add(23 * time.Hour)
	return nil
}

// Call sends one Tapo request and returns its result, logging in when
// needed.
func (s *SSLClient) Call(ctx context.Context, method string, params any) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if s.token == "" || time.Now().After(s.until) {
			if err := s.login(ctx); err != nil {
				return nil, err
			}
		}
		req := map[string]any{"method": method}
		if params != nil {
			req["params"] = params
		}
		m, err := s.post(ctx, req)
		if err != nil {
			s.token = ""
			return nil, err
		}
		switch c := errorCode(m); c {
		case 0:
			res, _ := m["result"].(map[string]any)
			if res == nil {
				res = map[string]any{}
			}
			return res, nil
		case aesErrSessionTimeout, aesErrSessionExpired, sslErrSessionExpired:
			s.token = ""
			continue
		default:
			return nil, &SmartError{Code: c, Method: method}
		}
	}
	return nil, fmt.Errorf("the device ended the HTTPS session twice")
}
