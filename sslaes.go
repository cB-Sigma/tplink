// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tapo cameras, doorbells and the H200 hub speak a third transport over
// HTTPS (port 443, self-signed certificates): a two-step login with
// nonces, then the securePassthrough envelope with keys derived from the
// login and every request signed in headers. Both steps are
// {"method": "login", "params": {"cnonce", "encrypt_type": "3",
// "username"}}: the first is answered with error -40413 and the device's
// nonce and a confirmation that proves it knows the password; the second
// adds "digest_passwd" and is answered with a session token ("stok") and a
// starting sequence. The password is used hashed: SHA-256, or MD5 on
// older firmware, as upper-case hexadecimal. Requests go to
// /stok=<token>/ds with "Seq" and "Tapo_tag" headers. Firmware that does
// not offer encrypt_type 3 takes a plain login with the MD5 hash and
// answers in clear. TP-Link documents none of it; the facts come from
// open-source clients (see PROVENANCE.md).
//
// Newer Kasa and Tapo firmware also serves KLAP over HTTPS, on port 4433:
// KLAPClient with Base "https://host:4433" and an HTTP client from
// InsecureHTTP does that.

// KLAPHTTPSPort is the port of KLAP over HTTPS.
const KLAPHTTPSPort = 4433

// InsecureHTTP is an HTTP client for the devices' self-signed
// certificates: it does not check the certificate, which a device on the
// LAN cannot have signed by a public authority. The sessions are still
// protected by the transports' own keys.
func InsecureHTTP(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // devices use self-signed certificates
	}}
}

// Error codes of the HTTPS transport.
const (
	sslErrInvalidNonce   = -40413 // first login step answered, or the digest refused
	sslErrSessionExpired = -40401
	sslErrBadUsername    = -40411
	sslErrDeviceBlocked  = -40404
	sslErrUnknownUser    = -60502
)

func sha256HexUp(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "")))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

func md5HexUp(s string) string {
	h := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// SSLAESConfirm is the device's proof of the password in the first login
// step, for a password hash (SSLAESPasswordHashes).
func SSLAESConfirm(cnonce, nonce, pwdHash string) string {
	return sha256HexUp(cnonce, pwdHash, nonce) + nonce + cnonce
}

// SSLAESDigest is the client's proof in the second login step.
func SSLAESDigest(cnonce, nonce, pwdHash string) string {
	return sha256HexUp(pwdHash, cnonce, nonce) + cnonce + nonce
}

// SSLAESPasswordHashes are the password hashes a device may hold, newest
// first: SHA-256 and MD5, upper-case hexadecimal.
func SSLAESPasswordHashes(password string) []string {
	return []string{sha256HexUp(password), md5HexUp(password)}
}

// SSLAESKeys derives the session's AES key and IV from the login.
func SSLAESKeys(cnonce, nonce, pwdHash string) (key, iv []byte) {
	hashed := sha256HexUp(cnonce, pwdHash, nonce)
	k := sha256.Sum256([]byte("lsk" + cnonce + nonce + hashed))
	v := sha256.Sum256([]byte("ivb" + cnonce + nonce + hashed))
	return k[:16], v[:16]
}

// SSLAESTag is the Tapo_tag header of a request body with its sequence.
func SSLAESTag(body []byte, cnonce, pwdHash string, seq int) string {
	return sha256HexUp(sha256HexUp(pwdHash, cnonce), string(body), strconv.Itoa(seq))
}

// SSLAESClient talks to a Tapo camera, doorbell or H200 hub over HTTPS,
// keeping its session. Username is the device's local user (the TP-Link
// account's e-mail on most firmware; cameras that were set up locally have
// their own); this module ships no default user.
type SSLAESClient struct {
	Base     string // https://host[:port], port 443 when not given
	Username string
	Password string
	HTTP     *http.Client // InsecureHTTP for self-signed certificates

	mu      sync.Mutex
	sess    *AESSession
	plain   bool // the plain login: answers in clear
	url     string
	cnonce  string
	pwdHash string
	seq     int
}

func (s *SSLAESClient) post(ctx context.Context, url string, body []byte, hdr map[string]string) (int, map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("requestByApp", "true")
	req.Header.Set("Referer", s.Base)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var m map[string]any
	if len(b) > 0 && json.Unmarshal(b, &m) != nil {
		return resp.StatusCode, nil, fmt.Errorf("the device's answer is not JSON (HTTP %d)", resp.StatusCode)
	}
	return resp.StatusCode, m, nil
}

func loginData(m map[string]any) map[string]any {
	res, _ := m["result"].(map[string]any)
	d, _ := res["data"].(map[string]any)
	if d == nil {
		d = map[string]any{}
	}
	return d
}

// login runs the two login steps (or the plain login). The caller holds
// s.mu.
func (s *SSLAESClient) login(ctx context.Context) error {
	s.sess, s.url, s.plain = nil, "", false
	var nb [8]byte
	_, _ = rand.Read(nb[:])
	cnonce := strings.ToUpper(hex.EncodeToString(nb[:]))
	body, _ := json.Marshal(map[string]any{"method": "login", "params": map[string]any{"cnonce": cnonce, "encrypt_type": "3", "username": s.Username}})
	code, m, err := s.post(ctx, s.Base, body, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("the HTTPS login answered HTTP %d", code)
	}
	ec := errorCode(m)
	data := loginData(m)
	if et, ok := data["encrypt_type"].([]any); ec == sslErrSessionExpired && ok && !(len(et) == 1 && str(et[0]) == "3") {
		return s.plainLogin(ctx)
	}
	if ec == sslErrDeviceBlocked || errorCode(map[string]any{"error_code": data["code"]}) == sslErrDeviceBlocked {
		return fmt.Errorf("the device blocked logins for a while (error %d)", sslErrDeviceBlocked)
	}
	nonce, confirm := str(data["nonce"]), str(data["device_confirm"])
	if ec != sslErrInvalidNonce || nonce == "" {
		if ec == sslErrSessionExpired || ec == sslErrUnknownUser || errorCode(map[string]any{"error_code": data["code"]}) == sslErrBadUsername {
			return ErrKLAPAuth
		}
		return fmt.Errorf("the HTTPS login's first step answered error %d", ec)
	}
	pwdHash := ""
	for _, h := range SSLAESPasswordHashes(s.Password) {
		if SSLAESConfirm(cnonce, nonce, h) == confirm {
			pwdHash = h
			break
		}
	}
	if pwdHash == "" {
		return ErrKLAPAuth
	}
	body, _ = json.Marshal(map[string]any{"method": "login", "params": map[string]any{"cnonce": cnonce, "encrypt_type": "3",
		"digest_passwd": SSLAESDigest(cnonce, nonce, pwdHash), "username": s.Username}})
	if code, m, err = s.post(ctx, s.Base, body, nil); err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("the HTTPS login's second step answered HTTP %d", code)
	}
	if ec := errorCode(m); ec == sslErrInvalidNonce {
		return ErrKLAPAuth
	} else if ec != 0 {
		return fmt.Errorf("the HTTPS login's second step answered error %d", ec)
	}
	res, _ := m["result"].(map[string]any)
	stok := str(res["stok"])
	seq, ok := num(res["start_seq"])
	if stok == "" || !ok {
		return errors.New("the HTTPS login answer has no token or sequence")
	}
	key, iv := SSLAESKeys(cnonce, nonce, pwdHash)
	s.sess = &AESSession{key: key, iv: iv}
	s.url = strings.TrimRight(s.Base, "/") + "/stok=" + stok + "/ds"
	s.cnonce, s.pwdHash, s.seq = cnonce, pwdHash, int(seq)
	return nil
}

// plainLogin is the login of firmware without encrypt_type 3.
func (s *SSLAESClient) plainLogin(ctx context.Context) error {
	body, _ := json.Marshal(map[string]any{"method": "login", "params": map[string]any{"hashed": true, "password": md5HexUp(s.Password), "username": s.Username}})
	code, m, err := s.post(ctx, s.Base, body, nil)
	if err != nil {
		return err
	}
	res, _ := m["result"].(map[string]any)
	if code != http.StatusOK || errorCode(m) != 0 || str(res["stok"]) == "" {
		return ErrKLAPAuth
	}
	s.plain = true
	s.url = strings.TrimRight(s.Base, "/") + "/stok=" + str(res["stok"]) + "/ds"
	return nil
}

// Handshake logs in now, without a request.
func (s *SSLAESClient) Handshake(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login(ctx)
}

// Send sends one request object ({"method", ...}) and returns the
// device's answer as it is (with error_code), logging in when needed.
func (s *SSLAESClient) Send(ctx context.Context, req any) (map[string]any, error) {
	plain, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if s.url == "" {
			if err := s.login(ctx); err != nil {
				return nil, err
			}
		}
		if s.plain {
			code, m, err := s.post(ctx, s.url, plain, nil)
			if err != nil {
				s.url = ""
				return nil, err
			}
			if code == http.StatusUnauthorized || errorCode(m) == sslErrSessionExpired {
				s.url = ""
				continue
			}
			return m, nil
		}
		body, _ := json.Marshal(map[string]any{"method": "securePassthrough", "params": map[string]any{"request": s.sess.Encrypt(plain)}})
		hdr := map[string]string{"Seq": strconv.Itoa(s.seq), "Tapo_tag": SSLAESTag(body, s.cnonce, s.pwdHash, s.seq)}
		s.seq++
		code, m, err := s.post(ctx, s.url, body, hdr)
		if err != nil {
			s.url = ""
			return nil, err
		}
		if code == http.StatusUnauthorized || code == http.StatusInternalServerError || errorCode(m) == sslErrSessionExpired {
			s.url = "" // the session ended: log in again
			continue
		}
		if code != http.StatusOK {
			s.url = ""
			return nil, fmt.Errorf("the device answered HTTP %d", code)
		}
		if c := errorCode(m); c != 0 {
			return map[string]any{"error_code": float64(c)}, nil
		}
		res, _ := m["result"].(map[string]any)
		raw, ok := res["response"].(string)
		if !ok {
			return m, nil // some firmware answers in clear
		}
		p, err := s.sess.Decrypt(raw)
		if err != nil {
			var clear map[string]any
			if json.Unmarshal([]byte(raw), &clear) == nil {
				return clear, nil
			}
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(p, &out); err != nil {
			return nil, fmt.Errorf("the passthrough answer is not JSON: %w", err)
		}
		return out, nil
	}
	return nil, errors.New("the device ended the HTTPS session twice")
}

// Call sends {"method", "params"} and returns the result, as KLAPClient
// and AESClient do. Cameras take most requests in a multipleRequest
// (MultiCall, CamGet).
func (s *SSLAESClient) Call(ctx context.Context, method string, params any) (map[string]any, error) {
	req := map[string]any{"method": method}
	if params != nil {
		req["params"] = params
	}
	m, err := s.Send(ctx, req)
	if err != nil {
		return nil, err
	}
	if c := errorCode(m); c != 0 {
		return nil, &SmartError{Code: c, Method: method}
	}
	res, _ := m["result"].(map[string]any)
	if res == nil {
		res = map[string]any{}
	}
	return res, nil
}

// --- Camera requests --------------------------------------------------------

// Camera requests ("smartcam") are camel-case methods whose params name a
// section: {"method": "getDeviceInfo", "params": {"device_info": {"name":
// ["basic_info"]}}}, answered {"device_info": {"basic_info": {...}}}.
// Clients send them in a multipleRequest. The H200 hub passes requests to
// its children with controlChild {"childControl": {"device_id",
// "request_data": {"method", "params"}}}, answered in response_data.

// CamGet sends one camera request in a multipleRequest and returns its
// result.
func CamGet(ctx context.Context, c SmartCaller, method string, params map[string]any) (map[string]any, error) {
	res, err := MultiCall(ctx, c, []SmartRequest{{Method: method, Params: params}}, 2)
	if err != nil {
		return nil, err
	}
	return res[0].Result, res[0].Err
}

// CamDeviceInfo asks a camera or H200 hub its basic information
// (getDeviceInfo, device_info.basic_info: device_model, device_type,
// sw_version, mac, device_alias, ...).
func CamDeviceInfo(ctx context.Context, c SmartCaller) (map[string]any, error) {
	res, err := CamGet(ctx, c, "getDeviceInfo", map[string]any{"device_info": map[string]any{"name": []any{"basic_info"}}})
	if err != nil {
		return nil, err
	}
	di, _ := res["device_info"].(map[string]any)
	bi, _ := di["basic_info"].(map[string]any)
	if bi == nil {
		return nil, errNoResult("getDeviceInfo", "device_info.basic_info")
	}
	return bi, nil
}

// CamChildList reads an H200 hub's children (getChildDeviceList, paged).
func CamChildList(ctx context.Context, c SmartCaller) ([]map[string]any, error) {
	var out []map[string]any
	for page := 0; page < 20; page++ {
		res, err := CamGet(ctx, c, "getChildDeviceList", map[string]any{"childControl": map[string]any{"start_index": len(out)}})
		if err != nil {
			return nil, err
		}
		list, _ := res["child_device_list"].([]any)
		for _, x := range list {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		sum, ok := num(res["sum"])
		if !ok || len(list) == 0 || len(out) >= int(sum) {
			break
		}
	}
	return out, nil
}

// CamControlChild sends one Tapo request ({"method", "params"}) to an
// H200 hub's child and returns its result.
func CamControlChild(ctx context.Context, c SmartCaller, deviceID, method string, params any) (map[string]any, error) {
	res, err := CamGet(ctx, c, "controlChild", map[string]any{"childControl": map[string]any{"device_id": deviceID,
		"request_data": map[string]any{"method": method, "params": params}}})
	if err != nil {
		return nil, err
	}
	rd, _ := res["response_data"].(map[string]any)
	if rd == nil {
		return map[string]any{}, nil
	}
	if code, ok := num(rd["error_code"]); ok && code != 0 {
		return nil, &SmartError{Code: int(code), Method: method}
	}
	out, _ := rd["result"].(map[string]any)
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}
