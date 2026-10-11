package tplink

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Older Tapo firmware (before KLAP) speaks "securePassthrough": plain JSON
// over HTTP to /app, where the client first sends an RSA public key
// (method handshake), the device answers an AES-128 key and IV encrypted
// to it with RSA PKCS#1 v1.5 and sets a session cookie, the client logs in
// (login_device with the account's SHA-1 hashed email and the password,
// base64; login version 2 sends the password SHA-1 hashed as password2)
// and gets a token, and every request after that is
// {"method": "securePassthrough", "params": {"request": base64 AES-CBC}}
// to /app?token=…, answered the same way. TP-Link documents none of it;
// the facts come from public descriptions by open-source clients.

// Tapo error codes the transport reacts to.
const (
	aesErrLogin          = -1501 // the credentials were refused
	aesErrSessionTimeout = 9999  // the session or token is no longer valid
	aesErrSessionExpired = 1003
)

// AESSession is the symmetric part of a securePassthrough session.
type AESSession struct {
	key, iv []byte
}

// NewAESSession takes the 32 bytes the device sent (key ‖ IV).
func NewAESSession(keyIV []byte) (*AESSession, error) {
	if len(keyIV) != 32 {
		return nil, fmt.Errorf("a handshake key of %d bytes, not 32", len(keyIV))
	}
	return &AESSession{key: keyIV[:16], iv: keyIV[16:]}, nil
}

// Encrypt pads (PKCS#7), encrypts and base64-encodes a payload.
func (s *AESSession) Encrypt(plain []byte) string {
	blk, _ := aes.NewCipher(s.key)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	p := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(p))
	cipher.NewCBCEncrypter(blk, s.iv).CryptBlocks(ct, p)
	return base64.StdEncoding.EncodeToString(ct)
}

// Decrypt reverses Encrypt.
func (s *AESSession) Decrypt(b64 string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("the passthrough answer is not base64: %w", err)
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("a passthrough answer of the wrong length")
	}
	blk, _ := aes.NewCipher(s.key)
	p := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, s.iv).CryptBlocks(p, ct)
	pad := int(p[len(p)-1])
	if pad < 1 || pad > aes.BlockSize || !bytes.Equal(p[len(p)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("a passthrough answer with bad padding")
	}
	return p[:len(p)-pad], nil
}

func sha1Hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// AESLogin is one set of login_device parameters to try.
type AESLogin struct {
	Name   string // account, or the Name of an extra Credential
	Params map[string]any
}

// AESLogins are the login_device parameters tried, in order: the account
// with the login version the device announced first (2 when unknown),
// then the other version.
func AESLogins(username, password string, version int) []AESLogin {
	return AESLoginsWith(username, password, version)
}

// AESLoginsWith is AESLogins with more accounts, each tried after the
// owner's with login version 2, then 1.
func AESLoginsWith(username, password string, version int, extra ...Credential) []AESLogin {
	v1 := func(u, p string) map[string]any {
		return map[string]any{"username": base64.StdEncoding.EncodeToString([]byte(sha1Hex(u))), "password": base64.StdEncoding.EncodeToString([]byte(p))}
	}
	v2 := func(u, p string) map[string]any {
		return map[string]any{"username": base64.StdEncoding.EncodeToString([]byte(sha1Hex(u))), "password2": base64.StdEncoding.EncodeToString([]byte(sha1Hex(p)))}
	}
	var out []AESLogin
	if username != "" || password != "" {
		if version == 1 {
			out = append(out, AESLogin{"account", v1(username, password)}, AESLogin{"account", v2(username, password)})
		} else {
			out = append(out, AESLogin{"account", v2(username, password)}, AESLogin{"account", v1(username, password)})
		}
	}
	for _, c := range extra {
		out = append(out, AESLogin{c.Name, v2(c.Username, c.Password)}, AESLogin{c.Name, v1(c.Username, c.Password)})
	}
	return out
}

// AESClient talks securePassthrough to one device, keeping its session.
type AESClient struct {
	Base   string // http://host[:port]
	Logins []AESLogin
	HTTP   *http.Client

	mu      sync.Mutex
	key     *rsa.PrivateKey
	sess    *AESSession
	cookie  string
	token   string
	until   time.Time
	matched string
}

// Matched names the login the device accepted ("" before one).
func (a *AESClient) Matched() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.matched
}

func (a *AESClient) postJSON(ctx context.Context, url string, body any) (map[string]any, http.Header, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cookie != "" {
		req.Header.Set("Cookie", a.cookie)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, fmt.Errorf("the device answered HTTP %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, resp.Header, fmt.Errorf("the device's answer is not JSON: %w", err)
	}
	return out, resp.Header, nil
}

func errorCode(m map[string]any) int {
	c, _ := m["error_code"].(float64)
	return int(c)
}

// handshake sends the public key and reads the session key.
func (a *AESClient) handshake(ctx context.Context) error {
	if a.key == nil {
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return err
		}
		a.key = k
	}
	der, _ := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	a.cookie, a.token, a.sess = "", "", nil
	m, hdr, err := a.postJSON(ctx, a.Base+"/app", map[string]any{"method": "handshake", "params": map[string]any{"key": pub}})
	if err != nil {
		return err
	}
	if c := errorCode(m); c != 0 {
		return fmt.Errorf("the securePassthrough handshake answered error %d", c)
	}
	res, _ := m["result"].(map[string]any)
	enc, err := base64.StdEncoding.DecodeString(str(res["key"]))
	if err != nil {
		return fmt.Errorf("the handshake key is not base64: %w", err)
	}
	keyIV, err := rsa.DecryptPKCS1v15(nil, a.key, enc)
	if err != nil {
		return errors.New("the handshake key could not be decrypted")
	}
	s, err := NewAESSession(keyIV)
	if err != nil {
		return err
	}
	timeout := 24 * time.Hour
	for _, c := range hdr.Values("Set-Cookie") {
		for _, part := range strings.Split(c, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "TP_SESSIONID=") || strings.HasPrefix(part, "SESSIONID=") {
				a.cookie = part
			}
			if v, ok := strings.CutPrefix(part, "TIMEOUT="); ok {
				var secs int
				if _, err := fmt.Sscan(v, &secs); err == nil && secs > 0 {
					timeout = time.Duration(secs) * time.Second
				}
			}
		}
	}
	a.sess, a.until = s, time.Now().Add(timeout-time.Minute)
	return nil
}

// Handshake runs the securePassthrough key exchange now, without logging
// in: it succeeds on a device that speaks securePassthrough, whatever the
// account.
func (a *AESClient) Handshake(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.handshake(ctx)
}

// passthrough sends one inner request on the session and returns the
// inner answer.
func (a *AESClient) passthrough(ctx context.Context, inner map[string]any) (map[string]any, error) {
	plain, _ := json.Marshal(inner)
	url := a.Base + "/app"
	if a.token != "" {
		url += "?token=" + a.token
	}
	m, _, err := a.postJSON(ctx, url, map[string]any{"method": "securePassthrough", "params": map[string]any{"request": a.sess.Encrypt(plain)}})
	if err != nil {
		return nil, err
	}
	if c := errorCode(m); c != 0 {
		return map[string]any{"error_code": float64(c)}, nil
	}
	res, _ := m["result"].(map[string]any)
	p, err := a.sess.Decrypt(str(res["response"]))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(p, &out); err != nil {
		return nil, fmt.Errorf("the passthrough answer is not JSON: %w", err)
	}
	return out, nil
}

// login does the handshake and logs in, trying each login in turn (a
// refused login needs a new handshake).
func (a *AESClient) login(ctx context.Context) error {
	for _, l := range a.Logins {
		if err := a.handshake(ctx); err != nil {
			return err
		}
		out, err := a.passthrough(ctx, map[string]any{"method": "login_device", "params": l.Params, "request_time_milis": time.Now().UnixMilli()})
		if err != nil {
			return err
		}
		if c := errorCode(out); c != 0 {
			if c == aesErrLogin {
				continue
			}
			return fmt.Errorf("the device answered error %d to login_device", c)
		}
		res, _ := out["result"].(map[string]any)
		a.token = str(res["token"])
		if a.token == "" {
			return errors.New("the device's login answer has no token")
		}
		a.matched = l.Name
		return nil
	}
	a.sess = nil
	return ErrKLAPAuth
}

// Call sends one Tapo request and returns its result.
func (a *AESClient) Call(ctx context.Context, method string, params any) (map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if a.sess == nil || a.token == "" || time.Now().After(a.until) {
			if err := a.login(ctx); err != nil {
				return nil, err
			}
		}
		out, err := a.passthrough(ctx, map[string]any{"method": method, "params": params, "requestTimeMils": time.Now().UnixMilli()})
		if err != nil {
			a.sess = nil
			return nil, err
		}
		switch c := errorCode(out); c {
		case 0:
			res, _ := out["result"].(map[string]any)
			if res == nil {
				res = map[string]any{}
			}
			return res, nil
		case aesErrSessionTimeout, aesErrSessionExpired:
			a.sess = nil // log in again
			continue
		default:
			return nil, &SmartError{Code: c, Method: method}
		}
	}
	return nil, errors.New("the device ended the securePassthrough session twice")
}
