package tplink

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// KLAP is the local protocol of Tapo devices and of newer Kasa firmware:
// HTTP on port 80 with a two-step handshake proving both sides know the
// owner's TP-Link account (the auth hash), then AES-128-CBC requests
// signed with SHA-256 and numbered by a sequence. Version 2 (Tapo, some
// Kasa) hashes the account with SHA-1 and proves over both seeds; version
// 1 (Kasa on newer firmware) hashes it with MD5 and proves over one seed.
// The handshake1 proof tells which one the device holds. Tapo devices
// carry {"method", "params"} requests; Kasa devices the legacy Kasa JSON.
// TP-Link documents none of it; the facts come from public descriptions
// by open-source clients (see PROVENANCE.md).

// AuthHash is the KLAP v2 auth hash of an account:
// SHA-256(SHA-1(username) ‖ SHA-1(password)).
func AuthHash(username, password string) []byte {
	u := sha1.Sum([]byte(username))
	p := sha1.Sum([]byte(password))
	h := sha256.Sum256(append(u[:], p[:]...))
	return h[:]
}

// AuthHashV1 is the KLAP v1 auth hash, used by Kasa devices whose newer
// firmware moved to KLAP: MD5(MD5(username) ‖ MD5(password)).
func AuthHashV1(username, password string) []byte {
	u := md5.Sum([]byte(username))
	p := md5.Sum([]byte(password))
	h := md5.Sum(append(u[:], p[:]...))
	return h[:]
}

func sha(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// Session holds the keys of one KLAP handshake.
type Session struct {
	key    []byte // AES-128 key
	iv     []byte // 12-byte IV prefix
	sig    []byte // 28-byte signature key
	seq    int32
	cookie string
	until  time.Time
}

// NewSession derives the session keys from the seeds and the auth hash.
func NewSession(local, remote, auth []byte) *Session {
	ivFull := sha([]byte("iv"), local, remote, auth)
	return &Session{
		key: sha([]byte("lsk"), local, remote, auth)[:16],
		iv:  ivFull[:12],
		sig: sha([]byte("ldk"), local, remote, auth)[:28],
		seq: int32(binary.BigEndian.Uint32(ivFull[28:32])),
	}
}

func (s *Session) ivFor(seq int32) []byte {
	iv := make([]byte, 16)
	copy(iv, s.iv)
	binary.BigEndian.PutUint32(iv[12:], uint32(seq))
	return iv
}

// Encrypt returns the next sequence number and the request body
// (signature ‖ ciphertext).
func (s *Session) Encrypt(plain []byte) (int32, []byte) {
	s.seq++
	return s.seq, s.Seal(s.seq, plain)
}

// Seal encrypts and signs a body for a sequence number (the device's
// answer uses the request's).
func (s *Session) Seal(seq int32, plain []byte) []byte {
	blk, _ := aes.NewCipher(s.key)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	p := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct := make([]byte, len(p))
	cipher.NewCBCEncrypter(blk, s.ivFor(seq)).CryptBlocks(ct, p)
	var sb [4]byte
	binary.BigEndian.PutUint32(sb[:], uint32(seq))
	return append(sha(s.sig, sb[:], ct), ct...)
}

// Decrypt opens a body for a sequence number and checks its signature.
func (s *Session) Decrypt(seq int32, body []byte) ([]byte, error) {
	p, ok, err := s.Open(seq, body)
	if err == nil && !ok {
		return nil, errors.New("the KLAP answer's signature does not match")
	}
	return p, err
}

// Open decrypts a body for a sequence number and tells whether its
// signature matched.
func (s *Session) Open(seq int32, body []byte) ([]byte, bool, error) {
	if len(body) < 32+aes.BlockSize || (len(body)-32)%aes.BlockSize != 0 {
		return nil, false, errors.New("a KLAP answer of the wrong length")
	}
	ct := body[32:]
	var sb [4]byte
	binary.BigEndian.PutUint32(sb[:], uint32(seq))
	sigOK := bytes.Equal(sha(s.sig, sb[:], ct), body[:32])
	blk, _ := aes.NewCipher(s.key)
	p := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, s.ivFor(seq)).CryptBlocks(p, ct)
	pad := int(p[len(p)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(p) || !bytes.Equal(p[len(p)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, false, errors.New("a KLAP answer with bad padding")
	}
	return p[:len(p)-pad], sigOK, nil
}

// ErrKLAPAuth means the device does not know the account: the handshake
// hash did not match (wrong username or password, or a device of another
// account).
var ErrKLAPAuth = errors.New("the device refused the TP-Link account credentials")

// KLAPAuth is one auth hash a device may hold, with the KLAP version whose
// handshake proofs use it.
type KLAPAuth struct {
	Version int    // 1: proofs over one seed (Kasa on newer firmware); 2: over both seeds
	Hash    []byte // AuthHashV1 for version 1, AuthHash for version 2
	Name    string // account, blank, or the Name of an extra Credential
}

// Credential is an account to try besides the owner's: devices that were
// reset, set up only locally or unbound from the cloud may hold a setup
// account instead. This module ships none; an application that wants to
// try such accounts passes them to KLAPAuthsWith and AESLoginsWith.
type Credential struct {
	Name     string // reported as KLAPAuth.Name or AESLogin.Name when it matches
	Username string
	Password string
}

// KLAPAuths are the auth hashes tried in a handshake, in order: the
// account as KLAP v2 and v1, then blank credentials. The device's
// handshake1 proof tells which one it holds, so trying them costs no
// extra request.
func KLAPAuths(username, password string) []KLAPAuth {
	return KLAPAuthsWith(username, password)
}

// KLAPAuthsWith is KLAPAuths with more accounts, tried after the owner's
// (each as KLAP v2 and v1) and before blank credentials.
func KLAPAuthsWith(username, password string, extra ...Credential) []KLAPAuth {
	out := []KLAPAuth{{2, AuthHash(username, password), "account"}, {1, AuthHashV1(username, password), "account"}}
	for _, c := range extra {
		out = append(out, KLAPAuth{2, AuthHash(c.Username, c.Password), c.Name}, KLAPAuth{1, AuthHashV1(c.Username, c.Password), c.Name})
	}
	if username != "" || password != "" {
		out = append(out, KLAPAuth{2, AuthHash("", ""), "blank"}, KLAPAuth{1, AuthHashV1("", ""), "blank"})
	}
	return out
}

// proofs are the handshake1 proof the device sends and the handshake2
// proof the client answers, for a KLAP version.
func (a KLAPAuth) proofs(local, remote []byte) (server, client []byte) {
	if a.Version == 1 {
		return sha(local, a.Hash), sha(remote, a.Hash)
	}
	return sha(local, remote, a.Hash), sha(remote, local, a.Hash)
}

// KLAPClient talks KLAP to one device, keeping its session.
type KLAPClient struct {
	Base string // http://host[:port]
	// Auth is a KLAP v2 auth hash, used when Auths is empty.
	Auth []byte
	// Auths are the auth hashes to try (KLAPAuths); the first whose proof
	// the device sends is used.
	Auths []KLAPAuth
	HTTP  *http.Client

	mu      sync.Mutex
	sess    *Session
	matched KLAPAuth
	badSig  atomic.Int32
}

// Matched is the auth the last handshake matched (zero before one).
func (k *KLAPClient) Matched() KLAPAuth {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.matched
}

// BadSignatures counts answers whose signature did not match; they are
// used anyway (decryption and padding still check them), as other clients
// do not check answer signatures at all.
func (k *KLAPClient) BadSignatures() int { return int(k.badSig.Load()) }

func (k *KLAPClient) post(ctx context.Context, path, cookie string, body []byte) ([]byte, http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.Base+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.Header, resp.StatusCode, nil
}

func (k *KLAPClient) handshake(ctx context.Context) (*Session, error) {
	local := make([]byte, 16)
	_, _ = rand.Read(local)
	b, hdr, code, err := k.post(ctx, "/app/handshake1", "", local)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK || len(b) != 48 {
		return nil, fmt.Errorf("KLAP handshake1 answered %d with %d bytes", code, len(b))
	}
	remote, serverHash := b[:16], b[16:]
	auths := k.Auths
	if len(auths) == 0 {
		auths = []KLAPAuth{{2, k.Auth, "account"}}
	}
	var auth KLAPAuth
	var clientProof []byte
	for _, a := range auths {
		if sp, cp := a.proofs(local, remote); bytes.Equal(sp, serverHash) {
			auth, clientProof = a, cp
			break
		}
	}
	if clientProof == nil {
		return nil, ErrKLAPAuth
	}
	cookie := ""
	var timeout time.Duration = 20 * time.Hour
	for _, c := range hdr.Values("Set-Cookie") {
		for _, part := range strings.Split(c, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "TP_SESSIONID=") {
				cookie = part
			}
			if v, ok := strings.CutPrefix(part, "TIMEOUT="); ok {
				var secs int
				if _, err := fmt.Sscan(v, &secs); err == nil && secs > 0 {
					timeout = time.Duration(secs) * time.Second
				}
			}
		}
	}
	if _, _, code, err := k.post(ctx, "/app/handshake2", cookie, clientProof); err != nil {
		return nil, err
	} else if code != http.StatusOK {
		return nil, fmt.Errorf("KLAP handshake2 answered %d", code)
	}
	s := NewSession(local, remote, auth.Hash)
	s.cookie = cookie
	s.until = time.Now().Add(timeout - time.Minute)
	k.matched = auth
	return s, nil
}

// Handshake runs the two-step KLAP handshake now, without a request, and
// keeps the session. A device that answers the first step with 48 bytes
// speaks KLAP: then the error is nil, or ErrKLAPAuth when none of the auth
// hashes matched its proof.
func (k *KLAPClient) Handshake(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, err := k.handshake(ctx)
	if err == nil {
		k.sess = s
	}
	return err
}

// Send sends one plain request body and returns the device's plain
// answer, doing the handshake when there is no live session. The body is
// a Tapo request ({"method", "params"}) or, for Kasa devices on KLAP, the
// legacy Kasa JSON.
func (k *KLAPClient) Send(ctx context.Context, plain []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if k.sess == nil || time.Now().After(k.sess.until) {
			s, err := k.handshake(ctx)
			if err != nil {
				return nil, err
			}
			k.sess = s
		}
		seq, body := k.sess.Encrypt(plain)
		b, _, code, err := k.post(ctx, fmt.Sprintf("/app/request?seq=%d", seq), k.sess.cookie, body)
		if err != nil {
			k.sess = nil
			return nil, err
		}
		if code == http.StatusForbidden || code == http.StatusUnauthorized {
			k.sess = nil // the session ended on the device: handshake again
			continue
		}
		if code != http.StatusOK {
			k.sess = nil
			return nil, fmt.Errorf("KLAP request answered %d", code)
		}
		p, sigOK, err := k.sess.Open(seq, b)
		if err != nil {
			k.sess = nil
			return nil, err
		}
		if !sigOK {
			k.badSig.Add(1)
		}
		return p, nil
	}
	return nil, errors.New("the device ended the KLAP session twice")
}

// ErrNotSmart means the device answered a Tapo request without a Tapo
// result (a Kasa device on KLAP, which wants the legacy JSON).
var ErrNotSmart = errors.New("the device did not answer the Tapo request")

// Call sends one Tapo request ({"method": …, "params": …}) and returns its
// result.
func (k *KLAPClient) Call(ctx context.Context, method string, params any) (map[string]any, error) {
	plain, _ := json.Marshal(map[string]any{"method": method, "params": params, "requestTimeMils": time.Now().UnixMilli()})
	p, err := k.Send(ctx, plain)
	if err != nil {
		return nil, err
	}
	var out struct {
		ErrorCode *float64       `json:"error_code"`
		Result    map[string]any `json:"result"`
	}
	if err := json.Unmarshal(p, &out); err != nil {
		return nil, err
	}
	if out.ErrorCode == nil {
		return nil, fmt.Errorf("%w %s", ErrNotSmart, method)
	}
	if *out.ErrorCode != 0 {
		return nil, &SmartError{Code: int(*out.ErrorCode), Method: method}
	}
	if out.Result == nil {
		out.Result = map[string]any{}
	}
	return out.Result, nil
}

// KasaCall sends a legacy Kasa request through KLAP (Kasa devices on
// newer firmware) and returns the answer, as KasaRequest does on TCP 9999.
func (k *KLAPClient) KasaCall(ctx context.Context, req any) (map[string]any, error) {
	plain, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	p, err := k.Send(ctx, plain)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(p, &out); err != nil {
		return nil, fmt.Errorf("the device's answer is not JSON: %w", err)
	}
	return out, nil
}
