// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// TPAP is the login of Tapo devices and cameras on newer firmware when
// the Tapo app's third-party compatibility option is off. The client and
// the device run SPAKE2+ (RFC 9383) on P-256 with SHA-256, HKDF-SHA256 and
// HMAC-SHA256: the client proves it knows a passcode derived from the
// owner's account password without sending it, and the device proves it
// knows it too. Both derive a key from the exchange; requests then go to
// /stok=<token>/ds as AES-128-CCM ciphertext numbered by a sequence.
//
// Every message of the login is JSON to the device's root path,
// {"method": "login", "params": {"sub_method": ...}}:
//
//   - discover: whether the device is in TPAP mode, and how to reach it
//     (the "tpap" object: TLS mode, port, passcode types);
//   - pake_register: the client's random and the suites it offers; the
//     device answers with its random, the PBKDF2 salt and iterations, its
//     share and how the password becomes the passcode (extra_crypt);
//   - pake_share: the client's share and confirmation; the device answers
//     with its confirmation, the session token and the first sequence
//     number.
//
// Only what public descriptions cover is implemented: cipher suite 1, the
// aes_128_ccm session cipher and the account password as passcode, which
// is what the tapo crate 0.11.1 uses with real devices. The default
// passcode, other suites and the device certificate check (dac) are not;
// see the README. TP-Link documents none of it (see PROVENANCE.md).

// Errors of the TPAP login.
var (
	// ErrTPAPAuth means the device refused the password.
	ErrTPAPAuth = errors.New("the device refused the password (TPAP)")
	// ErrTPAPLocked means the device locked itself after too many failed
	// logins; it refuses every login for a while, so do not retry at once.
	ErrTPAPLocked = errors.New("the device is locked after too many failed TPAP logins")
	// ErrTPAPDeviceProof means the device accepted the login but could not
	// prove that it knows the password: not the device it claims to be.
	ErrTPAPDeviceProof = errors.New("the device could not prove it knows the password (TPAP)")
	// ErrTPAPUnsupported means the device asks for a part of TPAP this
	// module does not implement.
	ErrTPAPUnsupported = errors.New("the device asks for a TPAP variant this module does not support")
)

// Error codes of the TPAP login.
const (
	tpapErrLocked      = -2101
	tpapErrCredentials = -2203
	tpapErrSession     = -2402
)

// TPAPInfo is how a device in TPAP mode wants to be logged in to: the
// "tpap" object of its discover answer or of its 20002 discovery answer.
type TPAPInfo struct {
	// TLS is 0 for plain HTTP, 1 for HTTPS with a certificate the client
	// does not check, 2 for HTTPS with one it checks.
	TLS int
	// Port is the port the login and requests go to (0: 80, or 443 over
	// TLS).
	Port int
	// Pake are the passcode types the device takes: 0 the default
	// passcode, 2 the account password, others.
	Pake []int
	// DAC and NOC are the device's certificate flags, as announced.
	DAC, NOC int
}

// ParseTPAPInfo reads a "tpap" object.
func ParseTPAPInfo(v any) (TPAPInfo, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return TPAPInfo{}, fmt.Errorf("%w: the tpap object is %T", ErrTPAPUnsupported, v)
	}
	var info TPAPInfo
	intOf := func(k string) (int, error) {
		x, has := m[k]
		if !has || x == nil {
			return 0, nil
		}
		f, ok := x.(float64)
		if !ok {
			return 0, fmt.Errorf("%w: tpap %s is %v", ErrTPAPUnsupported, k, x)
		}
		return int(f), nil
	}
	var err error
	if info.TLS, err = intOf("tls"); err != nil {
		return TPAPInfo{}, err
	}
	if info.Port, err = intOf("port"); err != nil {
		return TPAPInfo{}, err
	}
	if info.DAC, err = intOf("dac"); err != nil {
		return TPAPInfo{}, err
	}
	if info.NOC, err = intOf("noc"); err != nil {
		return TPAPInfo{}, err
	}
	if p, has := m["pake"]; has && p != nil {
		list, ok := p.([]any)
		if !ok {
			return TPAPInfo{}, fmt.Errorf("%w: tpap pake is %v", ErrTPAPUnsupported, p)
		}
		for _, x := range list {
			f, ok := x.(float64)
			if !ok {
				return TPAPInfo{}, fmt.Errorf("%w: tpap pake is %v", ErrTPAPUnsupported, p)
			}
			info.Pake = append(info.Pake, int(f))
		}
	}
	return info, nil
}

// TPAPCameraInfo is how a camera reached by its address is logged in to
// over TPAP: the account password over HTTPS on port 443. Cameras do not
// answer discover; these are the values a C220 announces in its 20002
// answer, as the tapo crate records.
func TPAPCameraInfo() TPAPInfo { return TPAPInfo{TLS: 1, Pake: []int{2}} }

// BaseURL is the URL of a device at host for TPAPClient.Base. A host that
// names a port (a forwarded port, a simulator) keeps it.
func (i TPAPInfo) BaseURL(host string) string {
	scheme, port := "http", 80
	if i.TLS != 0 {
		scheme, port = "https", 443
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		return scheme + "://" + net.JoinHostPort(h, p)
	}
	if i.Port > 0 {
		port = i.Port
	}
	return scheme + "://" + net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

// PasscodeType is the passcode_type the client offers: "userpw" (the
// account password) when the device lists type 2. The Tapo app prefers the
// default passcode when a device lists it as well; this client offers the
// account password then too, as it has no default passcode.
func (i TPAPInfo) PasscodeType() (string, error) {
	for _, p := range i.Pake {
		if p == 2 {
			return "userpw", nil
		}
	}
	return "", fmt.Errorf("%w: passcode types %v (only 2, the account password, is supported)", ErrTPAPUnsupported, i.Pake)
}

// TPAPDiscover asks the device at base (http://host[:port], port 80 on
// devices) whether it is in TPAP mode. It returns the device's TPAPInfo, or
// nil when the device does not answer as a device in TPAP mode (KLAP mode,
// older firmware). ErrTPAPLocked when the device is locked.
func TPAPDiscover(ctx context.Context, hc *http.Client, base string) (*TPAPInfo, error) {
	body, _ := json.Marshal(map[string]any{"method": "login", "params": map[string]any{"sub_method": "discover"}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var m struct {
		ErrorCode *float64       `json:"error_code"`
		Result    map[string]any `json:"result"`
	}
	if json.Unmarshal(b, &m) != nil || m.ErrorCode == nil {
		return nil, nil
	}
	if int(*m.ErrorCode) == tpapErrLocked {
		return nil, ErrTPAPLocked
	}
	if *m.ErrorCode != 0 {
		return nil, nil
	}
	t, ok := m.Result["tpap"].(map[string]any)
	if !ok {
		return nil, nil
	}
	info, err := ParseTPAPInfo(t)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// TPAPPasscodeSHA1 is the passcode of extra_crypt password_shadow with
// passwd_id 2: the lower-case hex SHA-1 of the password.
func TPAPPasscodeSHA1(password string) string {
	h := sha1.Sum([]byte(password))
	return hex.EncodeToString(h[:])
}

// TPAPPasscode is the string the login proves knowledge of, from the
// account password and the extra_crypt of the device's pake_register
// answer: for password_shadow with passwd_id 2 the hex SHA-1 of the
// password; for a camera that names none the hex MD5. Other forms are
// ErrTPAPUnsupported.
func TPAPPasscode(password string, extraCrypt map[string]any, camera bool) (string, error) {
	if extraCrypt == nil {
		if camera {
			h := md5.Sum([]byte(password))
			return hex.EncodeToString(h[:]), nil
		}
		return "", fmt.Errorf("%w: the device names no password transform (extra_crypt)", ErrTPAPUnsupported)
	}
	params, _ := extraCrypt["params"].(map[string]any)
	if id, ok := num(params["passwd_id"]); ok && id == 2 && str(extraCrypt["type"]) == "password_shadow" {
		return TPAPPasscodeSHA1(password), nil
	}
	b, _ := json.Marshal(extraCrypt)
	return "", fmt.Errorf("%w: password transform %s (type password_shadow with passwd_id 2 is supported)", ErrTPAPUnsupported, b)
}

// --- SPAKE2+ on P-256 (RFC 9383) ---------------------------------------------

// The curve's arithmetic comes from crypto/elliptic, whose P-256 is the
// standard library's constant-time implementation; its point API is
// deprecated in favour of crypto/ecdh, which has no point addition.

var p256 = elliptic.P256()

type point struct{ x, y *big.Int }

func (p point) inf() bool { return p.x.Sign() == 0 && p.y.Sign() == 0 }

func mustCompressed(h string) point {
	b, _ := hex.DecodeString(h)
	x, y := elliptic.UnmarshalCompressed(p256, b)
	if x == nil {
		panic("tplink: bad SPAKE2+ constant")
	}
	return point{x, y}
}

// M and N of RFC 9383 for P-256.
var (
	spakeM = mustCompressed("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	spakeN = mustCompressed("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
)

func scalarBytes(k *big.Int) []byte {
	return new(big.Int).Mod(k, p256.Params().N).FillBytes(make([]byte, 32))
}

func ecMul(p point, k *big.Int) point {
	if p.inf() {
		return p
	}
	x, y := p256.ScalarMult(p.x, p.y, scalarBytes(k))
	return point{x, y}
}

func baseMul(k *big.Int) point {
	x, y := p256.ScalarBaseMult(scalarBytes(k))
	return point{x, y}
}

func ecAdd(a, b point) point {
	if a.inf() {
		return b
	}
	if b.inf() {
		return a
	}
	x, y := p256.Add(a.x, a.y, b.x, b.y)
	return point{x, y}
}

// ecSub is a - k*q.
func ecSub(a, q point, k *big.Int) point {
	return ecAdd(a, ecMul(q, new(big.Int).Sub(p256.Params().N, new(big.Int).Mod(k, p256.Params().N))))
}

func encodePoint(p point) []byte {
	return elliptic.Marshal(p256, p.x, p.y) //nolint:staticcheck // see above
}

// decodePoint reads an uncompressed or compressed point on the curve.
func decodePoint(b []byte) (point, bool) {
	var x, y *big.Int
	switch {
	case len(b) == 65 && b[0] == 4:
		x, y = elliptic.Unmarshal(p256, b) //nolint:staticcheck // see above
	case len(b) == 33 && (b[0] == 2 || b[0] == 3):
		x, y = elliptic.UnmarshalCompressed(p256, b)
	}
	if x == nil {
		return point{}, false
	}
	return point{x, y}, true
}

func randScalar() *big.Int {
	n := new(big.Int).Sub(p256.Params().N, big.NewInt(1))
	k, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err)
	}
	return k.Add(k, big.NewInt(1))
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// hkdfSHA256 is HKDF (RFC 5869) with SHA-256.
func hkdfSHA256(ikm, salt, info []byte, n int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	prk := hmacSHA256(salt, ikm)
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		t = hmacSHA256(prk, t, info, []byte{i})
		out = append(out, t...)
	}
	return out[:n]
}

// pbkdf2SHA256 is PBKDF2 (RFC 8018) with HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iter, n int) []byte {
	var out []byte
	for block := uint32(1); len(out) < n; block++ {
		m := hmac.New(sha256.New, password)
		m.Write(salt)
		var bb [4]byte
		binary.BigEndian.PutUint32(bb[:], block)
		m.Write(bb[:])
		u := m.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			m.Reset()
			m.Write(u)
			u = m.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:n]
}

// tpapW are w0 and w1: the two 40-byte halves of PBKDF2-HMAC-SHA256 over
// the passcode, each reduced modulo the group order.
func tpapW(passcode string, salt []byte, iter int) (w0, w1 *big.Int) {
	k := pbkdf2SHA256([]byte(passcode), salt, iter, 80)
	n := p256.Params().N
	return new(big.Int).Mod(new(big.Int).SetBytes(k[:40]), n), new(big.Int).Mod(new(big.Int).SetBytes(k[40:]), n)
}

// tpapContext is the SPAKE2+ context of a TPAP login: SHA-256 of "PAKE V1",
// the client's random and the device's random.
func tpapContext(userRandom, devRandom []byte) []byte {
	return sha(append(append([]byte("PAKE V1"), userRandom...), devRandom...))
}

// spakeKeys derives the keys from the transcript: the confirmation keys of
// both sides and the shared key.
func spakeKeys(ctx, idP, idV []byte, shareP, shareV []byte, z, v point, w0 *big.Int) (kcP, kcV, shared []byte) {
	var tt []byte
	for _, item := range [][]byte{ctx, idP, idV, encodePoint(spakeM), encodePoint(spakeN), shareP, shareV, encodePoint(z), encodePoint(v), scalarBytes(w0)} {
		var l [8]byte
		binary.LittleEndian.PutUint64(l[:], uint64(len(item)))
		tt = append(append(tt, l[:]...), item...)
	}
	km := sha(tt)
	ck := hkdfSHA256(km, nil, []byte("ConfirmationKeys"), 64)
	return ck[:32], ck[32:], hkdfSHA256(km, nil, []byte("SharedKey"), 32)
}

// spakeProof is the prover's side once it has the verifier's share.
type spakeProof struct {
	share, confirm, shared []byte
	kcV                    []byte
}

func (p *spakeProof) verify(confirmV []byte) bool {
	return hmac.Equal(hmacSHA256(p.kcV, p.share), confirmV)
}

// spakeProve runs the prover with secret x against the verifier's share.
func spakeProve(w0, w1, x *big.Int, ctx, idP, idV, shareV []byte) (*spakeProof, error) {
	y, ok := decodePoint(shareV)
	if !ok {
		return nil, errors.New("the device's share (dev_share) is not a point on P-256")
	}
	X := ecAdd(baseMul(x), ecMul(spakeM, w0))
	un := ecSub(y, spakeN, w0)
	if un.inf() {
		return nil, errors.New("the device's share (dev_share) leads to a key that is not secret")
	}
	z, v := ecMul(un, x), ecMul(un, w1)
	if z.inf() || v.inf() {
		return nil, errors.New("the device's share (dev_share) leads to a key that is not secret")
	}
	shareP, yb := encodePoint(X), encodePoint(y)
	kcP, kcV, shared := spakeKeys(ctx, idP, idV, shareP, yb, z, v, w0)
	return &spakeProof{share: shareP, confirm: hmacSHA256(kcP, yb), shared: shared, kcV: kcV}, nil
}

// spakeVerifier is the device's side.
type spakeVerifier struct {
	w0, w1, y     *big.Int
	ctx, idP, idV []byte
	share         []byte
}

func newSpakeVerifier(w0, w1, y *big.Int, ctx, idP, idV []byte) *spakeVerifier {
	return &spakeVerifier{w0: w0, w1: w1, y: y, ctx: ctx, idP: idP, idV: idV, share: encodePoint(ecAdd(baseMul(y), ecMul(spakeN, w0)))}
}

// finish checks the prover's share and confirmation and returns the
// verifier's confirmation and the shared key.
func (s *spakeVerifier) finish(shareP, confirmP []byte) (confirmV, shared []byte, err error) {
	X, ok := decodePoint(shareP)
	if !ok {
		return nil, nil, errors.New("the client's share is not a point on P-256")
	}
	un := ecSub(X, spakeM, s.w0)
	if un.inf() {
		return nil, nil, errors.New("the client's share leads to a key that is not secret")
	}
	z, v := ecMul(un, s.y), ecMul(baseMul(s.w1), s.y)
	xb := encodePoint(X)
	kcP, kcV, shared := spakeKeys(s.ctx, s.idP, s.idV, xb, s.share, z, v, s.w0)
	if !hmac.Equal(hmacSHA256(kcP, s.share), confirmP) {
		return nil, nil, ErrTPAPAuth
	}
	return hmacSHA256(kcV, xb), shared, nil
}

// TPAPVerifier is the device side of one TPAP login, for simulators and
// tests: NewTPAPVerifier at pake_register, Finish at pake_share.
type TPAPVerifier struct{ v *spakeVerifier }

// NewTPAPVerifier starts the device side for the passcode (TPAPPasscode of
// the account password), the salt and iterations it announces, and both
// randoms. Share is the device's share (dev_share).
func NewTPAPVerifier(passcode string, salt []byte, iterations int, userRandom, devRandom []byte) (*TPAPVerifier, error) {
	if iterations < 1 {
		return nil, errors.New("TPAP iterations must be positive")
	}
	w0, w1 := tpapW(passcode, salt, iterations)
	return &TPAPVerifier{newSpakeVerifier(w0, w1, randScalar(), tpapContext(userRandom, devRandom), nil, nil)}, nil
}

// Share is the device's share, uncompressed.
func (t *TPAPVerifier) Share() []byte { return append([]byte(nil), t.v.share...) }

// Finish checks the client's share and confirmation (ErrTPAPAuth for a
// wrong password) and returns the device's confirmation and the shared
// key for NewTPAPCipher.
func (t *TPAPVerifier) Finish(userShare, userConfirm []byte) (devConfirm, sharedKey []byte, err error) {
	return t.v.finish(userShare, userConfirm)
}

// --- Session cipher ----------------------------------------------------------

// TPAPCipher is the cipher of a TPAP session: AES-128-CCM with a 16-byte
// tag, the key and the nonce base derived from the shared key with HKDF;
// each body is the 4-byte big-endian sequence number, then the ciphertext
// and tag. The nonce is the base's first 8 bytes and the sequence number.
type TPAPCipher struct {
	c     *ccm
	nonce []byte
}

// NewTPAPCipher derives the session cipher from the login's shared key.
func NewTPAPCipher(sharedKey []byte) (*TPAPCipher, error) {
	key := hkdfSHA256(sharedKey, []byte("tp-kdf-salt-aes128-key"), []byte("tp-kdf-info-aes128-key"), 16)
	nonce := hkdfSHA256(sharedKey, []byte("tp-kdf-salt-aes128-iv"), []byte("tp-kdf-info-aes128-iv"), 12)
	c, err := newCCM(key, 16)
	if err != nil {
		return nil, err
	}
	return &TPAPCipher{c: c, nonce: nonce}, nil
}

func (t *TPAPCipher) nonceFor(seq int32) []byte {
	n := make([]byte, 12)
	copy(n, t.nonce[:8])
	binary.BigEndian.PutUint32(n[8:], uint32(seq))
	return n
}

// Seal returns the body for a sequence number: the device answers under
// the request's.
func (t *TPAPCipher) Seal(seq int32, plain []byte) []byte {
	ct, _ := t.c.seal(t.nonceFor(seq), plain, nil) // a 12-byte nonce takes any message size
	var sb [4]byte
	binary.BigEndian.PutUint32(sb[:], uint32(seq))
	return append(sb[:], ct...)
}

// Open checks a body's sequence number and tag and returns the message.
func (t *TPAPCipher) Open(seq int32, body []byte) ([]byte, error) {
	if len(body) < 4+16 {
		return nil, fmt.Errorf("a TPAP body of %d bytes", len(body))
	}
	if got := int32(binary.BigEndian.Uint32(body[:4])); got != seq {
		return nil, fmt.Errorf("a TPAP answer under sequence %d to request %d", got, seq)
	}
	return t.c.open(t.nonceFor(seq), body[4:], nil)
}

// --- Client --------------------------------------------------------------------

// TPAPClient talks TPAP to one device, keeping its session. It is a
// SmartCaller: Tapo requests for plugs, bulbs, hubs and strips, camera
// requests (CamGet, MultiCall, TapoCamera) for cameras.
type TPAPClient struct {
	// Base is http://host:port or https://host:port: TPAPInfo.BaseURL.
	Base string
	// Password is the owner's TP-Link account password. The login names
	// the device's fixed local user, not the account email.
	Password string
	// Camera marks a camera, doorbell or camera hub: a password with no
	// transform named is hashed with MD5, and answers are read as camera
	// answers.
	Camera bool
	// PasscodeType is the passcode_type offered ("" is "userpw", the
	// account password).
	PasscodeType string
	// HTTP is the client; InsecureHTTP for a device on HTTPS (TLS 1).
	HTTP *http.Client

	mu   sync.Mutex
	sess *tpapSession
}

type tpapSession struct {
	url string
	c   *TPAPCipher
	seq int32
}

// tpapMaxIterations keeps a device from making the client spin.
const tpapMaxIterations = 100000

func (t *TPAPClient) login1(ctx context.Context, params map[string]any) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{"method": "login", "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(t.Base, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	sub := str(params["sub_method"])
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TPAP %s answered HTTP %d", sub, resp.StatusCode)
	}
	var m struct {
		ErrorCode float64        `json:"error_code"`
		Result    map[string]any `json:"result"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("TPAP %s answer is not JSON: %w", sub, err)
	}
	switch code := int(m.ErrorCode); {
	case code == tpapErrLocked:
		return nil, ErrTPAPLocked
	case code == tpapErrCredentials, code == sslErrSessionExpired && sub == "pake_share":
		// Cameras answer a wrong password with the code of an expired
		// session.
		return nil, ErrTPAPAuth
	case code != 0:
		return nil, &SmartError{Code: code, Method: "login " + sub}
	}
	if m.Result == nil {
		return nil, fmt.Errorf("TPAP %s answer has no result", sub)
	}
	return m.Result, nil
}

func b64field(m map[string]any, k string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(str(m[k]))
	if err != nil || str(m[k]) == "" {
		return nil, fmt.Errorf("the device's %s is not base64", k)
	}
	return b, nil
}

func (t *TPAPClient) login(ctx context.Context) (*tpapSession, error) {
	pt := t.PasscodeType
	if pt == "" {
		pt = "userpw"
	}
	ur := make([]byte, 32)
	_, _ = rand.Read(ur)
	admin := md5.Sum([]byte("admin"))
	reg, err := t.login1(ctx, map[string]any{"sub_method": "pake_register", "username": hex.EncodeToString(admin[:]),
		"user_random": base64.StdEncoding.EncodeToString(ur), "cipher_suites": []int{1}, "encryption": []string{"aes_128_ccm"}, "passcode_type": pt})
	if err != nil {
		return nil, err
	}
	if cs, _ := num(reg["cipher_suites"]); cs != 1 {
		return nil, fmt.Errorf("%w: cipher suite %v", ErrTPAPUnsupported, reg["cipher_suites"])
	}
	if enc := str(reg["encryption"]); enc != "aes_128_ccm" {
		return nil, fmt.Errorf("%w: session cipher %q", ErrTPAPUnsupported, enc)
	}
	iter, _ := num(reg["iterations"])
	if iter < 1 || iter > tpapMaxIterations {
		return nil, fmt.Errorf("the device asks for %v PBKDF2 iterations (1 to %d are taken)", reg["iterations"], tpapMaxIterations)
	}
	dr, err := b64field(reg, "dev_random")
	if err != nil {
		return nil, err
	}
	if len(dr) != 32 {
		return nil, fmt.Errorf("the device's dev_random has %d bytes, not 32", len(dr))
	}
	salt, err := b64field(reg, "dev_salt")
	if err != nil {
		return nil, err
	}
	share, err := b64field(reg, "dev_share")
	if err != nil {
		return nil, err
	}
	ec, _ := reg["extra_crypt"].(map[string]any)
	passcode, err := TPAPPasscode(t.Password, ec, t.Camera)
	if err != nil {
		return nil, err
	}
	w0, w1 := tpapW(passcode, salt, int(iter))
	proof, err := spakeProve(w0, w1, randScalar(), tpapContext(ur, dr), nil, nil, share)
	if err != nil {
		return nil, err
	}
	sh, err := t.login1(ctx, map[string]any{"sub_method": "pake_share", "user_share": base64.StdEncoding.EncodeToString(proof.share),
		"user_confirm": base64.StdEncoding.EncodeToString(proof.confirm)})
	if err != nil {
		return nil, err
	}
	dc, err := b64field(sh, "dev_confirm")
	if err != nil {
		return nil, err
	}
	if !proof.verify(dc) {
		return nil, ErrTPAPDeviceProof
	}
	stok := str(sh["stok"])
	if stok == "" {
		stok = str(sh["sessionId"])
	}
	if stok == "" {
		return nil, errors.New("the device's pake_share answer has no session token")
	}
	seq, ok := num(sh["start_seq"])
	if !ok {
		return nil, errors.New("the device's pake_share answer has no start_seq")
	}
	c, err := NewTPAPCipher(proof.shared)
	if err != nil {
		return nil, err
	}
	return &tpapSession{url: strings.TrimSuffix(t.Base, "/") + "/stok=" + stok + "/ds", c: c, seq: int32(seq)}, nil
}

// Handshake logs in now, without a request, and keeps the session.
func (t *TPAPClient) Handshake(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, err := t.login(ctx)
	if err == nil {
		t.sess = s
	}
	return err
}

// errTPAPSessionEnded marks an answer that says the device no longer knows
// the session.
var errTPAPSessionEnded = errors.New("the device ended the TPAP session")

func (t *TPAPClient) send1(ctx context.Context, plain []byte) ([]byte, error) {
	s := t.sess
	seq := s.seq
	s.seq++
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(s.c.Seal(seq, plain)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errTPAPSessionEnded
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the device answered HTTP %d", resp.StatusCode)
	}
	p, err := s.c.Open(seq, b)
	if err != nil {
		// A device that no longer knows the session answers with an error
		// code in clear; a ciphertext may start with '{' too, so this is
		// checked only after decryption failed.
		var m map[string]any
		if json.Unmarshal(b, &m) == nil && errorCode(m) != 0 {
			return nil, errTPAPSessionEnded
		}
		return nil, err
	}
	return p, nil
}

// Send sends one request object ({"method", ...}) and returns the device's
// answer as it is (with error_code), logging in when there is no session
// and again once when the device ended it.
func (t *TPAPClient) Send(ctx context.Context, req any) (map[string]any, error) {
	plain, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if t.sess == nil {
			s, err := t.login(ctx)
			if err != nil {
				return nil, err
			}
			t.sess = s
		}
		p, err := t.send1(ctx, plain)
		if errors.Is(err, errTPAPSessionEnded) {
			t.sess = nil
			continue
		}
		if err != nil {
			t.sess = nil
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(p, &out); err != nil {
			return nil, fmt.Errorf("the TPAP answer is not JSON: %w", err)
		}
		return out, nil
	}
	return nil, errors.New("the device ended the TPAP session twice")
}

// Call sends {"method", "params"} and returns the result, as the other
// clients do.
func (t *TPAPClient) Call(ctx context.Context, method string, params any) (map[string]any, error) {
	req := map[string]any{"method": method}
	if params != nil {
		req["params"] = params
	}
	m, err := t.Send(ctx, req)
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
