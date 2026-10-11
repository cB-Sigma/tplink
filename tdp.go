package tplink

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/lanbcast"
)

// Tapo devices, and Kasa devices on KLAP firmware, do not answer the
// legacy UDP 9999 broadcast; they answer a probe on UDP 20002 instead
// (TP-Link's device discovery protocol, as open-source clients describe
// it). The probe is a 16-byte header (version 2, message type 0, op code 1
// for a probe, the payload length, flags 0x11, a random serial, and a
// CRC-32 of the whole message computed with 0x5A6B7C8D in the CRC field)
// followed by JSON carrying an RSA public key, which newer firmware uses
// to encrypt part of its answer. The answer has a 16-byte header too,
// then {"error_code": 0, "result": {...}}: the device's type, model, ID,
// IP and MAC addresses, and how it wants to be spoken to
// (mgt_encrypt_schm: KLAP or AES, the HTTP port, the login version).

// TapoPort is the discovery port of Tapo and KLAP devices.
const TapoPort = 20002

// tdpCRCSeed is written in the CRC field before the CRC is computed.
const tdpCRCSeed = 0x5A6B7C8D

var (
	tdpKeyOnce sync.Once
	tdpKey     *rsa.PrivateKey
	tdpKeyPEM  []byte
	tdpKeyErr  error
)

// tdpPublicKey is the public key sent in probes: one per process, made on
// first use. Devices answer only probes that carry a key, and newer
// firmware encrypts part of its answer to it.
func tdpPublicKey() ([]byte, error) {
	tdpKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			tdpKeyErr = err
			return
		}
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			tdpKeyErr = err
			return
		}
		tdpKey = k
		tdpKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	})
	return tdpKeyPEM, tdpKeyErr
}

// The encrypted part of a 20002 answer is "encrypt_info": {"sym_schm":
// "AES", "key": base64 of a 16-byte AES key and a 16-byte IV encrypted to
// the probe's RSA key with OAEP (SHA-1, MGF1 SHA-1), "data": base64 of
// JSON encrypted with AES-128-CBC and PKCS#7 padding}.

// DecryptTapoAnswer decrypts the answer's encrypt_info with the private
// key whose public half the probe carried, and sets f.Decrypted. An
// answer without encrypt_info is left as it is.
func DecryptTapoAnswer(f *TapoFound, key *rsa.PrivateKey) error {
	ei, _ := f.Result["encrypt_info"].(map[string]any)
	if ei == nil || str(ei["key"]) == "" || str(ei["data"]) == "" {
		return nil
	}
	ek, err := base64.StdEncoding.DecodeString(str(ei["key"]))
	if err != nil {
		return fmt.Errorf("the encrypt_info key is not base64: %w", err)
	}
	keyIV, err := rsa.DecryptOAEP(sha1.New(), nil, key, ek, nil)
	if err != nil {
		return errors.New("the encrypt_info key could not be decrypted")
	}
	s, err := NewAESSession(keyIV)
	if err != nil {
		return err
	}
	p, err := s.Decrypt(str(ei["data"]))
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil {
		return fmt.Errorf("the encrypt_info data is not JSON: %w", err)
	}
	f.Decrypted = m
	return nil
}

// SealTapoDiscovery builds an encrypt_info for data, encrypted to the PEM
// public key of a probe, as a device does (for simulators and tests).
func SealTapoDiscovery(pubPEM []byte, data any) (map[string]any, error) {
	blk, _ := pem.Decode(pubPEM)
	if blk == nil {
		return nil, errors.New("the probe key is not PEM")
	}
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the probe key is not RSA")
	}
	keyIV := make([]byte, 32)
	_, _ = rand.Read(keyIV)
	ek, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rk, keyIV, nil)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	s, _ := NewAESSession(keyIV)
	return map[string]any{"sym_schm": "AES", "key": base64.StdEncoding.EncodeToString(ek), "data": s.Encrypt(plain)}, nil
}

// TapoProbe builds a discovery probe carrying the PEM public key.
func TapoProbe(pubPEM []byte) []byte {
	payload, _ := json.Marshal(map[string]any{"params": map[string]any{"rsa_key": string(pubPEM)}})
	msg := make([]byte, 16, 16+len(payload))
	msg[0] = 2 // version
	msg[1] = 0 // message type
	binary.BigEndian.PutUint16(msg[2:], 1)
	binary.BigEndian.PutUint16(msg[4:], uint16(len(payload)))
	msg[6] = 0x11 // flags
	msg[7] = 0
	var serial [4]byte
	_, _ = rand.Read(serial[:])
	copy(msg[8:12], serial[:])
	binary.BigEndian.PutUint32(msg[12:], tdpCRCSeed)
	msg = append(msg, payload...)
	binary.BigEndian.PutUint32(msg[12:], crc32.ChecksumIEEE(msg))
	return msg
}

// CheckTapoProbe tells whether b is a well-formed probe (version 2, op
// code 1, matching length and CRC), as a device checks it; it returns the
// payload.
func CheckTapoProbe(b []byte) ([]byte, error) {
	if len(b) < 16 {
		return nil, errors.New("shorter than the header")
	}
	if b[0] != 2 || binary.BigEndian.Uint16(b[2:]) != 1 {
		return nil, fmt.Errorf("version %d op code %d", b[0], binary.BigEndian.Uint16(b[2:]))
	}
	if int(binary.BigEndian.Uint16(b[4:])) != len(b)-16 {
		return nil, errors.New("payload length does not match")
	}
	got := binary.BigEndian.Uint32(b[12:])
	c := append([]byte(nil), b...)
	binary.BigEndian.PutUint32(c[12:], tdpCRCSeed)
	if crc32.ChecksumIEEE(c) != got {
		return nil, errors.New("CRC does not match")
	}
	return b[16:], nil
}

// TapoFound is a device that answered the 20002 probe.
type TapoFound struct {
	// Addr is where the answer came from (host:port).
	Addr string
	// Host is the device's address: the answer's source, else its "ip".
	Host       string
	DeviceType string // SMART.TAPOPLUG, SMART.KASAPLUG, SMART.TAPOHUB, IOT.SMARTPLUGSWITCH, …
	Model      string // without the region, "P110"
	DeviceID   string
	MAC        string // 12 hex digits
	// Encrypt is KLAP or AES (securePassthrough); "" when not told.
	Encrypt      string
	HTTPPort     int
	LoginVersion int
	HTTPS        bool
	Name         string
	Result       map[string]any
	// Decrypted is the answer's encrypt_info decrypted (newer firmware), or
	// nil. TapoDiscover fills it.
	Decrypted map[string]any
}

// Protocol is the row protocol the answer asks for: klap or aes ("" when
// not told).
func (f TapoFound) Protocol() string {
	switch strings.ToUpper(f.Encrypt) {
	case "KLAP":
		return "klap"
	case "AES":
		return "aes"
	}
	return ""
}

// BaseURL is the URL a client of the protocol the answer asks for starts
// from: http://host[:port] for KLAP and securePassthrough;
// https://host:port for KLAP over HTTPS (port 4433 when not told) and for
// the HTTPS transport of cameras and the H200 hub (SSLAESClient, port 443
// when not told). Use InsecureHTTP for the https ones.
func (f TapoFound) BaseURL() string {
	port := f.HTTPPort
	if !f.HTTPS {
		if port == 0 || port == 80 {
			return "http://" + f.Host
		}
		return fmt.Sprintf("http://%s:%d", f.Host, port)
	}
	if port == 0 {
		port = 443
		if f.Protocol() == "klap" {
			port = KLAPHTTPSPort
		}
	}
	return fmt.Sprintf("https://%s:%d", f.Host, port)
}

// ParseTapoAnswer reads a 20002 answer.
func ParseTapoAnswer(b []byte) (TapoFound, error) {
	if len(b) <= 16 {
		return TapoFound{}, errors.New("an answer without a payload")
	}
	var m struct {
		ErrorCode float64        `json:"error_code"`
		Result    map[string]any `json:"result"`
	}
	if err := json.Unmarshal(b[16:], &m); err != nil {
		return TapoFound{}, fmt.Errorf("the answer is not JSON: %w", err)
	}
	r := m.Result
	if r == nil {
		return TapoFound{}, fmt.Errorf("the answer has no result (error %v)", m.ErrorCode)
	}
	f := TapoFound{Result: r, DeviceType: str(r["device_type"]), DeviceID: str(r["device_id"]), MAC: NormaliseMAC(str(r["mac"])),
		Host: str(r["ip"])}
	f.Model, _, _ = strings.Cut(str(r["device_model"]), "(")
	f.Model = strings.TrimSpace(f.Model)
	if n := str(r["device_name"]); n != "" {
		f.Name = n
	}
	if s, ok := r["mgt_encrypt_schm"].(map[string]any); ok {
		f.Encrypt = str(s["encrypt_type"])
		if p, ok := num(s["http_port"]); ok {
			f.HTTPPort = int(p)
		}
		if lv, ok := num(s["lv"]); ok {
			f.LoginVersion = int(lv)
		}
		f.HTTPS, _ = s["is_support_https"].(bool)
	}
	if f.Encrypt == "" {
		if ei, ok := r["encrypt_info"].(map[string]any); ok {
			f.Encrypt = str(ei["sym_schm"])
		}
	}
	// Without "lv", the highest of a top-level "encrypt_type" list ("1",
	// "2", "3") is the login version; an HTTPS device naming only login
	// version 3 wants the AES login.
	if et, ok := r["encrypt_type"].([]any); ok && f.LoginVersion == 0 {
		for _, x := range et {
			var v int
			if _, err := fmt.Sscan(str(x), &v); err == nil && v > f.LoginVersion {
				f.LoginVersion = v
			}
		}
	}
	if f.Encrypt == "" && f.HTTPS && f.LoginVersion == 3 {
		f.Encrypt = "AES"
	}
	return f, nil
}

// TapoDiscover sends the 20002 probe to bcast (host:port) and collects
// answers for wait. The probe is sent three times over the wait, as
// datagrams get lost.
func TapoDiscover(ctx context.Context, bcast string, wait time.Duration) ([]TapoFound, error) {
	pub, err := tdpPublicKey()
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ra, err := net.ResolveUDPAddr("udp4", bcast)
	if err != nil {
		return nil, err
	}
	probe := TapoProbe(pub)
	if err := lanbcast.WriteBroadcast(c, probe, ra); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	resend := time.Now().Add(wait / 3)
	var out []TapoFound
	seen := map[string]bool{}
	buf := make([]byte, 64<<10)
	for {
		until := deadline
		if resend.Before(until) {
			until = resend
		}
		_ = c.SetReadDeadline(until)
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if !time.Now().Before(deadline) || ctx.Err() != nil {
					return out, nil
				}
				resend = time.Now().Add(wait / 3)
				_ = lanbcast.WriteBroadcast(c, probe, ra)
				continue
			}
			return out, err
		}
		f, perr := ParseTapoAnswer(buf[:n])
		key := f.MAC
		if key == "" {
			key = from.String()
		}
		if perr != nil || seen[key] {
			continue
		}
		seen[key] = true
		_ = DecryptTapoAnswer(&f, tdpKey) // an answer that cannot be decrypted is still a device
		f.Addr = from.String()
		f.Host = from.IP.String()
		out = append(out, f)
	}
}
