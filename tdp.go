package tplink

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	tdpKeyPEM  []byte
	tdpKeyErr  error
)

// tdpPublicKey is the public key sent in probes: one per process, made on
// first use (the answer's encrypted part is not needed, but devices answer
// only probes that carry a key).
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
		tdpKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	})
	return tdpKeyPEM, tdpKeyErr
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
		f.Addr = from.String()
		f.Host = from.IP.String()
		out = append(out, f)
	}
}
