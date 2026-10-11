package tplink

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/cB-Sigma/lanbcast"
)

// The Kasa legacy local protocol: JSON on TCP port 9999, each message
// prefixed by its length (4 bytes, big-endian) and obscured by an
// autokey XOR (the first key is 171, then each cipher byte is the next
// key); UDP port 9999 carries the same XOR without the length for
// discovery. TP-Link documents none of it; the facts come from public
// descriptions by open-source clients and security write-ups.

// KasaPort is the legacy protocol's port (TCP and UDP).
const KasaPort = 9999

const kasaKey = 171

// Encrypt obscures a Kasa payload.
func Encrypt(plain []byte) []byte {
	out := make([]byte, len(plain))
	k := byte(kasaKey)
	for i, b := range plain {
		c := k ^ b
		out[i] = c
		k = c
	}
	return out
}

// Decrypt reverses Encrypt.
func Decrypt(cipher []byte) []byte {
	out := make([]byte, len(cipher))
	k := byte(kasaKey)
	for i, c := range cipher {
		out[i] = k ^ c
		k = c
	}
	return out
}

// Frame is a TCP message: length and obscured payload.
func Frame(plain []byte) []byte {
	b := make([]byte, 4, 4+len(plain))
	binary.BigEndian.PutUint32(b, uint32(len(plain)))
	return append(b, Encrypt(plain)...)
}

// ReadFrame reads one TCP message.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 1<<20 {
		return nil, fmt.Errorf("a Kasa message of %d bytes is too long", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return Decrypt(b), nil
}

// KasaRequest sends one request to addr (host:port) and returns the
// answer.
func KasaRequest(ctx context.Context, addr string, req any, timeout time.Duration) (map[string]any, error) {
	plain, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(Frame(plain)); err != nil {
		return nil, err
	}
	b, err := ReadFrame(c)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("the device's answer is not JSON: %w", err)
	}
	return out, nil
}

// KasaError returns the first module error of a Kasa answer (an err_code
// that is set and not 0), or nil.
func KasaError(m map[string]any) error {
	for mod, v := range m {
		mm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for meth, r := range mm {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if c, ok := rm["err_code"].(float64); ok && c != 0 {
				msg, _ := rm["err_msg"].(string)
				return fmt.Errorf("the device refused %s.%s: error %v %s", mod, meth, c, msg)
			}
		}
	}
	return nil
}

// Found is a device that answered discovery.
type Found struct {
	Addr    string
	Sysinfo map[string]any
}

// KasaDiscover broadcasts get_sysinfo to bcast (host:port) and collects
// answers for wait.
func KasaDiscover(ctx context.Context, bcast string, wait time.Duration) ([]Found, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ra, err := net.ResolveUDPAddr("udp4", bcast)
	if err != nil {
		return nil, err
	}
	if err := lanbcast.WriteBroadcast(c, Encrypt([]byte(`{"system":{"get_sysinfo":{}}}`)), ra); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetReadDeadline(deadline)
	var out []Found
	seen := map[string]bool{}
	buf := make([]byte, 64<<10)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return out, nil
			}
			return out, err
		}
		var m map[string]any
		if json.Unmarshal(Decrypt(buf[:n]), &m) != nil {
			continue
		}
		si, _ := m["system"].(map[string]any)
		info, _ := si["get_sysinfo"].(map[string]any)
		if info == nil || seen[from.String()] {
			continue
		}
		seen[from.String()] = true
		out = append(out, Found{Addr: from.String(), Sysinfo: info}) // devices answer from port 9999
	}
}
