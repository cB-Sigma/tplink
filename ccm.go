// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// AES in CCM mode (counter mode for secrecy, CBC-MAC for integrity), as
// RFC 3610 and NIST SP 800-38C define it. The standard library has no CCM;
// TPAP uses it with a 12-byte nonce, a 16-byte tag and no associated data.
// This implementation takes any nonce of 7 to 13 bytes, an even tag of 4 to
// 16 bytes and optional associated data, so that published test vectors
// can check it.

var errCCMOpen = errors.New("ccm: message authentication failed")

type ccm struct {
	b      cipher.Block
	tagLen int
}

func newCCM(key []byte, tagLen int) (*ccm, error) {
	if tagLen < 4 || tagLen > 16 || tagLen%2 != 0 {
		return nil, errors.New("ccm: tag length must be an even number from 4 to 16")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ccm{b: b, tagLen: tagLen}, nil
}

// lenSize is the size of the length field: the rest of the 15 bytes after
// the nonce.
func ccmLenSize(nonce []byte) (int, error) {
	if len(nonce) < 7 || len(nonce) > 13 {
		return 0, errors.New("ccm: nonce must be 7 to 13 bytes")
	}
	return 15 - len(nonce), nil
}

// counter returns counter block i: flags (the length size less one), the
// nonce, and i in the length field.
func (c *ccm) counter(nonce []byte, q int, i uint64) [16]byte {
	var a [16]byte
	a[0] = byte(q - 1)
	copy(a[1:], nonce)
	for k := 0; k < q; k++ {
		a[15-k] = byte(i >> (8 * k))
	}
	return a
}

// mac is the CBC-MAC of the first block (flags, nonce, message length),
// the associated data with its length in front, and the message, each
// zero-padded to whole blocks.
func (c *ccm) mac(nonce []byte, q int, plain, aad []byte) [16]byte {
	var x, b0 [16]byte
	flags := byte(((c.tagLen - 2) / 2) << 3)
	flags |= byte(q - 1)
	if len(aad) > 0 {
		flags |= 0x40
	}
	b0[0] = flags
	copy(b0[1:], nonce)
	n := uint64(len(plain))
	for k := 0; k < q; k++ {
		b0[15-k] = byte(n >> (8 * k))
	}
	c.b.Encrypt(x[:], b0[:])
	absorb := func(data []byte) {
		for len(data) > 0 {
			var blk [16]byte
			m := copy(blk[:], data)
			data = data[m:]
			for i := range blk {
				x[i] ^= blk[i]
			}
			c.b.Encrypt(x[:], x[:])
		}
	}
	if len(aad) > 0 {
		var hdr []byte
		switch {
		case len(aad) < 0xff00:
			hdr = []byte{byte(len(aad) >> 8), byte(len(aad))}
		case uint64(len(aad)) <= 0xffffffff:
			hdr = []byte{0xff, 0xfe, byte(len(aad) >> 24), byte(len(aad) >> 16), byte(len(aad) >> 8), byte(len(aad))}
		default:
			l := uint64(len(aad))
			hdr = []byte{0xff, 0xff, byte(l >> 56), byte(l >> 48), byte(l >> 40), byte(l >> 32), byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
		}
		absorb(append(hdr, aad...))
	}
	absorb(plain)
	return x
}

// ctr XORs data with the key stream from counter block 1 on.
func (c *ccm) ctr(nonce []byte, q int, dst, src []byte) {
	var s [16]byte
	for i := 0; i*16 < len(src); i++ {
		a := c.counter(nonce, q, uint64(i+1))
		c.b.Encrypt(s[:], a[:])
		end := min((i+1)*16, len(src))
		for k := i * 16; k < end; k++ {
			dst[k] = src[k] ^ s[k-i*16]
		}
	}
}

func (c *ccm) tag(nonce []byte, q int, plain, aad []byte) []byte {
	t := c.mac(nonce, q, plain, aad)
	a0 := c.counter(nonce, q, 0)
	var s0 [16]byte
	c.b.Encrypt(s0[:], a0[:])
	out := make([]byte, c.tagLen)
	for i := range out {
		out[i] = t[i] ^ s0[i]
	}
	return out
}

// seal returns the ciphertext with the tag appended.
func (c *ccm) seal(nonce, plain, aad []byte) ([]byte, error) {
	q, err := ccmLenSize(nonce)
	if err != nil {
		return nil, err
	}
	if q < 8 && uint64(len(plain)) >= 1<<(8*q) {
		return nil, errors.New("ccm: message too long for the nonce size")
	}
	out := make([]byte, len(plain), len(plain)+c.tagLen)
	c.ctr(nonce, q, out, plain)
	return append(out, c.tag(nonce, q, plain, aad)...), nil
}

// open checks the tag at the end of sealed and returns the message.
func (c *ccm) open(nonce, sealed, aad []byte) ([]byte, error) {
	q, err := ccmLenSize(nonce)
	if err != nil {
		return nil, err
	}
	if len(sealed) < c.tagLen {
		return nil, errCCMOpen
	}
	ct, got := sealed[:len(sealed)-c.tagLen], sealed[len(sealed)-c.tagLen:]
	plain := make([]byte, len(ct))
	c.ctr(nonce, q, plain, ct)
	if subtle.ConstantTimeCompare(c.tag(nonce, q, plain, aad), got) != 1 {
		return nil, errCCMOpen
	}
	return plain, nil
}
