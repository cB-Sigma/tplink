// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tplink

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3610 packet vector #1: a 13-byte nonce, 8 bytes of associated data
// sent in clear before the ciphertext, an 8-byte tag.
func TestCCMVector(t *testing.T) {
	c, err := newCCM(unhex(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"), 8)
	if err != nil {
		t.Fatal(err)
	}
	nonce := unhex(t, "00000003020100a0a1a2a3a4a5")
	aad := unhex(t, "0001020304050607")
	plain := unhex(t, "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
	want := unhex(t, "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
	got, err := c.seal(nonce, plain, aad)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("seal %x %v", got, err)
	}
	back, err := c.open(nonce, got, aad)
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatalf("open %x %v", back, err)
	}
	got[3] ^= 1
	if _, err := c.open(nonce, got, aad); err == nil {
		t.Error("a changed byte was accepted")
	}
	// The form TPAP uses: 12-byte nonce, 16-byte tag, no associated data.
	c16, _ := newCCM(unhex(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"), 16)
	sealed, err := c16.seal(nonce[:12], plain, nil)
	if err != nil || len(sealed) != len(plain)+16 {
		t.Fatalf("seal 12/16 %v", err)
	}
	if back, err := c16.open(nonce[:12], sealed, nil); err != nil || !bytes.Equal(back, plain) {
		t.Errorf("open 12/16 %v", err)
	}
}
