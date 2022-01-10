/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package dpapi

import (
	"bytes"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestRoundTrip(t *testing.T) {
	name := "golang test"
	original := []byte("The quick brown fox jumped over the lazy dog")

	e, err := Encrypt(original, name)
	if err != nil {
		t.Errorf("Error encrypting: %s", err.Error())
	}

	if len(e) < len(original) {
		t.Error("Encrypted data is smaller than original data.")
	}

	d, err := Decrypt(e, name)
	if err != nil {
		t.Errorf("Error decrypting: %s", err.Error())
	}

	if !bytes.Equal(d, original) {
		t.Error("Decrypted content does not match original")
	}

	_, err = Decrypt(e, "bad name")
	if err == nil {
		t.Error("Decryption failed to notice ad mismatch")
	}

	eCorrupt := make([]byte, len(e))
	copy(eCorrupt, e)
	eCorrupt[len(original)-1] = 7
	_, err = Decrypt(eCorrupt, name)
	if err == nil {
		t.Error("Decryption failed to notice ciphertext corruption")
	}

	copy(eCorrupt, e)
	nameUtf16, err := windows.UTF16FromString(name)
	if err != nil {
		t.Errorf("Unable to get utf16 chars for name: %s", err)
	}
	nameUtf16Bytes := unsafe.Slice((*byte)(unsafe.Pointer(&nameUtf16[0])), len(nameUtf16)*2)
	i := bytes.Index(eCorrupt, nameUtf16Bytes)
	if i == -1 {
		t.Error("Unable to find ad in blob")
	} else {
		eCorrupt[i] = 7
		_, err = Decrypt(eCorrupt, name)
		if err == nil {
			t.Error("Decryption failed to notice ad corruption")
		}
	}

	// BUG: Actually, Windows doesn't report length extension of the buffer, unfortunately.
	//
	// eCorrupt = make([]byte, len(e)+1)
	// copy(eCorrupt, e)
	// _, err = Decrypt(eCorrupt, name)
	// if err == nil {
	// 	t.Error("Decryption failed to notice length extension")
	// }
}
