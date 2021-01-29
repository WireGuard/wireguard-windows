/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winhttp

import (
	"fmt"
	"io"
	"runtime"
	"testing"
)

type progressPrinter struct {
	downloaded uint64
	total      uint64
}

func (pp *progressPrinter) Write(p []byte) (int, error) {
	bytes := len(p)
	pp.downloaded += uint64(bytes)
	fmt.Printf("%d/%d bytes, %f%%\n", pp.downloaded, pp.total, float64(pp.downloaded)/float64(pp.total)*100.0)
	return bytes, nil
}

func TestResponse(t *testing.T) {
	session, err := NewSession("WinHTTP Test Suite/1.0")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := session.Connect("zx2c4.com", 443, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err := connection.Get("/ip", true)
	length, err := r.Length()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("The length is %d\n", length)
	bytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(bytes))
	r.Close()

	connection, err = session.Connect("speed.hetzner.de", 443, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = connection.Get("/10GB.bin", false)
	if err != nil {
		t.Fatal(err)
	}
	length, err = r.Length()
	if err != nil {
		t.Fatal(err)
	}
	amountRead, err := io.Copy(&progressPrinter{total: length}, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if length != uint64(amountRead) {
		t.Fatalf("Expected to read %d, but only read %d", length, amountRead)
	}

	runtime.GC() // Try to force the finalizers to be called
}
