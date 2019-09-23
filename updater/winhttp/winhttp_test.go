/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winhttp

import (
	"fmt"
	"io"
	"io/ioutil"
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
	r, err := Get("WinHTTP Test Suite/1.0", "https://www.zx2c4.com/ip")
	if err != nil {
		t.Fatal(err)
	}
	length, err := r.Length()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("The length is %d\n", length)
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(bytes))
	r.Close()

	r, err = Get("WinHTTP Test Suite/1.0", "https://speed.hetzner.de/10GB.bin")
	if err != nil {
		t.Fatal(err)
	}
	length, err = r.Length()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(&progressPrinter{total: length}, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}
