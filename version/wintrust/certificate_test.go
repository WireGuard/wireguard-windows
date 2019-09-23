/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintrust

import (
	"fmt"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestExtractCertificateNames(t *testing.T) {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	names, err := ExtractCertificateNames(filepath.Join(system32, "ntoskrnl.exe"))
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range names {
		fmt.Printf("%d: %s\n", i, name)
	}
}
