/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
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

func TestExtractCertificateExtension(t *testing.T) {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	policies, err := ExtractCertificatePolicies(filepath.Join(system32, "ntoskrnl.exe"), "2.5.29.32")
	if err != nil {
		t.Fatal(err)
	}
	for i, policy := range policies {
		fmt.Printf("%d: %s\n", i, policy)
	}
}
