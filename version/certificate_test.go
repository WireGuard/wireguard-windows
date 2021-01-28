/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package version

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
	names, err := extractCertificateNames(filepath.Join(system32, "ntoskrnl.exe"))
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
	policies, err := extractCertificatePolicies(filepath.Join(system32, "ntoskrnl.exe"), "2.5.29.32")
	if err != nil {
		t.Fatal(err)
	}
	for i, policy := range policies {
		fmt.Printf("%d: %s\n", i, policy)
	}
}
