/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"regexp"
	"strconv"
	"strings"
)

var reservedNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

const serviceNameForbidden = "$"
const netshellDllForbidden = "\\/:*?\"<>|\t"
const specialChars = "/\\<>:\"|?*\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x00"

var allowedNameFormat *regexp.Regexp

func init() {
	allowedNameFormat = regexp.MustCompile("^[a-zA-Z0-9_=+.-]{1,32}$")
}

func isReserved(name string) bool {
	if len(name) == 0 {
		return false
	}
	for _, reserved := range reservedNames {
		if strings.EqualFold(name, reserved) {
			return true
		}
	}
	return false
}

func hasSpecialChars(name string) bool {
	return strings.ContainsAny(name, specialChars) || strings.ContainsAny(name, netshellDllForbidden) || strings.ContainsAny(name, serviceNameForbidden)
}

func TunnelNameIsValid(name string) bool {
	// Aside from our own restrictions, let's impose the Windows restrictions first
	if isReserved(name) || hasSpecialChars(name) {
		return false
	}
	return allowedNameFormat.MatchString(name)
}

type naturalSortToken struct {
	maybeString string
	maybeNumber int
}
type naturalSortString struct {
	originalString string
	tokens         []naturalSortToken
}

var naturalSortDigitFinder = regexp.MustCompile(`\d+|\D+`)

func newNaturalSortString(s string) (t naturalSortString) {
	t.originalString = s
	s = strings.ToLower(strings.Join(strings.Fields(s), " "))
	x := naturalSortDigitFinder.FindAllString(s, -1)
	t.tokens = make([]naturalSortToken, len(x))
	for i, s := range x {
		if n, err := strconv.Atoi(s); err == nil {
			t.tokens[i].maybeNumber = n
		} else {
			t.tokens[i].maybeString = s
		}
	}
	return
}

func (f1 naturalSortToken) Cmp(f2 naturalSortToken) int {
	if len(f1.maybeString) == 0 {
		if len(f2.maybeString) > 0 || f1.maybeNumber < f2.maybeNumber {
			return -1
		} else if f1.maybeNumber > f2.maybeNumber {
			return 1
		}
	} else if len(f2.maybeString) == 0 || f1.maybeString > f2.maybeString {
		return 1
	} else if f1.maybeString < f2.maybeString {
		return -1
	}
	return 0
}

func TunnelNameIsLess(a, b string) bool {
	if a == b {
		return false
	}
	na, nb := newNaturalSortString(a), newNaturalSortString(b)
	for i, t := range nb.tokens {
		if i == len(na.tokens) {
			return true
		}
		switch na.tokens[i].Cmp(t) {
		case -1:
			return true
		case 1:
			return false
		}
	}
	return false
}
