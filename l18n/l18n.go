/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package l18n

import (
	"sync"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var printer *message.Printer
var printerLock sync.Mutex

// prn returns the printer for user preferred UI language.
func prn() *message.Printer {
	if printer != nil {
		return printer
	}
	printerLock.Lock()
	if printer != nil {
		printerLock.Unlock()
		return printer
	}
	printer = message.NewPrinter(lang())
	printerLock.Unlock()
	return printer
}

// lang returns the user preferred UI language we have most confident translation in the default catalog available.
func lang() (tag language.Tag) {
	tag = language.English
	confidence := language.No
	languages, err := getUserLanguages()
	if err != nil {
		return
	}
	for i := range languages {
		t, _, c := message.DefaultCatalog.Matcher().Match(message.MatchLanguage(languages[i]))
		if c > confidence {
			tag = t
			confidence = c
		}
	}
	return
}

// Sprintf is like fmt.Sprintf, but using language-specific formatting.
func Sprintf(key message.Reference, a ...interface{}) string {
	return prn().Sprintf(key, a...)
}

// EnumerationSeparator returns enumeration separator. For English and western languages,
// enumeration separator is a comma followed by a space (i.e. ", "). For Chinese, it returns
// "\u3001".
func EnumerationSeparator() string {
	// BUG: We could just use `Sprintf(", " /* ...translator instructions... */)` and let the
	// individual locale catalog handle its translation. Unfortunately, the gotext utility tries to
	// be nice to translators and skips all strings without letters when updating catalogs.
	return Sprintf("[EnumerationSeparator]" /* Text to insert between items when listing - most western languages will translate ‘[EnumerationSeparator]’ into ‘, ’ to produce lists like ‘apple, orange, strawberry’. Eastern languages might translate into ‘、’ to produce lists like ‘リンゴ、オレンジ、イチゴ’. */)
}

// UnitSeparator returns the separator to use when concatenating multiple units of the same metric
// (e.g. "1 minute, 32 seconds", "6 feet, 1 inch"). For English and western languages, unit
// separator is a comma followed by a space (i.e. ", "). For Slovenian and Japanese, it returns
// just space.
func UnitSeparator() string {
	// BUG: We could just use `Sprintf(", " /* ...translator instructions... */)` and let the
	// individual locale catalog handle its translation. Unfortunately, the gotext utility tries to
	// be nice to translators and skips all strings without letters when updating catalogs.
	return Sprintf("[UnitSeparator]" /* Text to insert when combining units of a measure - most languages will translate ‘[UnitSeparator]’ into ‘ ’ (space) to produce lists like ‘2 minuti 30 sekund’, or empty string ‘’ to produce ‘2分30秒’. */)
}
