/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package l18n

import (
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

type prnContext struct {
	printer              *message.Printer
	enumerationSeparator string
	unitSeparator        string
}

var (
	printer     *prnContext
	printerLock sync.Mutex
)

// prn returns the printer for user preferred UI language.
func prn() *prnContext {
	if printer != nil {
		return printer
	}
	printerLock.Lock()
	if printer != nil {
		printerLock.Unlock()
		return printer
	}
	lang, enumSep, unitSep := lang(), ", ", ", "
	base, _ := lang.Base()
	if faBase, _ := language.Persian.Base(); base == faBase {
		enumSep = "\u060c "
		unitSep = "\u060c "
	} else if frBase, _ := language.French.Base(); base == frBase {
		unitSep = " "
	} else if itBase, _ := language.Italian.Base(); base == itBase {
		unitSep = " "
	} else if jaBase, _ := language.Japanese.Base(); base == jaBase {
		unitSep = " "
	} else if nlBase, _ := language.Dutch.Base(); base == nlBase {
		unitSep = " "
	} else if skBase, _ := language.Slovak.Base(); base == skBase {
		unitSep = " "
	} else if slBase, _ := language.Slovenian.Base(); base == slBase {
		unitSep = " "
	} else if viBase, _ := language.Vietnamese.Base(); base == viBase {
		enumSep = ","
		unitSep = ","
	} else if zhBase, _ := language.Chinese.Base(); base == zhBase {
		enumSep = "\u3001"
		unitSep = " "
	}
	printer = &prnContext{
		printer:              message.NewPrinter(lang),
		enumerationSeparator: enumSep,
		unitSeparator:        unitSep,
	}
	printerLock.Unlock()
	return printer
}

func lang() language.Tag {
	languages, err := windows.GetThreadPreferredUILanguages(windows.MUI_LANGUAGE_NAME | windows.MUI_UI_FALLBACK)
	if err != nil {
		return language.English
	}
	available := message.DefaultCatalog.Languages()
	for _, l := range languages {
		t, err := language.Parse(l)
		if err != nil {
			continue
		}
		for ; !t.IsRoot(); t = t.Parent() {
			for _, a := range available {
				if a == t {
					return a
				}
			}
		}
	}
	return language.English
}

// Sprintf is like fmt.Sprintf, but using language-specific formatting.
func Sprintf(key message.Reference, a ...any) string {
	return prn().printer.Sprintf(key, a...)
}

// EnumerationSeparator returns enumeration separator. For English and western languages,
// enumeration separator is a comma followed by a space (i.e. ", "). For Chinese, it returns
// "\u3001".
func EnumerationSeparator() string {
	return prn().enumerationSeparator
}

// UnitSeparator returns the separator to use when concatenating multiple units of the same metric
// (e.g. "1 minute, 32 seconds", "6 feet, 1 inch"). For English and western languages, unit
// separator is a comma followed by a space (i.e. ", "). For Slovenian and Japanese, it returns
// just space.
func UnitSeparator() string {
	return prn().unitSeparator
}
