/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"os"

	"github.com/lxn/walk"
)

type orderedStringSet struct {
	items      []string
	item2index map[string]int
}

func orderedStringSetFromSlice(items []string) *orderedStringSet {
	oss := newOrderedStringSet()
	oss.AddMany(items)
	return oss
}

func newOrderedStringSet() *orderedStringSet {
	return &orderedStringSet{item2index: make(map[string]int)}
}

func (oss *orderedStringSet) Add(item string) bool {
	if _, ok := oss.item2index[item]; ok {
		return false
	}

	oss.item2index[item] = len(oss.items)
	oss.items = append(oss.items, item)
	return true
}

func (oss *orderedStringSet) AddMany(items []string) {
	for _, item := range items {
		oss.Add(item)
	}
}

func (oss *orderedStringSet) UniteWith(other *orderedStringSet) {
	if other == oss {
		return
	}

	oss.AddMany(other.items)
}

func (oss *orderedStringSet) Remove(item string) bool {
	if i, ok := oss.item2index[item]; ok {
		oss.items = append(oss.items[:i], oss.items[i+1:]...)
		delete(oss.item2index, item)
		return true
	}

	return false
}

func (oss *orderedStringSet) Len() int {
	return len(oss.items)
}

func (oss *orderedStringSet) ToSlice() []string {
	return append(([]string)(nil), oss.items...)
}

func (oss *orderedStringSet) Contains(item string) bool {
	_, ok := oss.item2index[item]
	return ok
}

func (oss *orderedStringSet) IsSupersetOf(other *orderedStringSet) bool {
	if oss.Len() < other.Len() {
		return false
	}

	for _, item := range other.items {
		if !oss.Contains(item) {
			return false
		}
	}

	return true
}

func (oss *orderedStringSet) String() string {
	return fmt.Sprintf("%v", oss.items)
}

func writeFileWithOverwriteHandling(owner walk.Form, filePath string, write func(file *os.File) error) bool {
	showError := func(err error) bool {
		if err == nil {
			return false
		}

		walk.MsgBox(owner, "Writing file failed", err.Error(), walk.MsgBoxIconError)

		return true
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			if walk.DlgCmdNo == walk.MsgBox(owner, "Writing file failed", fmt.Sprintf(`File "%s" already exists.

Do you want to overwrite it?`, filePath), walk.MsgBoxYesNo|walk.MsgBoxDefButton2|walk.MsgBoxIconWarning) {
				return false
			}

			if file, err = os.Create(filePath); err != nil {
				return !showError(err)
			}
		} else {
			return !showError(err)
		}
	}
	defer file.Close()

	return !showError(write(file))
}
