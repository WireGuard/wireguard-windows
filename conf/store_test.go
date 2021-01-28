/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"reflect"
	"testing"
)

func TestStorage(t *testing.T) {
	c, err := FromWgQuick(testInput, "golangTest")
	if err != nil {
		t.Errorf("Unable to parse test config: %s", err.Error())
		return
	}

	err = c.Save()
	if err != nil {
		t.Errorf("Unable to save config: %s", err.Error())
	}

	configs, err := ListConfigNames()
	if err != nil {
		t.Errorf("Unable to list configs: %s", err.Error())
	}

	found := false
	for _, name := range configs {
		if name == "golangTest" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Unable to find saved config in list")
	}

	loaded, err := LoadFromName("golangTest")
	if err != nil {
		t.Errorf("Unable to load config: %s", err.Error())
		return
	}

	if !reflect.DeepEqual(loaded, c) {
		t.Error("Loaded config is not the same as saved config")
	}

	k, err := NewPrivateKey()
	if err != nil {
		t.Errorf("Unable to generate new private key: %s", err.Error())
	}
	c.Interface.PrivateKey = *k

	err = c.Save()
	if err != nil {
		t.Errorf("Unable to save config a second time: %s", err.Error())
	}

	loaded, err = LoadFromName("golangTest")
	if err != nil {
		t.Errorf("Unable to load config a second time: %s", err.Error())
		return
	}

	if !reflect.DeepEqual(loaded, c) {
		t.Error("Second loaded config is not the same as second saved config")
	}

	err = DeleteName("golangTest")
	if err != nil {
		t.Errorf("Unable to delete config: %s", err.Error())
	}

	configs, err = ListConfigNames()
	if err != nil {
		t.Errorf("Unable to list configs: %s", err.Error())
	}
	found = false
	for _, name := range configs {
		if name == "golangTest" {
			found = true
			break
		}
	}
	if found {
		t.Error("Config wasn't actually deleted")
	}
}
