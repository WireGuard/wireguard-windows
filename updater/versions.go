/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/windows/version"
)

func versionNewerThanUs(candidate string) (bool, error) {
	candidateParts := strings.Split(candidate, ".")
	ourParts := strings.Split(version.Number, ".")
	if len(candidateParts) == 0 || len(ourParts) == 0 {
		return false, errors.New("Empty version")
	}
	l := len(candidateParts)
	if len(ourParts) > l {
		l = len(ourParts)
	}
	for i := 0; i < l; i++ {
		var err error
		cP, oP := uint64(0), uint64(0)
		if i < len(candidateParts) {
			if len(candidateParts[i]) == 0 {
				return false, errors.New("Empty version part")
			}
			cP, err = strconv.ParseUint(candidateParts[i], 10, 16)
			if err != nil {
				return false, errors.New("Invalid version integer part")
			}
		}
		if i < len(ourParts) {
			if len(ourParts[i]) == 0 {
				return false, errors.New("Empty version part")
			}
			oP, err = strconv.ParseUint(ourParts[i], 10, 16)
			if err != nil {
				return false, errors.New("Invalid version integer part")
			}
		}
		if cP == oP {
			continue
		}
		return cP > oP, nil
	}
	return false, nil
}

func findCandidate(candidates fileList) (*UpdateFound, error) {
	prefix := fmt.Sprintf(msiArchPrefix, version.NativeArch())
	suffix := msiSuffix
	for name, hash := range candidates {
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			version := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
			if len(version) > 128 {
				return nil, errors.New("Version length is too long")
			}
			newer, err := versionNewerThanUs(version)
			if err != nil {
				return nil, err
			}
			if newer {
				return &UpdateFound{name, hash}, nil
			}
		}
	}
	return nil, nil
}
