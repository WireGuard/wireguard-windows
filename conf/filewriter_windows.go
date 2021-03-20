/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"os"
)

func writeLockedDownFile(destination string, overwrite bool, contents []byte) error {
	// Simple file write
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY, 0777)
	f.WriteString(string(contents))
	defer f.Close()

	if err != nil {
		return err
	}

	return nil
}
