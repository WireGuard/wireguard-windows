/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"testing"
)

func TestUpdate(t *testing.T) {
	update, err := CheckForUpdate()
	if err != nil {
		t.Error(err)
		return
	}
	if update == nil {
		t.Error("No update available")
		return
	}
	t.Log("Found update")
	progress := DownloadVerifyAndExecute(0, nil)
	for {
		dp := <-progress
		if dp.Error != nil {
			t.Error(dp.Error)
			return
		}
		if len(dp.Activity) > 0 {
			t.Log(dp.Activity)
		}
		if dp.BytesTotal > 0 {
			t.Logf("Downloaded %d of %d", dp.BytesDownloaded, dp.BytesTotal)
		}
		if dp.Complete {
			t.Log("Complete!")
			break
		}
	}
}
