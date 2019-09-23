/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync/atomic"

	"golang.org/x/crypto/blake2b"

	"golang.zx2c4.com/wireguard/windows/updater/winhttp"
	"golang.zx2c4.com/wireguard/windows/version"
)

type DownloadProgress struct {
	Activity        string
	BytesDownloaded uint64
	BytesTotal      uint64
	Error           error
	Complete        bool
}

type progressHashWatcher struct {
	dp        *DownloadProgress
	c         chan DownloadProgress
	hashState hash.Hash
}

func (pm *progressHashWatcher) Write(p []byte) (int, error) {
	bytes := len(p)
	pm.dp.BytesDownloaded += uint64(bytes)
	pm.c <- *pm.dp
	pm.hashState.Write(p)
	return bytes, nil
}

type UpdateFound struct {
	name string
	hash [blake2b.Size256]byte
}

func CheckForUpdate() (*UpdateFound, error) {
	response, err := winhttp.Get(version.UserAgent(), latestVersionURL)
	if err != nil {
		return nil, err
	}
	defer response.Close()
	var fileList [1024 * 512] /* 512 KiB */ byte
	bytesRead, err := response.Read(fileList[:])
	if err != nil && (err != io.EOF || bytesRead == 0) {
		return nil, err
	}
	files, err := readFileList(fileList[:bytesRead])
	if err != nil {
		return nil, err
	}
	return findCandidate(files)
}

var updateInProgress = uint32(0)

func DownloadVerifyAndExecute(userToken uintptr) (progress chan DownloadProgress) {
	progress = make(chan DownloadProgress, 128)
	progress <- DownloadProgress{Activity: "Initializing"}

	if !atomic.CompareAndSwapUint32(&updateInProgress, 0, 1) {
		progress <- DownloadProgress{Error: errors.New("An update is already in progress")}
		return
	}

	go func() {
		defer atomic.StoreUint32(&updateInProgress, 0)

		progress <- DownloadProgress{Activity: "Rechecking for update"}
		update, err := CheckForUpdate()
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		if update == nil {
			progress <- DownloadProgress{Error: errors.New("No update was found when re-checking for updates")}
			return
		}

		progress <- DownloadProgress{Activity: "Creating temporary file"}
		file, err := msiTempFile()
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		defer func() {
			if file != nil {
				name := file.Name()
				file.Seek(0, io.SeekStart)
				file.Truncate(0)
				file.Close()
				os.Remove(name) // TODO: Do we have any sort of TOCTOU here?
			}
		}()

		dp := DownloadProgress{Activity: "Downloading update"}
		progress <- dp
		response, err := winhttp.Get(version.UserAgent(), fmt.Sprintf(msiURL, update.name))
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		defer response.Close()
		length, err := response.Length()
		if err == nil && length >= 0 {
			dp.BytesTotal = length
			progress <- dp
		}
		hasher, err := blake2b.New256(nil)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		pm := &progressHashWatcher{&dp, progress, hasher}
		_, err = io.Copy(file, io.TeeReader(io.LimitReader(response, 1024*1024*100 /* 100 MiB */), pm))
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		if !hmac.Equal(hasher.Sum(nil), update.hash[:]) {
			progress <- DownloadProgress{Error: errors.New("The downloaded update has the wrong hash")}
			return
		}

		// TODO: it would be nice to rename in place from "file.msi.unverified" to "file.msi", but Windows TOCTOU stuff
		// is hard, so we'll come back to this later.
		name := file.Name()
		file.Close()
		file = nil

		progress <- DownloadProgress{Activity: "Verifying authenticode signature"}
		if !version.VerifyAuthenticode(name) {
			os.Remove(name) // TODO: Do we have any sort of TOCTOU here?
			progress <- DownloadProgress{Error: errors.New("The downloaded update does not have an authentic authenticode signature")}
			return
		}

		progress <- DownloadProgress{Activity: "Installing update"}
		err = runMsi(name, userToken)
		os.Remove(name) // TODO: Do we have any sort of TOCTOU here?
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}

		progress <- DownloadProgress{Complete: true}
	}()

	return progress
}
