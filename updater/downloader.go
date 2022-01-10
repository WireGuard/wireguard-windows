/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/blake2b"

	"golang.zx2c4.com/wireguard/windows/elevate"
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

func CheckForUpdate() (updateFound *UpdateFound, err error) {
	updateFound, _, _, err = checkForUpdate(false)
	return
}

func checkForUpdate(keepSession bool) (*UpdateFound, *winhttp.Session, *winhttp.Connection, error) {
	if !version.IsRunningOfficialVersion() {
		return nil, nil, nil, errors.New("Build is not official, so updates are disabled")
	}
	session, err := winhttp.NewSession(version.UserAgent())
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil || !keepSession {
			session.Close()
		}
	}()
	connection, err := session.Connect(updateServerHost, updateServerPort, updateServerUseHttps)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if err != nil || !keepSession {
			connection.Close()
		}
	}()
	response, err := connection.Get(latestVersionPath, true)
	if err != nil {
		return nil, nil, nil, err
	}
	defer response.Close()
	var fileList [1024 * 512] /* 512 KiB */ byte
	bytesRead, err := response.Read(fileList[:])
	if err != nil && (err != io.EOF || bytesRead == 0) {
		return nil, nil, nil, err
	}
	files, err := readFileList(fileList[:bytesRead])
	if err != nil {
		return nil, nil, nil, err
	}
	updateFound, err := findCandidate(files)
	if err != nil {
		return nil, nil, nil, err
	}
	if keepSession {
		return updateFound, session, connection, nil
	}
	return updateFound, nil, nil, nil
}

var updateInProgress = uint32(0)

func DownloadVerifyAndExecute(userToken uintptr) (progress chan DownloadProgress) {
	progress = make(chan DownloadProgress, 128)
	progress <- DownloadProgress{Activity: "Initializing"}

	if !atomic.CompareAndSwapUint32(&updateInProgress, 0, 1) {
		progress <- DownloadProgress{Error: errors.New("An update is already in progress")}
		return
	}

	doIt := func() {
		defer atomic.StoreUint32(&updateInProgress, 0)

		progress <- DownloadProgress{Activity: "Checking for update"}
		update, session, connection, err := checkForUpdate(true)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		defer connection.Close()
		defer session.Close()
		if update == nil {
			progress <- DownloadProgress{Error: errors.New("No update was found")}
			return
		}

		progress <- DownloadProgress{Activity: "Creating temporary file"}
		file, err := msiTempFile()
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		progress <- DownloadProgress{Activity: fmt.Sprintf("Msi destination is %#q", file.Name())}
		defer func() {
			if file != nil {
				file.Delete()
			}
		}()

		dp := DownloadProgress{Activity: "Downloading update"}
		progress <- dp
		response, err := connection.Get(fmt.Sprintf(msiPath, update.name), false)
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

		progress <- DownloadProgress{Activity: "Verifying authenticode signature"}
		if !verifyAuthenticode(file.ExclusivePath()) {
			progress <- DownloadProgress{Error: errors.New("The downloaded update does not have an authentic authenticode signature")}
			return
		}

		progress <- DownloadProgress{Activity: "Installing update"}
		err = runMsi(file, userToken)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}

		progress <- DownloadProgress{Complete: true}
	}
	if userToken == 0 {
		go func() {
			err := elevate.DoAsSystem(func() error {
				doIt()
				return nil
			})
			if err != nil {
				progress <- DownloadProgress{Error: err}
			}
		}()
	} else {
		go doIt()
	}

	return progress
}
