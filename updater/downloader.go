/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.zx2c4.com/wireguard/windows/version"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"sync/atomic"
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
	request, err := http.NewRequest(http.MethodGet, latestVersionURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("User-Agent", version.UserAgent())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var fileList [1024 * 512] /* 512 KiB */ byte
	bytesRead, err := response.Body.Read(fileList[:])
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

func DownloadVerifyAndExecute() (progress chan DownloadProgress) {
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

		progress <- DownloadProgress{Activity: "Creating update file"}
		updateDir, err := msiSaveDirectory()
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		// Clean up old updates the brutal way:
		os.RemoveAll(updateDir)

		err = os.MkdirAll(updateDir, 0700)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		destinationFilename := path.Join(updateDir, update.name)
		unverifiedDestinationFilename := destinationFilename + ".unverified"
		out, err := os.Create(unverifiedDestinationFilename)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		defer func() {
			if out != nil {
				out.Seek(0, io.SeekStart)
				out.Truncate(0)
				out.Close()
				os.Remove(unverifiedDestinationFilename)
			}
		}()

		dp := DownloadProgress{Activity: "Downloading update"}
		progress <- dp
		request, err := http.NewRequest(http.MethodGet, fmt.Sprintf(msiURL, update.name), nil)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		request.Header.Add("User-Agent", version.UserAgent())
		request.Header.Set("Accept-Encoding", "identity")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		defer response.Body.Close()
		if response.ContentLength >= 0 {
			dp.BytesTotal = uint64(response.ContentLength)
			progress <- dp
		}
		hasher, err := blake2b.New256(nil)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		pm := &progressHashWatcher{&dp, progress, hasher}
		_, err = io.Copy(out, io.TeeReader(io.LimitReader(response.Body, 1024*1024*100 /* 100 MiB */), pm))
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}
		if !hmac.Equal(hasher.Sum(nil), update.hash[:]) {
			progress <- DownloadProgress{Error: errors.New("The downloaded update has the wrong hash")}
			return
		}
		out.Close()
		out = nil
		err = os.Rename(unverifiedDestinationFilename, destinationFilename)
		if err != nil {
			os.Remove(unverifiedDestinationFilename)
			progress <- DownloadProgress{Error: err}
			return
		}
		progress <- DownloadProgress{Activity: "Installing update"}
		err = runMsi(destinationFilename)
		os.Remove(unverifiedDestinationFilename)
		if err != nil {
			progress <- DownloadProgress{Error: err}
			return
		}

		progress <- DownloadProgress{Complete: true}
	}()

	return progress
}
