/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package updater

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/blake2b"
)

/*
 * Generate with:
 *   $ b2sum -l 256 *.msi > list
 *   $ signify -S -e -s release.sec -m list
 *   $ upload ./list.sec
 */

type fileList map[string][blake2b.Size256]byte

func readFileList(input []byte) (fileList, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(releasePublicKeyBase64)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize+10 || publicKeyBytes[0] != 'E' || publicKeyBytes[1] != 'd' {
		return nil, errors.New("Invalid public key")
	}
	lines := bytes.SplitN(input, []byte{'\n'}, 3)
	if len(lines) != 3 {
		return nil, errors.New("Signature input has too few lines")
	}
	if !bytes.HasPrefix(lines[0], []byte("untrusted comment: ")) {
		return nil, errors.New("Signature input is missing untrusted comment")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(string(lines[1]))
	if err != nil {
		return nil, errors.New("Signature input is not valid base64")
	}
	if len(signatureBytes) != ed25519.SignatureSize+10 || !bytes.Equal(signatureBytes[:10], publicKeyBytes[:10]) {
		return nil, errors.New("Signature input bytes are incorrect length, type, or keyid")
	}
	if !ed25519.Verify(publicKeyBytes[10:], lines[2], signatureBytes[10:]) {
		return nil, errors.New("Signature is invalid")
	}
	fileLines := strings.Split(string(lines[2]), "\n")
	fileHashes := make(map[string][blake2b.Size256]byte, len(fileLines))
	for index, line := range fileLines {
		if len(line) == 0 && index == len(fileLines)-1 {
			break
		}
		first, second, ok := strings.Cut(line, "  ")
		if !ok {
			return nil, errors.New("File hash line has too few components")
		}
		maybeHash, err := hex.DecodeString(first)
		if err != nil || len(maybeHash) != blake2b.Size256 {
			return nil, errors.New("File hash is invalid base64 or incorrect number of bytes")
		}
		var hash [blake2b.Size256]byte
		copy(hash[:], maybeHash)
		fileHashes[second] = hash
	}
	if len(fileHashes) == 0 {
		return nil, errors.New("No file hashes found in signed input")
	}
	return fileHashes, nil
}
