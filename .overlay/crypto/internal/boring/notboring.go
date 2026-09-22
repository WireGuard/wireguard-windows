//go:build !(boringcrypto && linux && (amd64 || arm64) && !android && !msan && cgo)

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package boring

const available = false

type randReader int

const RandReader = randReader(0)

func (randReader) Read([]byte) (int, error) { panic("") }

type PublicKeyECDH struct{}
type PrivateKeyECDH struct{}

func ECDH(*PrivateKeyECDH, *PublicKeyECDH) ([]byte, error)      { panic("") }
func GenerateKeyECDH(string) (*PrivateKeyECDH, []byte, error)   { panic("") }
func NewPrivateKeyECDH(string, []byte) (*PrivateKeyECDH, error) { panic("") }
func NewPublicKeyECDH(string, []byte) (*PublicKeyECDH, error)   { panic("") }
func (*PublicKeyECDH) Bytes() []byte                            { panic("") }
func (*PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error)      { panic("") }
