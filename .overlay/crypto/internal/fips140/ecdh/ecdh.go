/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ecdh

import "io"

type PrivateKey struct{}
type PublicKey struct{}
type Curve struct{}

func (*PrivateKey) Bytes() []byte                          { panic("") }
func (*PrivateKey) PublicKey() *PublicKey                  { panic("") }
func (*PublicKey) Bytes() []byte                           { panic("") }
func P224() *Curve                                         { panic("") }
func P256() *Curve                                         { panic("") }
func P384() *Curve                                         { panic("") }
func P521() *Curve                                         { panic("") }
func GenerateKey(*Curve, io.Reader) (*PrivateKey, error)   { panic("") }
func NewPrivateKey(*Curve, []byte) (*PrivateKey, error)    { panic("") }
func NewPublicKey(*Curve, []byte) (*PublicKey, error)      { panic("") }
func ECDH(*Curve, *PrivateKey, *PublicKey) ([]byte, error) { panic("") }
