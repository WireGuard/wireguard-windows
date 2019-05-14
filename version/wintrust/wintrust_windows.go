/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wintrust

import (
	"syscall"

	"golang.org/x/sys/windows"
)

type WinTrustData struct {
	CbStruct                        uint32
	PolicyCallbackData              uintptr
	SIPClientData                   uintptr
	UIChoice                        uint32
	RevocationChecks                uint32
	UnionChoice                     uint32
	FileOrCatalogOrBlobOrSgnrOrCert uintptr
	StateAction                     uint32
	StateData                       syscall.Handle
	URLReference                    *uint16
	ProvFlags                       uint32
	UIContext                       uint32
	SignatureSettings               *WintrustSignatureSettings
}

const (
	WTD_UI_ALL    = 1
	WTD_UI_NONE   = 2
	WTD_UI_NOBAD  = 3
	WTD_UI_NOGOOD = 4
)

const (
	WTD_REVOKE_NONE       = 0
	WTD_REVOKE_WHOLECHAIN = 1
)

const (
	WTD_CHOICE_FILE    = 1
	WTD_CHOICE_CATALOG = 2
	WTD_CHOICE_BLOB    = 3
	WTD_CHOICE_SIGNER  = 4
	WTD_CHOICE_CERT    = 5
)

const (
	WTD_STATEACTION_IGNORE           = 0x00000000
	WTD_STATEACTION_VERIFY           = 0x00000010
	WTD_STATEACTION_CLOSE            = 0x00000002
	WTD_STATEACTION_AUTO_CACHE       = 0x00000003
	WTD_STATEACTION_AUTO_CACHE_FLUSH = 0x00000004
)

const (
	WTD_USE_IE4_TRUST_FLAG                  = 0x1
	WTD_NO_IE4_CHAIN_FLAG                   = 0x2
	WTD_NO_POLICY_USAGE_FLAG                = 0x4
	WTD_REVOCATION_CHECK_NONE               = 0x10
	WTD_REVOCATION_CHECK_END_CERT           = 0x20
	WTD_REVOCATION_CHECK_CHAIN              = 0x40
	WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x80
	WTD_SAFER_FLAG                          = 0x100
	WTD_HASH_ONLY_FLAG                      = 0x200
	WTD_USE_DEFAULT_OSVER_CHECK             = 0x400
	WTD_LIFETIME_SIGNING_FLAG               = 0x800
	WTD_CACHE_ONLY_URL_RETRIEVAL            = 0x1000
	WTD_DISABLE_MD2_MD4                     = 0x2000
	WTD_MOTW                                = 0x4000
)

const (
	TRUST_E_NOSIGNATURE         = 0x800B0100
	TRUST_E_EXPLICIT_DISTRUST   = 0x800B0111
	TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
	CRYPT_E_SECURITY_SETTINGS   = 0x80092026
)

const (
	WTD_UICONTEXT_EXECUTE = 0
	WTD_UICONTEXT_INSTALL = 1
)

var WINTRUST_ACTION_GENERIC_VERIFY_V2 = windows.GUID{
	Data1: 0xaac56b,
	Data2: 0xcd44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
}

type WinTrustFileInfo struct {
	CbStruct     uint32
	FilePath     *uint16
	File         windows.Handle
	KnownSubject *windows.GUID
}

type WintrustSignatureSettings struct {
	CbStruct         uint32
	Index            uint32
	Flags            uint32
	SecondarySigs    uint32
	VerifiedSigIndex uint32
	CryptoPolicy     *CertStrongSignPara
}

type CertStrongSignPara struct {
	CbStruct                  uint32
	InfoChoice                uint32
	InfoOrSerializedInfoOrOID uintptr
}

//sys	WinVerifyTrust(hWnd windows.Handle, actionId *windows.GUID, data *WinTrustData) (err error) [r1 != 0] = wintrust.WinVerifyTrust
