/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package updater

const (
	releasePublicKeyBase64 = "RWRNqGKtBXftKTKPpBPGDMe8jHLnFQ0EdRy8Wg0apV6vTDFLAODD83G4"
	updateServerHost       = "download.wireguard.com"
	updateServerPort       = 443
	updateServerUseHttps   = true
	latestVersionPath      = "/windows-client/latest.sig"
	msiPath                = "/windows-client/%s"
	msiArchPrefix          = "wireguard-%s-"
	msiSuffix              = ".msi"
)
