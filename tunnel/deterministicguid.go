/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"encoding/binary"
	"sort"
	"unsafe"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/sys/windows"
	"golang.org/x/text/unicode/norm"

	"golang.zx2c4.com/wireguard/windows/conf"
)

const deterministicGUIDLabel = "Deterministic WireGuard Windows GUID v1 jason@zx2c4.com"
const fixedGUIDLabel = "Fixed WireGuard Windows GUID v1 jason@zx2c4.com"

// Escape hatch for external consumers, not us.
var UseFixedGUIDInsteadOfDeterministic = false

/* All peer public keys and allowed ips are sorted. Length/number fields are
 * little endian 32-bit. Hash input is:
 *
 * label || len(interface name) || interface name ||
 * interface public key || number of peers ||
 * peer public key || number of peer allowed ips ||
 * len(allowed ip string) || allowed ip/cidr in canonical string notation ||
 * len(allowed ip string) || allowed ip/cidr in canonical string notation ||
 * len(allowed ip string) || allowed ip/cidr in canonical string notation ||
 * ...
 * peer public key || number of peer allowed ips ||
 * len(allowed ip string) || allowed ip/cidr in canonical string notation ||
 * len(allowed ip string) || allowed ip/cidr in canonical string notation ||
 * len(allowed ip string) || allowed ip/cidr in canonical string notation ||
 * ...
 * ...
 */

func deterministicGUID(c *conf.Config) *windows.GUID {
	b2, _ := blake2s.New256(nil)
	if !UseFixedGUIDInsteadOfDeterministic {
		b2.Write([]byte(deterministicGUIDLabel))
	} else {
		b2.Write([]byte(fixedGUIDLabel))
	}
	b2Number := func(i int) {
		if uint(i) > uint(^uint32(0)) {
			panic("length out of bounds")
		}
		var bytes [4]byte
		binary.LittleEndian.PutUint32(bytes[:], uint32(i))
		b2.Write(bytes[:])
	}
	b2String := func(s string) {
		bytes := []byte(s)
		bytes = norm.NFC.Bytes(bytes)
		b2Number(len(bytes))
		b2.Write(bytes)
	}
	b2Key := func(k *conf.Key) {
		b2.Write(k[:])
	}

	b2String(c.Name)
	if !UseFixedGUIDInsteadOfDeterministic {
		b2Key(c.Interface.PrivateKey.Public())
		b2Number(len(c.Peers))
		sortedPeers := c.Peers
		sort.Slice(sortedPeers, func(i, j int) bool {
			return bytes.Compare(sortedPeers[i].PublicKey[:], sortedPeers[j].PublicKey[:]) < 0
		})
		for _, peer := range sortedPeers {
			b2Key(&peer.PublicKey)
			b2Number(len(peer.AllowedIPs))
			sortedAllowedIPs := peer.AllowedIPs
			sort.Slice(sortedAllowedIPs, func(i, j int) bool {
				if bi, bj := sortedAllowedIPs[i].Bits(), sortedAllowedIPs[j].Bits(); bi != bj {
					return bi < bj
				}
				if sortedAllowedIPs[i].Cidr != sortedAllowedIPs[j].Cidr {
					return sortedAllowedIPs[i].Cidr < sortedAllowedIPs[j].Cidr
				}
				return bytes.Compare(sortedAllowedIPs[i].IP[:], sortedAllowedIPs[j].IP[:]) < 0
			})
			for _, allowedip := range sortedAllowedIPs {
				b2String(allowedip.String())
			}
		}
	}
	return (*windows.GUID)(unsafe.Pointer(&b2.Sum(nil)[0]))
}
