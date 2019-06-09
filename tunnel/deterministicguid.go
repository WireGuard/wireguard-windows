/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"encoding/binary"
	"sort"
	"unsafe"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
)

const deterministicGUIDLabel = "Deterministic WireGuard Windows GUID for interface: "

/* All peer public keys and allowed ips are sorted. Hash input is:
 *
 * label || interface name || zero padding to blake2s blocksize ||
 * interface public key ||
 * little endian 32-bit number of peers ||
 * peer public key || little endian 32-bit number of peer allowed ips ||
 * allowed ip in canonical string notation || '/' || cidr in decimal || '\n' ||
 * allowed ip in canonical string notation || '/' || cidr in decimal || '\n' ||
 * ...
 * peer public key || little endian 32-bit number of peer allowed ips ||
 * allowed ip in canonical string notation || '/' || cidr in decimal || '\n' ||
 * allowed ip in canonical string notation || '/' || cidr in decimal || '\n' ||
 * ...
 * ...
 */

func deterministicGUID(conf *conf.Config) *windows.GUID {
	b2, _ := blake2s.New256(nil)
	u32 := func(i uint32) {
		var bytes [4]byte
		binary.LittleEndian.PutUint32(bytes[:], i)
		b2.Write(bytes[:])
	}
	header := []byte(deterministicGUIDLabel)
	header = append(header, []byte(conf.Name)...)
	b2.Write(header)
	b2.Write(make([]byte, (((len(header)-1)|(blake2s.BlockSize-1))+1)-len(header)))
	b2.Write(conf.Interface.PrivateKey.Public()[:])
	u32(uint32(len(conf.Peers)))
	sortedPeers := conf.Peers
	sort.Slice(sortedPeers, func(i, j int) bool {
		return bytes.Compare(sortedPeers[i].PublicKey[:], sortedPeers[j].PublicKey[:]) < 0
	})
	for _, peer := range sortedPeers {
		b2.Write(peer.PublicKey[:])
		u32(uint32(len(peer.AllowedIPs)))
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
			b2.Write([]byte(allowedip.String() + "\n"))
		}
	}
	return (*windows.GUID)(unsafe.Pointer(&b2.Sum(nil)[0]))
}
