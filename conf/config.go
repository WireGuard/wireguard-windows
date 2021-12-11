/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"golang.zx2c4.com/go118/netip"

	"golang.org/x/crypto/curve25519"

	"golang.zx2c4.com/wireguard/windows/l18n"
)

const KeyLength = 32

type Endpoint struct {
	Host string
	Port uint16
}

type (
	Key           [KeyLength]byte
	HandshakeTime time.Duration
	Bytes         uint64
)

type Config struct {
	Name      string
	Interface Interface
	Peers     []Peer
}

type Interface struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	ListenPort uint16
	MTU        uint16
	DNS        []netip.Addr
	DNSSearch  []string
	PreUp      string
	PostUp     string
	PreDown    string
	PostDown   string
	TableOff   bool
}

type Peer struct {
	PublicKey           Key
	PresharedKey        Key
	AllowedIPs          []netip.Prefix
	Endpoint            Endpoint
	PersistentKeepalive uint16
	UpdateEndpointIP    uint16

	RxBytes           Bytes
	TxBytes           Bytes
	LastHandshakeTime HandshakeTime
	UnresolvedHost    string
}

func (conf *Config) IntersectsWith(other *Config) bool {
	allRoutes := make(map[netip.Prefix]bool, len(conf.Interface.Addresses)*2+len(conf.Peers)*3)
	for _, a := range conf.Interface.Addresses {
		allRoutes[netip.PrefixFrom(a.Addr(), a.Addr().BitLen())] = true
		allRoutes[a.Masked()] = true
	}
	for i := range conf.Peers {
		for _, a := range conf.Peers[i].AllowedIPs {
			allRoutes[a.Masked()] = true
		}
	}
	for _, a := range other.Interface.Addresses {
		if allRoutes[netip.PrefixFrom(a.Addr(), a.Addr().BitLen())] {
			return true
		}
		if allRoutes[a.Masked()] {
			return true
		}
	}
	for i := range other.Peers {
		for _, a := range other.Peers[i].AllowedIPs {
			if allRoutes[a.Masked()] {
				return true
			}
		}
	}
	return false
}

func (e *Endpoint) String() string {
	if strings.IndexByte(e.Host, ':') != -1 {
		return fmt.Sprintf("[%s]:%d", e.Host, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Endpoint) IsEmpty() bool {
	return len(e.Host) == 0
}

func (k *Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k *Key) IsZero() bool {
	var zeros Key
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

func (k *Key) Public() *Key {
	var p [KeyLength]byte
	curve25519.ScalarBaseMult(&p, (*[KeyLength]byte)(k))
	return (*Key)(&p)
}

func NewPresharedKey() (*Key, error) {
	var k [KeyLength]byte
	_, err := rand.Read(k[:])
	if err != nil {
		return nil, err
	}
	return (*Key)(&k), nil
}

func NewPrivateKey() (*Key, error) {
	k, err := NewPresharedKey()
	if err != nil {
		return nil, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

func NewPrivateKeyFromString(b64 string) (*Key, error) {
	return parseKeyBase64(b64)
}

func (t HandshakeTime) IsEmpty() bool {
	return t == HandshakeTime(0)
}

func (t HandshakeTime) String() string {
	u := time.Unix(0, 0).Add(time.Duration(t)).Unix()
	n := time.Now().Unix()
	if u == n {
		return l18n.Sprintf("Now")
	} else if u > n {
		return l18n.Sprintf("System clock wound backward!")
	}
	left := n - u
	years := left / (365 * 24 * 60 * 60)
	left = left % (365 * 24 * 60 * 60)
	days := left / (24 * 60 * 60)
	left = left % (24 * 60 * 60)
	hours := left / (60 * 60)
	left = left % (60 * 60)
	minutes := left / 60
	seconds := left % 60
	s := make([]string, 0, 5)
	if years > 0 {
		s = append(s, l18n.Sprintf("%d year(s)", years))
	}
	if days > 0 {
		s = append(s, l18n.Sprintf("%d day(s)", days))
	}
	if hours > 0 {
		s = append(s, l18n.Sprintf("%d hour(s)", hours))
	}
	if minutes > 0 {
		s = append(s, l18n.Sprintf("%d minute(s)", minutes))
	}
	if seconds > 0 {
		s = append(s, l18n.Sprintf("%d second(s)", seconds))
	}
	timestamp := strings.Join(s, l18n.UnitSeparator())
	return l18n.Sprintf("%s ago", timestamp)
}

func (b Bytes) String() string {
	if b < 1024 {
		return l18n.Sprintf("%d\u00a0B", b)
	} else if b < 1024*1024 {
		return l18n.Sprintf("%.2f\u00a0KiB", float64(b)/1024)
	} else if b < 1024*1024*1024 {
		return l18n.Sprintf("%.2f\u00a0MiB", float64(b)/(1024*1024))
	} else if b < 1024*1024*1024*1024 {
		return l18n.Sprintf("%.2f\u00a0GiB", float64(b)/(1024*1024*1024))
	}
	return l18n.Sprintf("%.2f\u00a0TiB", float64(b)/(1024*1024*1024)/1024)
}

func (conf *Config) DeduplicateNetworkEntries() {
	m := make(map[string]bool, len(conf.Interface.Addresses))
	i := 0
	for _, addr := range conf.Interface.Addresses {
		s := addr.String()
		if m[s] {
			continue
		}
		m[s] = true
		conf.Interface.Addresses[i] = addr
		i++
	}
	conf.Interface.Addresses = conf.Interface.Addresses[:i]

	m = make(map[string]bool, len(conf.Interface.DNS))
	i = 0
	for _, addr := range conf.Interface.DNS {
		s := addr.String()
		if m[s] {
			continue
		}
		m[s] = true
		conf.Interface.DNS[i] = addr
		i++
	}
	conf.Interface.DNS = conf.Interface.DNS[:i]

	for _, peer := range conf.Peers {
		m = make(map[string]bool, len(peer.AllowedIPs))
		i = 0
		for _, addr := range peer.AllowedIPs {
			s := addr.String()
			if m[s] {
				continue
			}
			m[s] = true
			peer.AllowedIPs[i] = addr
			i++
		}
		peer.AllowedIPs = peer.AllowedIPs[:i]
	}
}

func (conf *Config) Redact() {
	conf.Interface.PrivateKey = Key{}
	for i := range conf.Peers {
		conf.Peers[i].PublicKey = Key{}
		conf.Peers[i].PresharedKey = Key{}
	}
}
