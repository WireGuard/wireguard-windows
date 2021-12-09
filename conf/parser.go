/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/base64"
	"strconv"
	"strings"

	"golang.zx2c4.com/go118/netip"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"

	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/l18n"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return l18n.Sprintf("%s: %q", e.why, e.offender)
}

func parseIPCidr(s string) (netip.Prefix, error) {
	ipcidr, err := netip.ParsePrefix(s)
	if err == nil {
		return ipcidr, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, &ParseError{l18n.Sprintf("Invalid IP address: "), s}
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func parseEndpoint(s string) (*Endpoint, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, &ParseError{l18n.Sprintf("Missing port from endpoint"), s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return nil, &ParseError{l18n.Sprintf("Invalid endpoint host"), host}
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{l18n.Sprintf("Brackets must contain an IPv6 address"), host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			end := len(host) - 1
			if i := strings.LastIndexByte(host, '%'); i > 1 {
				end = i
			}
			maybeV6, err2 := netip.ParseAddr(host[1:end])
			if err2 != nil || !maybeV6.Is6() {
				return nil, err
			}
		} else {
			return nil, err
		}
		host = host[1 : len(host)-1]
	}
	return &Endpoint{host, port}, nil
}

func parseMTU(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 576 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid MTU"), s}
	}
	return uint16(m), nil
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid port"), s}
	}
	return uint16(m), nil
}

func parsePersistentKeepalive(s string) (uint16, error) {
	if s == "off" {
		return 0, nil
	}
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid persistent keepalive"), s}
	}
	return uint16(m), nil
}

func parseTableOff(s string) (bool, error) {
	if s == "off" {
		return true, nil
	} else if s == "auto" || s == "main" {
		return false, nil
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return false, err
}

func parseKeyBase64(s string) (*Key, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, &ParseError{l18n.Sprintf("Invalid key: %v", err), s}
	}
	if len(k) != KeyLength {
		return nil, &ParseError{l18n.Sprintf("Keys must decode to exactly 32 bytes"), s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func splitList(s string) ([]string, error) {
	var out []string
	for _, split := range strings.Split(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, &ParseError{l18n.Sprintf("Two commas in a row"), s}
		}
		out = append(out, trim)
	}
	return out, nil
}

type parserState int

const (
	inInterfaceSection parserState = iota
	inPeerSection
	notInASection
)

func (c *Config) maybeAddPeer(p *Peer) {
	if p != nil {
		c.Peers = append(c.Peers, *p)
	}
}

func FromWgQuick(s, name string) (*Config, error) {
	if !TunnelNameIsValid(name) {
		return nil, &ParseError{l18n.Sprintf("Tunnel name is not valid"), name}
	}
	lines := strings.Split(s, "\n")
	parserState := notInASection
	conf := Config{Name: name}
	sawPrivateKey := false
	var peer *Peer
	for _, line := range lines {
		pound := strings.IndexByte(line, '#')
		if pound >= 0 {
			line = line[:pound]
		}
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		if len(line) == 0 {
			continue
		}
		if lineLower == "[interface]" {
			conf.maybeAddPeer(peer)
			parserState = inInterfaceSection
			continue
		}
		if lineLower == "[peer]" {
			conf.maybeAddPeer(peer)
			peer = &Peer{}
			parserState = inPeerSection
			continue
		}
		if parserState == notInASection {
			return nil, &ParseError{l18n.Sprintf("Line must occur in a section"), line}
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{l18n.Sprintf("Config key is missing an equals separator"), line}
		}
		key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
		if len(val) == 0 {
			return nil, &ParseError{l18n.Sprintf("Key must have a value"), line}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "privatekey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.PrivateKey = *k
				sawPrivateKey = true
			case "listenport":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.ListenPort = p
			case "mtu":
				m, err := parseMTU(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.MTU = m
			case "address":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					conf.Interface.Addresses = append(conf.Interface.Addresses, a)
				}
			case "dns":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := netip.ParseAddr(address)
					if err != nil {
						conf.Interface.DNSSearch = append(conf.Interface.DNSSearch, address)
					} else {
						conf.Interface.DNS = append(conf.Interface.DNS, a)
					}
				}
			case "preup":
				conf.Interface.PreUp = val
			case "postup":
				conf.Interface.PostUp = val
			case "predown":
				conf.Interface.PreDown = val
			case "postdown":
				conf.Interface.PostDown = val
			case "table":
				tableOff, err := parseTableOff(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.TableOff = tableOff
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for [Interface] section"), key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "publickey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "presharedkey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = *k
			case "allowedips":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					peer.AllowedIPs = append(peer.AllowedIPs, a)
				}
			case "persistentkeepalive":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoint = *e
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for [Peer] section"), key}
			}
		}
	}
	conf.maybeAddPeer(peer)

	if !sawPrivateKey {
		return nil, &ParseError{l18n.Sprintf("An interface must have a private key"), l18n.Sprintf("[none specified]")}
	}
	for _, p := range conf.Peers {
		if p.PublicKey.IsZero() {
			return nil, &ParseError{l18n.Sprintf("All peers must have public keys"), l18n.Sprintf("[none specified]")}
		}
	}

	return &conf, nil
}

func FromWgQuickWithUnknownEncoding(s, name string) (*Config, error) {
	c, firstErr := FromWgQuick(s, name)
	if firstErr == nil {
		return c, nil
	}
	for _, encoding := range unicode.All {
		decoded, err := encoding.NewDecoder().String(s)
		if err == nil {
			c, err := FromWgQuick(decoded, name)
			if err == nil {
				return c, nil
			}
		}
	}
	return nil, firstErr
}

func FromDriverConfiguration(interfaze *driver.Interface, existingConfig *Config) *Config {
	conf := Config{
		Name: existingConfig.Name,
		Interface: Interface{
			Addresses: existingConfig.Interface.Addresses,
			DNS:       existingConfig.Interface.DNS,
			DNSSearch: existingConfig.Interface.DNSSearch,
			MTU:       existingConfig.Interface.MTU,
			PreUp:     existingConfig.Interface.PreUp,
			PostUp:    existingConfig.Interface.PostUp,
			PreDown:   existingConfig.Interface.PreDown,
			PostDown:  existingConfig.Interface.PostDown,
			TableOff:  existingConfig.Interface.TableOff,
		},
	}
	if interfaze.Flags&driver.InterfaceHasPrivateKey != 0 {
		conf.Interface.PrivateKey = interfaze.PrivateKey
	}
	if interfaze.Flags&driver.InterfaceHasListenPort != 0 {
		conf.Interface.ListenPort = interfaze.ListenPort
	}
	var p *driver.Peer
	for i := uint32(0); i < interfaze.PeerCount; i++ {
		if p == nil {
			p = interfaze.FirstPeer()
		} else {
			p = p.NextPeer()
		}
		peer := Peer{}
		if p.Flags&driver.PeerHasPublicKey != 0 {
			peer.PublicKey = p.PublicKey
		}
		if p.Flags&driver.PeerHasPresharedKey != 0 {
			peer.PresharedKey = p.PresharedKey
		}
		if p.Flags&driver.PeerHasEndpoint != 0 {
			peer.Endpoint.Port = p.Endpoint.Port()
			peer.Endpoint.Host = p.Endpoint.Addr().String()
		}
		if p.Flags&driver.PeerHasPersistentKeepalive != 0 {
			peer.PersistentKeepalive = p.PersistentKeepalive
		}
		peer.TxBytes = Bytes(p.TxBytes)
		peer.RxBytes = Bytes(p.RxBytes)
		if p.LastHandshake != 0 {
			peer.LastHandshakeTime = HandshakeTime((p.LastHandshake - 116444736000000000) * 100)
		}
		var a *driver.AllowedIP
		for j := uint32(0); j < p.AllowedIPsCount; j++ {
			if a == nil {
				a = p.FirstAllowedIP()
			} else {
				a = a.NextAllowedIP()
			}
			var ip netip.Addr
			if a.AddressFamily == windows.AF_INET {
				ip = netip.AddrFrom4(*(*[4]byte)(a.Address[:4]))
			} else if a.AddressFamily == windows.AF_INET6 {
				ip = netip.AddrFrom16(*(*[16]byte)(a.Address[:16]))
			}
			peer.AllowedIPs = append(peer.AllowedIPs, netip.PrefixFrom(ip, int(a.Cidr)))
		}
		conf.Peers = append(conf.Peers, peer)
	}
	return &conf
}
