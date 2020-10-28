/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package syntax

import "strings"

type highlight int

const (
	highlightSection highlight = iota
	highlightField
	highlightPrivateKey
	highlightPublicKey
	highlightPresharedKey
	highlightIP
	highlightCidr
	highlightHost
	highlightPort
	highlightMTU
	highlightKeepalive
	highlightComment
	highlightDelimiter
	highlightTable
	highlightFwMark
	highlightSaveConfig
	highlightCmd
	highlightError
)

func validateHighlight(isValid bool, t highlight) highlight {
	if isValid {
		return t
	}
	return highlightError
}

type stringSpan struct {
	s, len int
}

type highlightSpan struct {
	stringSpan
	t highlight
}

type highlightSpanArray []highlightSpan

func (a *highlightSpanArray) append(s stringSpan, t highlight) {
	if s.len == 0 {
		return
	}
	*a = append(*a, highlightSpan{stringSpan{s.s, s.len}, t})
}

type config string

func isDecimal(c uint8) bool {
	return c >= '0' && c <= '9'
}

func isHexadecimal(c uint8) bool {
	return isDecimal(c) || ((c|32) >= 'a' && (c|32) <= 'f')
}

func isAlphabet(c uint8) bool {
	return (c|32) >= 'a' && (c|32) <= 'z'
}

func (cfg config) isSame(s stringSpan, c string) bool {
	return string(cfg[s.s:s.s+s.len]) == c
}

func (cfg config) isCaselessSame(s stringSpan, c string) bool {
	return strings.EqualFold(string(cfg[s.s:s.s+s.len]), c)
}

func (cfg config) isValidKey(s stringSpan) bool {
	if s.len != 44 || cfg[s.s+43] != '=' {
		return false
	}

	for i := 0; i < 42; i++ {
		if !isDecimal(cfg[s.s+i]) && !isAlphabet(cfg[s.s+i]) &&
			cfg[s.s+i] != '/' && cfg[s.s+i] != '+' {
			return false
		}
	}
	switch cfg[s.s+42] {
	case 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '4', '8', '0':
		return true
	}
	return false
}

func (cfg config) isValidHostname(s stringSpan) bool {
	numDigit := 0
	numEntity := s.len

	if s.len > 63 || s.len == 0 {
		return false
	}
	if cfg[s.s] == '-' || cfg[s.s+s.len-1] == '-' {
		return false
	}
	if cfg[s.s] == '.' || cfg[s.s+s.len-1] == '.' {
		return false
	}

	for i := 0; i < s.len; i++ {
		if isDecimal(cfg[s.s+i]) {
			numDigit++
			continue
		}
		if cfg[s.s+i] == '.' {
			numEntity--
			continue
		}

		if !isAlphabet(cfg[s.s+i]) && cfg[s.s+i] != '-' {
			return false
		}

		if i != 0 && cfg[s.s+i] == '.' && cfg[s.s+i-1] == '.' {
			return false
		}
	}
	return numDigit != numEntity
}

func (cfg config) isValidIPv4(s stringSpan) bool {
	pos := 0
	for i := 0; i < 4 && pos < s.len; i++ {
		val := uint32(0)

		j := 0
		for ; j < 3 && pos+j < s.len && isDecimal(cfg[s.s+pos+j]); j++ {
			val = 10*val + uint32(cfg[s.s+pos+j]-'0')
		}
		if j == 0 || (j > 1 && cfg[s.s+pos] == '0') || val > 255 {
			return false
		}
		if pos+j == s.len && i == 3 {
			return true
		}
		if cfg[s.s+pos+j] != '.' {
			return false
		}
		pos += j + 1
	}
	return false
}

func (cfg config) isValidIPv6(s stringSpan) bool {
	seenColon := false

	if s.len < 2 {
		return false
	}
	if cfg[s.s] == ':' && cfg[s.s+1] != ':' {
		return false
	}
	if cfg[s.s+s.len-1] == ':' && cfg[s.s+s.len-2] != ':' {
		return false
	}

	pos := 1
	for i := 0; pos < s.len; i++ {
		if cfg[s.s+pos] == ':' && !seenColon {
			seenColon = true
			pos++
			if pos == s.len {
				break
			}
			if i == 7 {
				return false
			}
			continue
		}
		j := 0
		for ; j < 4 && pos+j < s.len && isHexadecimal(cfg[s.s+pos+j]); j++ {
		}
		if j == 0 {
			return false
		}
		if pos+j == s.len && (seenColon || i == 7) {
			break
		}
		if i == 7 {
			return false
		}
		if cfg[s.s+pos+j] != ':' {
			if cfg[s.s+pos+j] != '.' || (i < 6 && !seenColon) {
				return false
			}
			return cfg.isValidIPv4(stringSpan{s.s + pos, s.len - pos})
		}
		pos += j + 1
	}
	return true
}

func (cfg config) isValidUint(s stringSpan, supportHex bool, min, max uint64) bool {
	val := uint64(0)

	/* Bound this around 32 bits, so that we don't have to write overflow logic. */
	if s.len > 10 || s.len == 0 {
		return false
	}

	if supportHex && s.len > 2 && cfg[s.s] == '0' && cfg[s.s+1] == 'x' {
		for i := 2; i < s.len; i++ {
			if cfg[s.s+i]-'0' < 10 {
				val = 16*val + uint64(cfg[s.s+i]-'0')
			} else if (cfg[s.s+i]|32)-'a' < 6 {
				val = 16*val + uint64((cfg[s.s+i]|32)-'a'+10)
			} else {
				return false
			}
		}
	} else {
		for i := 0; i < s.len; i++ {
			if !isDecimal(cfg[s.s+i]) {
				return false
			}
			val = 10*val + uint64(cfg[s.s+i]-'0')
		}
	}
	return val <= max && val >= min
}

func (cfg config) isValidPort(s stringSpan) bool {
	return cfg.isValidUint(s, false, 0, 65535)
}

func (cfg config) isValidMTU(s stringSpan) bool {
	return cfg.isValidUint(s, false, 576, 65535)
}

func (cfg config) isValidPersistentKeepAlive(s stringSpan) bool {
	if cfg.isSame(s, "off") {
		return true
	}
	return cfg.isValidUint(s, false, 0, 65535)
}

func (cfg config) isValidFwmark(s stringSpan) bool {
	if cfg.isSame(s, "off") {
		return true
	}
	return cfg.isValidUint(s, true, 0, 4294967295)
}

func (cfg config) isValidTable(s stringSpan) bool {
	if cfg.isSame(s, "auto") {
		return true
	}
	if cfg.isSame(s, "off") {
		return true
	}
	/* This pretty much invalidates the other checks, but rt_names.c's
	 * fread_id_name does no validation aside from this. */
	if s.len < 512 {
		return true
	}
	return cfg.isValidUint(s, false, 0, 4294967295)
}

func (cfg config) isValidSaveConfig(s stringSpan) bool {
	return cfg.isSame(s, "true") || cfg.isSame(s, "false")
}

func (cfg config) isValidPrePostUpDown(s stringSpan) bool {
	/* It's probably not worthwhile to try to validate a bash expression.
	 * So instead we just demand non-zero length. */
	return s.len != 0
}

func (cfg config) isValidScope(s stringSpan) bool {
	if s.len > 64 || s.len == 0 {
		return false
	}
	for i := 0; i < s.len; i++ {
		if !isAlphabet(cfg[s.s+i]) && !isDecimal(cfg[s.s+i]) &&
			cfg[s.s+i] != '_' && cfg[s.s+i] != '=' && cfg[s.s+i] != '+' &&
			cfg[s.s+i] != '.' && cfg[s.s+i] != '-' {
			return false
		}
	}
	return true
}

func (cfg config) isValidEndpoint(s stringSpan) bool {

	if s.len == 0 {
		return false
	}

	if cfg[s.s] == '[' {
		seenScope := false
		hostspan := stringSpan{s.s + 1, 0}

		for i := 1; i < s.len; i++ {
			if cfg[s.s+i] == '%' {
				if seenScope {
					return false
				}
				seenScope = true
				if !cfg.isValidIPv6(hostspan) {
					return false
				}
				hostspan = stringSpan{s.s + i + 1, 0}
			} else if cfg[s.s+i] == ']' {
				if seenScope {
					if !cfg.isValidScope(hostspan) {
						return false
					}
				} else if !cfg.isValidIPv6(hostspan) {
					return false
				}
				if i == s.len-1 || cfg[s.s+i+1] != ':' {
					return false
				}
				return cfg.isValidPort(stringSpan{s.s + i + 2, s.len - i - 2})
			} else {
				hostspan.len++
			}
		}
		return false
	}
	for i := 0; i < s.len; i++ {
		if cfg[s.s+i] == ':' {
			host := stringSpan{s.s, i}
			port := stringSpan{s.s + i + 1, s.len - i - 1}
			return cfg.isValidPort(port) && (cfg.isValidIPv4(host) || cfg.isValidHostname(host))
		}
	}
	return false
}

func (cfg config) isValidNetwork(s stringSpan) bool {
	for i := 0; i < s.len; i++ {
		if cfg[s.s+i] == '/' {
			ip := stringSpan{s.s, i}
			cidr := stringSpan{s.s + i + 1, s.len - i - 1}
			cidrval := uint16(0)

			if cidr.len > 3 || cidr.len == 0 {
				return false
			}

			for j := 0; j < cidr.len; j++ {
				if !isDecimal(cfg[cidr.s+j]) {
					return false
				}
				cidrval = 10*cidrval + uint16(cfg[cidr.s+j]-'0')
			}
			if cfg.isValidIPv4(ip) {
				return cidrval <= 32
			} else if cfg.isValidIPv6(ip) {
				return cidrval <= 128
			}
			return false
		}
	}
	return cfg.isValidIPv4(s) || cfg.isValidIPv6(s)
}

type field int

const (
	fieldInterfaceSection field = iota
	fieldPrivateKey
	fieldListenPort
	fieldAddress
	fieldDNS
	fieldMTU
	fieldFwMark
	fieldTable
	fieldPreUp
	fieldPostUp
	fieldPreDown
	fieldPostDown
	fieldSaveConfig

	fieldPeerSection
	fieldPublicKey
	fieldPresharedKey
	fieldAllowedIPs
	fieldEndpoint
	fieldPersistentKeepalive

	fieldInvalid
)

func (t field) section() field {
	if t > fieldInterfaceSection && t < fieldPeerSection {
		return fieldInterfaceSection
	}
	if t > fieldPeerSection && t < fieldInvalid {
		return fieldPeerSection
	}
	return fieldInvalid
}

func (cfg config) field(s stringSpan) field {
	switch {
	case cfg.isCaselessSame(s, "PrivateKey"):
		return fieldPrivateKey
	case cfg.isCaselessSame(s, "ListenPort"):
		return fieldListenPort
	case cfg.isCaselessSame(s, "Address"):
		return fieldAddress
	case cfg.isCaselessSame(s, "DNS"):
		return fieldDNS
	case cfg.isCaselessSame(s, "MTU"):
		return fieldMTU
	case cfg.isCaselessSame(s, "PublicKey"):
		return fieldPublicKey
	case cfg.isCaselessSame(s, "PresharedKey"):
		return fieldPresharedKey
	case cfg.isCaselessSame(s, "AllowedIPs"):
		return fieldAllowedIPs
	case cfg.isCaselessSame(s, "Endpoint"):
		return fieldEndpoint
	case cfg.isCaselessSame(s, "PersistentKeepalive"):
		return fieldPersistentKeepalive
	case cfg.isCaselessSame(s, "FwMark"):
		return fieldFwMark
	case cfg.isCaselessSame(s, "Table"):
		return fieldTable
	case cfg.isCaselessSame(s, "PreUp"):
		return fieldPreUp
	case cfg.isCaselessSame(s, "PostUp"):
		return fieldPostUp
	case cfg.isCaselessSame(s, "PreDown"):
		return fieldPreDown
	case cfg.isCaselessSame(s, "PostDown"):
		return fieldPostDown
	case cfg.isCaselessSame(s, "SaveConfig"):
		return fieldSaveConfig
	}
	return fieldInvalid
}

func (cfg config) section(s stringSpan) field {
	if cfg.isCaselessSame(s, "[Peer]") {
		return fieldPeerSection
	}
	if cfg.isCaselessSame(s, "[Interface]") {
		return fieldInterfaceSection
	}
	return fieldInvalid
}

func (cfg config) highlightMultivalueValue(ret *highlightSpanArray, s stringSpan, section field) {
	switch section {
	case fieldDNS:
		if cfg.isValidIPv4(s) || cfg.isValidIPv6(s) {
			ret.append(s, highlightIP)
		} else if cfg.isValidHostname(s) {
			ret.append(s, highlightHost)
		} else {
			ret.append(s, highlightError)
		}
	case fieldAddress, fieldAllowedIPs:
		if !cfg.isValidNetwork(s) {
			ret.append(s, highlightError)
			break
		}
		slash := 0
		for ; slash < s.len; slash++ {
			if cfg[s.s+slash] == '/' {
				break
			}
		}
		if slash == s.len {
			ret.append(s, highlightIP)
		} else {
			ret.append(stringSpan{s.s, slash}, highlightIP)
			ret.append(stringSpan{s.s + slash, 1}, highlightDelimiter)
			ret.append(stringSpan{s.s + slash + 1, s.len - slash - 1}, highlightCidr)
		}
	default:
		ret.append(s, highlightError)
	}
}

func (cfg config) highlightMultivalue(ret *highlightSpanArray, s stringSpan, section field) {
	currentSpan := stringSpan{s.s, 0}
	lenAtLastSpace := 0

	for i := 0; i < s.len; i++ {
		if cfg[s.s+i] == ',' {
			currentSpan.len = lenAtLastSpace
			cfg.highlightMultivalueValue(ret, currentSpan, section)
			ret.append(stringSpan{s.s + i, 1}, highlightDelimiter)
			lenAtLastSpace = 0
			currentSpan = stringSpan{s.s + i + 1, 0}
		} else if cfg[s.s+i] == ' ' || cfg[s.s+i] == '\t' {
			if s.s+i == currentSpan.s && currentSpan.len == 0 {
				currentSpan.s++
			} else {
				currentSpan.len++
			}
		} else {
			currentSpan.len++
			lenAtLastSpace = currentSpan.len
		}
	}
	currentSpan.len = lenAtLastSpace
	if currentSpan.len != 0 {
		cfg.highlightMultivalueValue(ret, currentSpan, section)
	} else if (*ret)[len(*ret)-1].t == highlightDelimiter {
		(*ret)[len(*ret)-1].t = highlightError
	}
}

func (cfg config) highlightValue(ret *highlightSpanArray, s stringSpan, section field) {
	switch section {
	case fieldPrivateKey:
		ret.append(s, validateHighlight(cfg.isValidKey(s), highlightPrivateKey))
	case fieldPublicKey:
		ret.append(s, validateHighlight(cfg.isValidKey(s), highlightPublicKey))
	case fieldPresharedKey:
		ret.append(s, validateHighlight(cfg.isValidKey(s), highlightPresharedKey))
	case fieldMTU:
		ret.append(s, validateHighlight(cfg.isValidMTU(s), highlightMTU))
	case fieldSaveConfig:
		ret.append(s, validateHighlight(cfg.isValidSaveConfig(s), highlightSaveConfig))
	case fieldFwMark:
		ret.append(s, validateHighlight(cfg.isValidFwmark(s), highlightFwMark))
	case fieldTable:
		ret.append(s, validateHighlight(cfg.isValidTable(s), highlightTable))
	case fieldPreUp, fieldPostUp, fieldPreDown, fieldPostDown:
		ret.append(s, validateHighlight(cfg.isValidPrePostUpDown(s), highlightCmd))
	case fieldListenPort:
		ret.append(s, validateHighlight(cfg.isValidPort(s), highlightPort))
	case fieldPersistentKeepalive:
		ret.append(s, validateHighlight(cfg.isValidPersistentKeepAlive(s), highlightKeepalive))
	case fieldEndpoint:
		if !cfg.isValidEndpoint(s) {
			ret.append(s, highlightError)
			break
		}
		colon := s.len
		for colon > 0 {
			colon--
			if cfg[s.s+colon] == ':' {
				break
			}
		}
		ret.append(stringSpan{s.s, colon}, highlightHost)
		ret.append(stringSpan{s.s + colon, 1}, highlightDelimiter)
		ret.append(stringSpan{s.s + colon + 1, s.len - colon - 1}, highlightPort)
	case fieldAddress, fieldDNS, fieldAllowedIPs:
		cfg.highlightMultivalue(ret, s, section)
	default:
		ret.append(s, highlightError)
	}
}

func highlightConfig(cfg string) []highlightSpan {
	c := config(cfg)
	ret := highlightSpanArray(make([]highlightSpan, 0, 500))
	currentSpan := stringSpan{}
	currentSection := fieldInvalid
	currentField := fieldInvalid
	const (
		OnNone = iota
		OnKey
		OnValue
		OnComment
		OnSection
	)
	state := OnNone
	lenAtLastSpace := 0
	equalsLocation := 0

	for i := 0; i <= len(cfg); i++ {
		if i == len(cfg) || cfg[i] == '\n' || (state != OnComment && cfg[i] == '#') {
			if state == OnKey {
				currentSpan.len = lenAtLastSpace
				ret.append(currentSpan, highlightError)
			} else if state == OnValue {
				if currentSpan.len != 0 {
					ret.append(stringSpan{equalsLocation, 1}, highlightDelimiter)
					currentSpan.len = lenAtLastSpace
					c.highlightValue(&ret, currentSpan, currentField)
				} else {
					ret.append(stringSpan{equalsLocation, 1}, highlightError)
				}
			} else if state == OnSection {
				currentSpan.len = lenAtLastSpace
				currentSection = c.section(currentSpan)
				ret.append(currentSpan, validateHighlight(currentSection != fieldInvalid, highlightSection))
			} else if state == OnComment {
				ret.append(currentSpan, highlightComment)
			}
			if i == len(cfg) {
				break
			}
			lenAtLastSpace = 0
			currentField = fieldInvalid
			if cfg[i] == '#' {
				currentSpan = stringSpan{i, 1}
				state = OnComment
			} else {
				currentSpan = stringSpan{i + 1, 0}
				state = OnNone
			}
		} else if state == OnComment {
			currentSpan.len++
		} else if cfg[i] == ' ' || cfg[i] == '\t' {
			if i == currentSpan.s && currentSpan.len == 0 {
				currentSpan.s++
			} else {
				currentSpan.len++
			}
		} else if cfg[i] == '=' && state == OnKey {
			currentSpan.len = lenAtLastSpace
			currentField = c.field(currentSpan)
			section := currentField.section()
			ret.append(currentSpan, validateHighlight(section != fieldInvalid && currentField != fieldInvalid && section == currentSection, highlightField))
			equalsLocation = i
			currentSpan = stringSpan{i + 1, 0}
			state = OnValue
		} else {
			if state == OnNone {
				if cfg[i] == '[' {
					state = OnSection
				} else {
					state = OnKey
				}
			}
			currentSpan.len++
			lenAtLastSpace = currentSpan.len
		}
	}
	return ret
}
