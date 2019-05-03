/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func permitTunInterface(session uintptr, baseObjects *baseObjects, ifLuid uint64) error {
	ifaceCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: (uintptr)(unsafe.Pointer(&ifLuid)),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.whitelist,
		weight:              filterWeightMax(),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&ifaceCondition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterId := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv4 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound IPv6 traffic on TUN", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func getCurrentProcessSecurityDescriptor() (*wtFwpByteBlob, error) {
	procHandle, err := windows.GetCurrentProcess()
	if err != nil {
		panic(err)
	}
	blob := &wtFwpByteBlob{}
	err = getSecurityInfo(procHandle, cSE_KERNEL_OBJECT, cDACL_SECURITY_INFORMATION, nil, nil, nil, nil, (*uintptr)(unsafe.Pointer(&blob.data)))
	if err != nil {
		return nil, wrapErr(err)
	}
	blob.size = getSecurityDescriptorLength(uintptr(unsafe.Pointer(blob.data)))
	return blob, nil
}

func getCurrentProcessAppId() (*wtFwpByteBlob, error) {
	currentFile, err := os.Executable()
	if err != nil {
		return nil, wrapErr(err)
	}

	curFilePtr, err := windows.UTF16PtrFromString(currentFile)
	if err != nil {
		return nil, wrapErr(err)
	}

	var appId *wtFwpByteBlob
	err = fwpmGetAppIdFromFileName0(curFilePtr, unsafe.Pointer(&appId))
	if err != nil {
		return nil, wrapErr(err)
	}
	return appId, nil
}

func permitWireGuardService(session uintptr, baseObjects *baseObjects) error {
	var conditions [2]wtFwpmFilterCondition0

	//
	// First condition is the exe path of the current process.
	//
	appId, err := getCurrentProcessAppId()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appId))

	conditions[0] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_BYTE_BLOB_TYPE,
			value: uintptr(unsafe.Pointer(appId)),
		},
	}

	//
	// Second condition is the SECURITY_DESCRIPTOR of the current process.
	// This prevents low privileged applications hosted in the same exe from matching this filter.
	//
	sd, err := getCurrentProcessSecurityDescriptor()
	if err != nil {
		return wrapErr(err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(sd.data)))

	conditions[1] = wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_ALE_USER_ID,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_SECURITY_DESCRIPTOR_TYPE,
			value: uintptr(unsafe.Pointer(sd)),
		},
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.whitelist,
		weight:              filterWeightMax(),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterId := uint64(0)

	//
	// #1 Permit outbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted outbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit unrestricted inbound traffic for WireGuard service (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

//
// Permit all private nets and any combination of sender/receiver.
//
func permitLanIpv4(session uintptr, baseObjects *baseObjects) error {
	privateNetworks := [4]wtFwpV4AddrAndMask{
		{0x0a000000, 0xff000000},
		{0xac100000, 0xfff00000},
		{0xc0a80000, 0xffff0000},
		{0xa9fe0000, 0xffff0000},
	}

	var conditions [8]wtFwpmFilterCondition0

	//
	// Repeating a condition type is evaluated as logical OR.
	//

	for idx, addr := range privateNetworks {
		conditions[idx].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[idx].matchType = cFWP_MATCH_EQUAL
		conditions[idx].conditionValue._type = cFWP_V4_ADDR_MASK
		conditions[idx].conditionValue.value = uintptr(unsafe.Pointer(&addr))

		conditions[4+idx].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[4+idx].matchType = cFWP_MATCH_EQUAL
		conditions[4+idx].conditionValue._type = cFWP_V4_ADDR_MASK
		conditions[4+idx].conditionValue.value = uintptr(unsafe.Pointer(&addr))
	}

	//
	// Assemble the filter.
	//
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.whitelist,
		weight:              filterWeightMax(),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterId := uint64(0)

	//
	// #1 Permit outbound LAN traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound LAN traffic (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound LAN traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound LAN traffic (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitLanIpv6(session uintptr, baseObjects *baseObjects) error {
	privateNetwork := wtFwpV6AddrAndMask{[16]uint8{0xfe, 0x80}, 10}

	var conditions [2]wtFwpmFilterCondition0

	conditions[0].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
	conditions[0].matchType = cFWP_MATCH_EQUAL
	conditions[0].conditionValue._type = cFWP_V6_ADDR_MASK
	conditions[0].conditionValue.value = uintptr(unsafe.Pointer(&privateNetwork))

	conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
	conditions[1].matchType = cFWP_MATCH_EQUAL
	conditions[1].conditionValue._type = cFWP_V6_ADDR_MASK
	conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&privateNetwork))

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.whitelist,
		weight:              filterWeightMax(),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterId := uint64(0)

	//
	// #1 Permit outbound LAN traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound LAN traffic (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound LAN traffic.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound LAN traffic (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitLoopback(session uintptr, baseObjects *baseObjects) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_INTERFACE_TYPE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT32,
			value: uintptr(cIF_TYPE_SOFTWARE_LOOPBACK),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.whitelist,
		weight:              filterWeightMax(),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	filterId := uint64(0)

	//
	// #1 Permit outbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Permit inbound IPv4 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Permit outbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit outbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Permit inbound IPv6 on loopback.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Permit inbound on loopback (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDhcpIpv4(session uintptr, baseObjects *baseObjects) error {
	//
	// #1 Outbound DHCP request on IPv4.
	//
	{
		var conditions [4]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT32
		conditions[3].conditionValue.value = uintptr(0xffffffff)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
			subLayerKey:         baseObjects.whitelist,
			weight:              filterWeightMax(),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterId := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv4.
	//
	{
		var conditions [3]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(68)

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(67)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
			subLayerKey:         baseObjects.whitelist,
			weight:              filterWeightMax(),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterId := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitDhcpIpv6(session uintptr, baseObjects *baseObjects) error {
	privateNetwork := wtFwpV6AddrAndMask{[16]uint8{0xfe, 0x80}, 10}

	//
	// #1 Outbound DHCP request on IPv6.
	//
	{
		linkLocalDhcpMulticast := wtFwpByteArray16{[16]uint8{0xFF, 0x02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x2}}
		siteLocalDhcpMulticast := wtFwpByteArray16{[16]uint8{0xFF, 0x05, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x3}}

		var conditions [6]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&linkLocalDhcpMulticast))

		// Repeat the condition type for logical OR.
		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_BYTE_ARRAY16_TYPE
		conditions[2].conditionValue.value = uintptr(unsafe.Pointer(&siteLocalDhcpMulticast))

		conditions[3].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_UINT16
		conditions[3].conditionValue.value = uintptr(547)

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[4].conditionValue.value = uintptr(unsafe.Pointer(&privateNetwork))

		conditions[5].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[5].matchType = cFWP_MATCH_EQUAL
		conditions[5].conditionValue._type = cFWP_UINT16
		conditions[5].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit outbound DHCP request (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V6,
			subLayerKey:         baseObjects.whitelist,
			weight:              filterWeightMax(),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterId := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound DHCP response on IPv6.
	//
	{
		var conditions [5]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_UDP)

		conditions[1].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[1].conditionValue.value = uintptr(unsafe.Pointer(&privateNetwork))

		conditions[2].fieldKey = cFWPM_CONDITION_IP_REMOTE_PORT
		conditions[2].matchType = cFWP_MATCH_EQUAL
		conditions[2].conditionValue._type = cFWP_UINT16
		conditions[2].conditionValue.value = uintptr(547)

		conditions[3].fieldKey = cFWPM_CONDITION_IP_LOCAL_ADDRESS
		conditions[3].matchType = cFWP_MATCH_EQUAL
		conditions[3].conditionValue._type = cFWP_V6_ADDR_MASK
		conditions[3].conditionValue.value = uintptr(unsafe.Pointer(&privateNetwork))

		conditions[4].fieldKey = cFWPM_CONDITION_IP_LOCAL_PORT
		conditions[4].matchType = cFWP_MATCH_EQUAL
		conditions[4].conditionValue._type = cFWP_UINT16
		conditions[4].conditionValue.value = uintptr(546)

		displayData, err := createWtFwpmDisplayData0("Permit inbound DHCP response (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
			subLayerKey:         baseObjects.whitelist,
			weight:              filterWeightMax(),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions)),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}

		filterId := uint64(0)

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

func permitNdp(session uintptr, baseObjects *baseObjects) error {

	/* TODO: Objective is:
	 *  icmpv6 133: must be outgoing, dst must be FF02::2/128, hop limit must be 255
	 *  icmpv6 134: must be incoming, src must be FE80::/10, hop limit must be 255
	 *  icmpv6 135: either incoming or outgoing, hop limit must be 255
	 *  icmpv6 136: either incoming or outgoing, hop limit must be 255
	 *  icmpv6 137: must be incoming, src must be FE80::/10, hop limit must be 255
	 */

	//
	// #1 out: icmp icmp_type=133 dhost=linkLocal|siteLocal ttl=255
	//
	{
		var conditions [5]wtFwpmFilterCondition0

		conditions[0].fieldKey = cFWPM_CONDITION_IP_PROTOCOL
		conditions[0].matchType = cFWP_MATCH_EQUAL
		conditions[0].conditionValue._type = cFWP_UINT8
		conditions[0].conditionValue.value = uintptr(cIPPROTO_ICMP)

		conditions[1].fieldKey = cFWPM_CONDITION_ICMP_TYPE // TODO: This could be wrong, it might be _CODE
		conditions[1].matchType = cFWP_MATCH_EQUAL
		conditions[1].conditionValue._type = cFWP_UINT16
		conditions[1].conditionValue.value = uintptr(133)
	}

	return nil
}

// Block all traffic except what is explicitly permitted by other rules.
func blockAllUnmatched(session uintptr, baseObjects *baseObjects) error {
	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.whitelist,
		weight:      filterWeightMin(),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterId := uint64(0)

	//
	// #1 Block outbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block inbound traffic on IPv4.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block outbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block inbound traffic on IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block all inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}

// Block all DNS except what is matched by a permissive rule.
func blockDnsUnmatched(session uintptr, baseObjects *baseObjects) error {
	condition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT16,
			value: uintptr(53),
		},
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.blacklist,
		weight:              filterWeightMin(),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&condition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterId := uint64(0)

	//
	// #1 Block IPv4 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Block IPv4 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv4)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #3 Block IPv6 outbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS outbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #4 Block IPv6 inbound DNS.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Block DNS inbound (IPv6)", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterId)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}
