/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"testing"
	"unsafe"
)

const (
	mibIPInterfaceRowSize                                       = 168
	mibIPInterfaceRowInterfaceLUIDOffset                        = 8
	mibIPInterfaceRowInterfaceIndexOffset                       = 16
	mibIPInterfaceRowMaxReassemblySizeOffset                    = 20
	mibIPInterfaceRowInterfaceIdentifierOffset                  = 24
	mibIPInterfaceRowMinRouterAdvertisementIntervalOffset       = 32
	mibIPInterfaceRowMaxRouterAdvertisementIntervalOffset       = 36
	mibIPInterfaceRowAdvertisingEnabledOffset                   = 40
	mibIPInterfaceRowForwardingEnabledOffset                    = 41
	mibIPInterfaceRowWeakHostSendOffset                         = 42
	mibIPInterfaceRowWeakHostReceiveOffset                      = 43
	mibIPInterfaceRowUseAutomaticMetricOffset                   = 44
	mibIPInterfaceRowUseNeighborUnreachabilityDetectionOffset   = 45
	mibIPInterfaceRowManagedAddressConfigurationSupportedOffset = 46
	mibIPInterfaceRowOtherStatefulConfigurationSupportedOffset  = 47
	mibIPInterfaceRowAdvertiseDefaultRouteOffset                = 48
	mibIPInterfaceRowRouterDiscoveryBehaviorOffset              = 52
	mibIPInterfaceRowDadTransmitsOffset                         = 56
	mibIPInterfaceRowBaseReachableTimeOffset                    = 60
	mibIPInterfaceRowRetransmitTimeOffset                       = 64
	mibIPInterfaceRowPathMTUDiscoveryTimeoutOffset              = 68
	mibIPInterfaceRowLinkLocalAddressBehaviorOffset             = 72
	mibIPInterfaceRowLinkLocalAddressTimeoutOffset              = 76
	mibIPInterfaceRowZoneIndicesOffset                          = 80
	mibIPInterfaceRowSitePrefixLengthOffset                     = 144
	mibIPInterfaceRowMetricOffset                               = 148
	mibIPInterfaceRowNLMTUOffset                                = 152
	mibIPInterfaceRowConnectedOffset                            = 156
	mibIPInterfaceRowSupportsWakeUpPatternsOffset               = 157
	mibIPInterfaceRowSupportsNeighborDiscoveryOffset            = 158
	mibIPInterfaceRowSupportsRouterDiscoveryOffset              = 159
	mibIPInterfaceRowReachableTimeOffset                        = 160
	mibIPInterfaceRowTransmitOffloadOffset                      = 164
	mibIPInterfaceRowReceiveOffloadOffset                       = 165
	mibIPInterfaceRowDisableDefaultRoutesOffset                 = 166

	mibIPInterfaceTableSize        = 176
	mibIPInterfaceTableTableOffset = 8

	mibIfRow2Size                              = 1352
	mibIfRow2InterfaceIndexOffset              = 8
	mibIfRow2InterfaceGUIDOffset               = 12
	mibIfRow2AliasOffset                       = 28
	mibIfRow2DescriptionOffset                 = 542
	mibIfRow2PhysicalAddressLengthOffset       = 1056
	mibIfRow2PhysicalAddressOffset             = 1060
	mibIfRow2PermanentPhysicalAddressOffset    = 1092
	mibIfRow2MTUOffset                         = 1124
	mibIfRow2TypeOffset                        = 1128
	mibIfRow2TunnelTypeOffset                  = 1132
	mibIfRow2MediaTypeOffset                   = 1136
	mibIfRow2PhysicalMediumTypeOffset          = 1140
	mibIfRow2AccessTypeOffset                  = 1144
	mibIfRow2DirectionTypeOffset               = 1148
	mibIfRow2InterfaceAndOperStatusFlagsOffset = 1152
	mibIfRow2OperStatusOffset                  = 1156
	mibIfRow2AdminStatusOffset                 = 1160
	mibIfRow2MediaConnectStateOffset           = 1164
	mibIfRow2NetworkGUIDOffset                 = 1168
	mibIfRow2ConnectionTypeOffset              = 1184
	mibIfRow2TransmitLinkSpeedOffset           = 1192
	mibIfRow2ReceiveLinkSpeedOffset            = 1200
	mibIfRow2InOctetsOffset                    = 1208
	mibIfRow2InUcastPktsOffset                 = 1216
	mibIfRow2InNUcastPktsOffset                = 1224
	mibIfRow2InDiscardsOffset                  = 1232
	mibIfRow2InErrorsOffset                    = 1240
	mibIfRow2InUnknownProtosOffset             = 1248
	mibIfRow2InUcastOctetsOffset               = 1256
	mibIfRow2InMulticastOctetsOffset           = 1264
	mibIfRow2InBroadcastOctetsOffset           = 1272
	mibIfRow2OutOctetsOffset                   = 1280
	mibIfRow2OutUcastPktsOffset                = 1288
	mibIfRow2OutNUcastPktsOffset               = 1296
	mibIfRow2OutDiscardsOffset                 = 1304
	mibIfRow2OutErrorsOffset                   = 1312
	mibIfRow2OutUcastOctetsOffset              = 1320
	mibIfRow2OutMulticastOctetsOffset          = 1328
	mibIfRow2OutBroadcastOctetsOffset          = 1336
	mibIfRow2OutQLenOffset                     = 1344

	mibIfTable2Size        = 1360
	mibIfTable2TableOffset = 8

	rawSockaddrInetSize       = 28
	rawSockaddrInetDataOffset = 2

	mibUnicastIPAddressRowSize                     = 80
	mibUnicastIPAddressRowInterfaceLUIDOffset      = 32
	mibUnicastIPAddressRowInterfaceIndexOffset     = 40
	mibUnicastIPAddressRowPrefixOriginOffset       = 44
	mibUnicastIPAddressRowSuffixOriginOffset       = 48
	mibUnicastIPAddressRowValidLifetimeOffset      = 52
	mibUnicastIPAddressRowPreferredLifetimeOffset  = 56
	mibUnicastIPAddressRowOnLinkPrefixLengthOffset = 60
	mibUnicastIPAddressRowSkipAsSourceOffset       = 61
	mibUnicastIPAddressRowDadStateOffset           = 64
	mibUnicastIPAddressRowScopeIDOffset            = 68
	mibUnicastIPAddressRowCreationTimeStampOffset  = 72

	mibUnicastIPAddressTableSize        = 88
	mibUnicastIPAddressTableTableOffset = 8

	mibAnycastIPAddressRowSize                 = 48
	mibAnycastIPAddressRowInterfaceLUIDOffset  = 32
	mibAnycastIPAddressRowInterfaceIndexOffset = 40
	mibAnycastIPAddressRowScopeIDOffset        = 44

	mibAnycastIPAddressTableSize        = 56
	mibAnycastIPAddressTableTableOffset = 8

	ipAddressPrefixSize               = 32
	ipAddressPrefixPrefixLengthOffset = 28

	mibIPforwardRow2Size                       = 104
	mibIPforwardRow2InterfaceIndexOffset       = 8
	mibIPforwardRow2DestinationPrefixOffset    = 12
	mibIPforwardRow2NextHopOffset              = 44
	mibIPforwardRow2SitePrefixLengthOffset     = 72
	mibIPforwardRow2ValidLifetimeOffset        = 76
	mibIPforwardRow2PreferredLifetimeOffset    = 80
	mibIPforwardRow2MetricOffset               = 84
	mibIPforwardRow2ProtocolOffset             = 88
	mibIPforwardRow2LoopbackOffset             = 92
	mibIPforwardRow2AutoconfigureAddressOffset = 93
	mibIPforwardRow2PublishOffset              = 94
	mibIPforwardRow2ImmortalOffset             = 95
	mibIPforwardRow2AgeOffset                  = 96
	mibIPforwardRow2OriginOffset               = 100

	mibIPforwardTable2Size        = 112
	mibIPforwardTable2TableOffset = 8
)

func TestIPAdapterWINSServerAddress(t *testing.T) {
	s := IPAdapterWINSServerAddress{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualIPAdapterWINSServerAddressSize = unsafe.Sizeof(s)

	if actualIPAdapterWINSServerAddressSize != ipAdapterWINSServerAddressSize {
		t.Errorf("Size of IPAdapterWINSServerAddress is %d, although %d is expected.", actualIPAdapterWINSServerAddressSize, ipAdapterWINSServerAddressSize)
	}

	offset := uintptr(unsafe.Pointer(&s.Next)) - sp
	if offset != ipAdapterWINSServerAddressNextOffset {
		t.Errorf("IPAdapterWINSServerAddress.Next offset is %d although %d is expected", offset, ipAdapterWINSServerAddressNextOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Address)) - sp
	if offset != ipAdapterWINSServerAddressAddressOffset {
		t.Errorf("IPAdapterWINSServerAddress.Address offset is %d although %d is expected", offset, ipAdapterWINSServerAddressAddressOffset)
	}
}

func TestIPAdapterGatewayAddress(t *testing.T) {
	s := IPAdapterGatewayAddress{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualIPAdapterGatewayAddressSize = unsafe.Sizeof(s)

	if actualIPAdapterGatewayAddressSize != ipAdapterGatewayAddressSize {
		t.Errorf("Size of IPAdapterGatewayAddress is %d, although %d is expected.", actualIPAdapterGatewayAddressSize, ipAdapterGatewayAddressSize)
	}

	offset := uintptr(unsafe.Pointer(&s.Next)) - sp
	if offset != ipAdapterGatewayAddressNextOffset {
		t.Errorf("IPAdapterGatewayAddress.Next offset is %d although %d is expected", offset, ipAdapterGatewayAddressNextOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Address)) - sp
	if offset != ipAdapterGatewayAddressAddressOffset {
		t.Errorf("IPAdapterGatewayAddress.Address offset is %d although %d is expected", offset, ipAdapterGatewayAddressAddressOffset)
	}
}

func TestIPAdapterDNSSuffix(t *testing.T) {
	s := IPAdapterDNSSuffix{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualIPAdapterDNSSuffixSize = unsafe.Sizeof(s)

	if actualIPAdapterDNSSuffixSize != ipAdapterDNSSuffixSize {
		t.Errorf("Size of IPAdapterDNSSuffix is %d, although %d is expected.", actualIPAdapterDNSSuffixSize, ipAdapterDNSSuffixSize)
	}

	offset := uintptr(unsafe.Pointer(&s.str)) - sp
	if offset != ipAdapterDNSSuffixStringOffset {
		t.Errorf("IPAdapterDNSSuffix.str offset is %d although %d is expected", offset, ipAdapterDNSSuffixStringOffset)
	}
}

func TestInAdapterAddresses(t *testing.T) {
	s := IPAdapterAddresses{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualIn6AddrSize = unsafe.Sizeof(s)

	if actualIn6AddrSize != ipAdapterAddressesSize {
		t.Errorf("Size of IPAdapterAddresses is %d, although %d is expected.", actualIn6AddrSize, ipAdapterAddressesSize)
	}

	offset := uintptr(unsafe.Pointer(&s.IfIndex)) - sp
	if offset != ipAdapterAddressesIfIndexOffset {
		t.Errorf("IPAdapterAddresses.IfIndex offset is %d although %d is expected", offset, ipAdapterAddressesIfIndexOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Next)) - sp
	if offset != ipAdapterAddressesNextOffset {
		t.Errorf("IPAdapterAddresses.Next offset is %d although %d is expected", offset, ipAdapterAddressesNextOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.adapterName)) - sp
	if offset != ipAdapterAddressesAdapterNameOffset {
		t.Errorf("IPAdapterAddresses.adapterName offset is %d although %d is expected", offset, ipAdapterAddressesAdapterNameOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstUnicastAddress)) - sp
	if offset != ipAdapterAddressesFirstUnicastAddressOffset {
		t.Errorf("IPAdapterAddresses.FirstUnicastAddress offset is %d although %d is expected", offset, ipAdapterAddressesFirstUnicastAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstAnycastAddress)) - sp
	if offset != ipAdapterAddressesFirstAnycastAddressOffset {
		t.Errorf("IPAdapterAddresses.FirstAnycastAddress offset is %d although %d is expected", offset, ipAdapterAddressesFirstAnycastAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstMulticastAddress)) - sp
	if offset != ipAdapterAddressesFirstMulticastAddressOffset {
		t.Errorf("IPAdapterAddresses.FirstMulticastAddress offset is %d although %d is expected", offset, ipAdapterAddressesFirstMulticastAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstDNSServerAddress)) - sp
	if offset != ipAdapterAddressesFirstDNSServerAddressOffset {
		t.Errorf("IPAdapterAddresses.FirstDNSServerAddress offset is %d although %d is expected", offset, ipAdapterAddressesFirstDNSServerAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.dnsSuffix)) - sp
	if offset != ipAdapterAddressesDNSSuffixOffset {
		t.Errorf("IPAdapterAddresses.DNSSuffix offset is %d although %d is expected", offset, ipAdapterAddressesDNSSuffixOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.description)) - sp
	if offset != ipAdapterAddressesDescriptionOffset {
		t.Errorf("IPAdapterAddresses.Description offset is %d although %d is expected", offset, ipAdapterAddressesDescriptionOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.friendlyName)) - sp
	if offset != ipAdapterAddressesFriendlyNameOffset {
		t.Errorf("IPAdapterAddresses.FriendlyName offset is %d although %d is expected", offset, ipAdapterAddressesFriendlyNameOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.physicalAddress)) - sp
	if offset != ipAdapterAddressesPhysicalAddressOffset {
		t.Errorf("IPAdapterAddresses.PhysicalAddress offset is %d although %d is expected", offset, ipAdapterAddressesPhysicalAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.physicalAddressLength)) - sp
	if offset != ipAdapterAddressesPhysicalAddressLengthOffset {
		t.Errorf("IPAdapterAddresses.PhysicalAddressLength offset is %d although %d is expected", offset, ipAdapterAddressesPhysicalAddressLengthOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Flags)) - sp
	if offset != ipAdapterAddressesFlagsOffset {
		t.Errorf("IPAdapterAddresses.Flags offset is %d although %d is expected", offset, ipAdapterAddressesFlagsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.MTU)) - sp
	if offset != ipAdapterAddressesMTUOffset {
		t.Errorf("IPAdapterAddresses.MTU offset is %d although %d is expected", offset, ipAdapterAddressesMTUOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.IfType)) - sp
	if offset != ipAdapterAddressesIfTypeOffset {
		t.Errorf("IPAdapterAddresses.IfType offset is %d although %d is expected", offset, ipAdapterAddressesIfTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OperStatus)) - sp
	if offset != ipAdapterAddressesOperStatusOffset {
		t.Errorf("IPAdapterAddresses.OperStatus offset is %d although %d is expected", offset, ipAdapterAddressesOperStatusOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.IPv6IfIndex)) - sp
	if offset != ipAdapterAddressesIPv6IfIndexOffset {
		t.Errorf("IPAdapterAddresses.IPv6IfIndex offset is %d although %d is expected", offset, ipAdapterAddressesIPv6IfIndexOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ZoneIndices)) - sp
	if offset != ipAdapterAddressesZoneIndicesOffset {
		t.Errorf("IPAdapterAddresses.ZoneIndices offset is %d although %d is expected", offset, ipAdapterAddressesZoneIndicesOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstPrefix)) - sp
	if offset != ipAdapterAddressesFirstPrefixOffset {
		t.Errorf("IPAdapterAddresses.FirstPrefix offset is %d although %d is expected", offset, ipAdapterAddressesFirstPrefixOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.TransmitLinkSpeed)) - sp
	if offset != ipAdapterAddressesTransmitLinkSpeedOffset {
		t.Errorf("IPAdapterAddresses.TransmitLinkSpeed offset is %d although %d is expected", offset, ipAdapterAddressesTransmitLinkSpeedOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ReceiveLinkSpeed)) - sp
	if offset != ipAdapterAddressesReceiveLinkSpeedOffset {
		t.Errorf("IPAdapterAddresses.ReceiveLinkSpeed offset is %d although %d is expected", offset, ipAdapterAddressesReceiveLinkSpeedOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstWINSServerAddress)) - sp
	if offset != ipAdapterAddressesFirstWINSServerAddressOffset {
		t.Errorf("IPAdapterAddresses.FirstWINSServerAddress offset is %d although %d is expected", offset, ipAdapterAddressesFirstWINSServerAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstGatewayAddress)) - sp
	if offset != ipAdapterAddressesFirstGatewayAddressOffset {
		t.Errorf("IPAdapterAddresses.FirstGatewayAddress offset is %d although %d is expected", offset, ipAdapterAddressesFirstGatewayAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Ipv4Metric)) - sp
	if offset != ipAdapterAddressesIPv4MetricOffset {
		t.Errorf("IPAdapterAddresses.IPv4Metric offset is %d although %d is expected", offset, ipAdapterAddressesIPv4MetricOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Ipv6Metric)) - sp
	if offset != ipAdapterAddressesIPv6MetricOffset {
		t.Errorf("IPAdapterAddresses.IPv6Metric offset is %d although %d is expected", offset, ipAdapterAddressesIPv6MetricOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.LUID)) - sp
	if offset != ipAdapterAddressesLUIDOffset {
		t.Errorf("IPAdapterAddresses.LUID offset is %d although %d is expected", offset, ipAdapterAddressesLUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DHCPv4Server)) - sp
	if offset != ipAdapterAddressesDHCPv4ServerOffset {
		t.Errorf("IPAdapterAddresses.DHCPv4Server offset is %d although %d is expected", offset, ipAdapterAddressesDHCPv4ServerOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.CompartmentID)) - sp
	if offset != ipAdapterAddressesCompartmentIDOffset {
		t.Errorf("IPAdapterAddresses.CompartmentID offset is %d although %d is expected", offset, ipAdapterAddressesCompartmentIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.NetworkGUID)) - sp
	if offset != ipAdapterAddressesNetworkGUIDOffset {
		t.Errorf("IPAdapterAddresses.NetworkGUID offset is %d although %d is expected", offset, ipAdapterAddressesNetworkGUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ConnectionType)) - sp
	if offset != ipAdapterAddressesConnectionTypeOffset {
		t.Errorf("IPAdapterAddresses.ConnectionType offset is %d although %d is expected", offset, ipAdapterAddressesConnectionTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.TunnelType)) - sp
	if offset != ipAdapterAddressesTunnelTypeOffset {
		t.Errorf("IPAdapterAddresses.TunnelType offset is %d although %d is expected", offset, ipAdapterAddressesTunnelTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DHCPv6Server)) - sp
	if offset != ipAdapterAddressesDHCPv6ServerOffset {
		t.Errorf("IPAdapterAddresses.DHCPv6Server offset is %d although %d is expected", offset, ipAdapterAddressesDHCPv6ServerOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.dhcpv6ClientDUID)) - sp
	if offset != ipAdapterAddressesDHCPv6ClientDUIDOffset {
		t.Errorf("IPAdapterAddresses.DHCPv6ClientDUID offset is %d although %d is expected", offset, ipAdapterAddressesDHCPv6ClientDUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.dhcpv6ClientDUIDLength)) - sp
	if offset != ipAdapterAddressesDHCPv6ClientDUIDLengthOffset {
		t.Errorf("IPAdapterAddresses.DHCPv6ClientDUIDLength offset is %d although %d is expected", offset, ipAdapterAddressesDHCPv6ClientDUIDLengthOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DHCPv6IAID)) - sp
	if offset != ipAdapterAddressesDHCPv6IAIDOffset {
		t.Errorf("IPAdapterAddresses.DHCPv6IAID offset is %d although %d is expected", offset, ipAdapterAddressesDHCPv6IAIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.FirstDNSSuffix)) - sp
	if offset != ipAdapterAddressesFirstDNSSuffixOffset {
		t.Errorf("IPAdapterAddresses.FirstDNSSuffix offset is %d although %d is expected", offset, ipAdapterAddressesFirstDNSSuffixOffset)
	}
}

func TestMibIPInterfaceRow(t *testing.T) {
	s := MibIPInterfaceRow{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualTestMibIPInterfaceRowSize = unsafe.Sizeof(s)

	if actualTestMibIPInterfaceRowSize != mibIPInterfaceRowSize {
		t.Errorf("Size of MibIPInterfaceRow is %d, although %d is expected.", actualTestMibIPInterfaceRowSize, mibIPInterfaceRowSize)
	}

	offset := uintptr(unsafe.Pointer(&s.InterfaceLUID)) - sp
	if offset != mibIPInterfaceRowInterfaceLUIDOffset {
		t.Errorf("MibIPInterfaceRow.InterfaceLUID offset is %d although %d is expected", offset, mibIPInterfaceRowInterfaceLUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InterfaceIndex)) - sp
	if offset != mibIPInterfaceRowInterfaceIndexOffset {
		t.Errorf("MibIPInterfaceRow.InterfaceIndex offset is %d although %d is expected", offset, mibIPInterfaceRowInterfaceIndexOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.MaxReassemblySize)) - sp
	if offset != mibIPInterfaceRowMaxReassemblySizeOffset {
		t.Errorf("mibIPInterfaceRow.MaxReassemblySize offset is %d although %d is expected", offset, mibIPInterfaceRowMaxReassemblySizeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InterfaceIdentifier)) - sp
	if offset != mibIPInterfaceRowInterfaceIdentifierOffset {
		t.Errorf("MibIPInterfaceRow.InterfaceIdentifier offset is %d although %d is expected", offset, mibIPInterfaceRowInterfaceIdentifierOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.MinRouterAdvertisementInterval)) - sp
	if offset != mibIPInterfaceRowMinRouterAdvertisementIntervalOffset {
		t.Errorf("MibIPInterfaceRow.MinRouterAdvertisementInterval offset is %d although %d is expected", offset, mibIPInterfaceRowMinRouterAdvertisementIntervalOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.MaxRouterAdvertisementInterval)) - sp
	if offset != mibIPInterfaceRowMaxRouterAdvertisementIntervalOffset {
		t.Errorf("MibIPInterfaceRow.MaxRouterAdvertisementInterval offset is %d although %d is expected", offset, mibIPInterfaceRowMaxRouterAdvertisementIntervalOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.AdvertisingEnabled)) - sp
	if offset != mibIPInterfaceRowAdvertisingEnabledOffset {
		t.Errorf("MibIPInterfaceRow.AdvertisingEnabled offset is %d although %d is expected", offset, mibIPInterfaceRowAdvertisingEnabledOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ForwardingEnabled)) - sp
	if offset != mibIPInterfaceRowForwardingEnabledOffset {
		t.Errorf("MibIPInterfaceRow.ForwardingEnabled offset is %d although %d is expected", offset, mibIPInterfaceRowForwardingEnabledOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.WeakHostSend)) - sp
	if offset != mibIPInterfaceRowWeakHostSendOffset {
		t.Errorf("MibIPInterfaceRow.WeakHostSend offset is %d although %d is expected", offset, mibIPInterfaceRowWeakHostSendOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.WeakHostReceive)) - sp
	if offset != mibIPInterfaceRowWeakHostReceiveOffset {
		t.Errorf("MibIPInterfaceRow.WeakHostReceive offset is %d although %d is expected", offset, mibIPInterfaceRowWeakHostReceiveOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.UseAutomaticMetric)) - sp
	if offset != mibIPInterfaceRowUseAutomaticMetricOffset {
		t.Errorf("MibIPInterfaceRow.UseAutomaticMetric offset is %d although %d is expected", offset, mibIPInterfaceRowUseAutomaticMetricOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.UseNeighborUnreachabilityDetection)) - sp
	if offset != mibIPInterfaceRowUseNeighborUnreachabilityDetectionOffset {
		t.Errorf("MibIPInterfaceRow.UseNeighborUnreachabilityDetection offset is %d although %d is expected", offset, mibIPInterfaceRowUseNeighborUnreachabilityDetectionOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ManagedAddressConfigurationSupported)) - sp
	if offset != mibIPInterfaceRowManagedAddressConfigurationSupportedOffset {
		t.Errorf("MibIPInterfaceRow.ManagedAddressConfigurationSupported offset is %d although %d is expected", offset, mibIPInterfaceRowManagedAddressConfigurationSupportedOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OtherStatefulConfigurationSupported)) - sp
	if offset != mibIPInterfaceRowOtherStatefulConfigurationSupportedOffset {
		t.Errorf("MibIPInterfaceRow.OtherStatefulConfigurationSupported offset is %d although %d is expected", offset, mibIPInterfaceRowOtherStatefulConfigurationSupportedOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.AdvertiseDefaultRoute)) - sp
	if offset != mibIPInterfaceRowAdvertiseDefaultRouteOffset {
		t.Errorf("MibIPInterfaceRow.AdvertiseDefaultRoute offset is %d although %d is expected", offset, mibIPInterfaceRowAdvertiseDefaultRouteOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.RouterDiscoveryBehavior)) - sp
	if offset != mibIPInterfaceRowRouterDiscoveryBehaviorOffset {
		t.Errorf("MibIPInterfaceRow.RouterDiscoveryBehavior offset is %d although %d is expected", offset, mibIPInterfaceRowRouterDiscoveryBehaviorOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DadTransmits)) - sp
	if offset != mibIPInterfaceRowDadTransmitsOffset {
		t.Errorf("MibIPInterfaceRow.DadTransmits offset is %d although %d is expected", offset, mibIPInterfaceRowDadTransmitsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.BaseReachableTime)) - sp
	if offset != mibIPInterfaceRowBaseReachableTimeOffset {
		t.Errorf("MibIPInterfaceRow.BaseReachableTime offset is %d although %d is expected", offset, mibIPInterfaceRowBaseReachableTimeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.RetransmitTime)) - sp
	if offset != mibIPInterfaceRowRetransmitTimeOffset {
		t.Errorf("MibIPInterfaceRow.RetransmitTime offset is %d although %d is expected", offset, mibIPInterfaceRowRetransmitTimeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.PathMTUDiscoveryTimeout)) - sp
	if offset != mibIPInterfaceRowPathMTUDiscoveryTimeoutOffset {
		t.Errorf("MibIPInterfaceRow.PathMTUDiscoveryTimeout offset is %d although %d is expected", offset, mibIPInterfaceRowPathMTUDiscoveryTimeoutOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.LinkLocalAddressBehavior)) - sp
	if offset != mibIPInterfaceRowLinkLocalAddressBehaviorOffset {
		t.Errorf("MibIPInterfaceRow.LinkLocalAddressBehavior offset is %d although %d is expected", offset, mibIPInterfaceRowLinkLocalAddressBehaviorOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.LinkLocalAddressTimeout)) - sp
	if offset != mibIPInterfaceRowLinkLocalAddressTimeoutOffset {
		t.Errorf("MibIPInterfaceRow.LinkLocalAddressTimeout offset is %d although %d is expected", offset, mibIPInterfaceRowLinkLocalAddressTimeoutOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ZoneIndices)) - sp
	if offset != mibIPInterfaceRowZoneIndicesOffset {
		t.Errorf("MibIPInterfaceRow.ZoneIndices offset is %d although %d is expected", offset, mibIPInterfaceRowZoneIndicesOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.SitePrefixLength)) - sp
	if offset != mibIPInterfaceRowSitePrefixLengthOffset {
		t.Errorf("MibIPInterfaceRow.SitePrefixLength offset is %d although %d is expected", offset, mibIPInterfaceRowSitePrefixLengthOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Metric)) - sp
	if offset != mibIPInterfaceRowMetricOffset {
		t.Errorf("MibIPInterfaceRow.Metric offset is %d although %d is expected", offset, mibIPInterfaceRowMetricOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.NLMTU)) - sp
	if offset != mibIPInterfaceRowNLMTUOffset {
		t.Errorf("MibIPInterfaceRow.NLMTU offset is %d although %d is expected", offset, mibIPInterfaceRowNLMTUOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Connected)) - sp
	if offset != mibIPInterfaceRowConnectedOffset {
		t.Errorf("MibIPInterfaceRow.Connected offset is %d although %d is expected", offset, mibIPInterfaceRowConnectedOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.SupportsWakeUpPatterns)) - sp
	if offset != mibIPInterfaceRowSupportsWakeUpPatternsOffset {
		t.Errorf("MibIPInterfaceRow.SupportsWakeUpPatterns offset is %d although %d is expected", offset, mibIPInterfaceRowSupportsWakeUpPatternsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.SupportsNeighborDiscovery)) - sp
	if offset != mibIPInterfaceRowSupportsNeighborDiscoveryOffset {
		t.Errorf("MibIPInterfaceRow.SupportsNeighborDiscovery offset is %d although %d is expected", offset, mibIPInterfaceRowSupportsNeighborDiscoveryOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.SupportsRouterDiscovery)) - sp
	if offset != mibIPInterfaceRowSupportsRouterDiscoveryOffset {
		t.Errorf("MibIPInterfaceRow.SupportsRouterDiscovery offset is %d although %d is expected", offset, mibIPInterfaceRowSupportsRouterDiscoveryOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ReachableTime)) - sp
	if offset != mibIPInterfaceRowReachableTimeOffset {
		t.Errorf("MibIPInterfaceRow.ReachableTime offset is %d although %d is expected", offset, mibIPInterfaceRowReachableTimeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.TransmitOffload)) - sp
	if offset != mibIPInterfaceRowTransmitOffloadOffset {
		t.Errorf("MibIPInterfaceRow.TransmitOffload offset is %d although %d is expected", offset, mibIPInterfaceRowTransmitOffloadOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ReceiveOffload)) - sp
	if offset != mibIPInterfaceRowReceiveOffloadOffset {
		t.Errorf("MibIPInterfaceRow.ReceiveOffload offset is %d although %d is expected", offset, mibIPInterfaceRowReceiveOffloadOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DisableDefaultRoutes)) - sp
	if offset != mibIPInterfaceRowDisableDefaultRoutesOffset {
		t.Errorf("MibIPInterfaceRow.DisableDefaultRoutes offset is %d although %d is expected", offset, mibIPInterfaceRowDisableDefaultRoutesOffset)
	}
}

func TestMibIPInterfaceTable(t *testing.T) {
	s := mibIPInterfaceTable{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualmibIPInterfaceTableSize = unsafe.Sizeof(s)

	if actualmibIPInterfaceTableSize != mibIPInterfaceTableSize {
		t.Errorf("Size of mibIPInterfaceTable is %d, although %d is expected.", actualmibIPInterfaceTableSize, mibIPInterfaceTableSize)
	}

	offset := uintptr(unsafe.Pointer(&s.table)) - sp
	if offset != mibIPInterfaceTableTableOffset {
		t.Errorf("mibIPInterfaceTable.table offset is %d although %d is expected", offset, mibIPInterfaceTableTableOffset)
	}
}

func TestMibIfRow2(t *testing.T) {
	s := MibIfRow2{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualMibIfRow2Size = unsafe.Sizeof(s)

	if actualMibIfRow2Size != mibIfRow2Size {
		t.Errorf("Size of MibIfRow2 is %d, although %d is expected.", actualMibIfRow2Size, mibIfRow2Size)
	}

	offset := uintptr(unsafe.Pointer(&s.InterfaceIndex)) - sp
	if offset != mibIfRow2InterfaceIndexOffset {
		t.Errorf("MibIfRow2.InterfaceIndex offset is %d although %d is expected", offset, mibIfRow2InterfaceIndexOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InterfaceGUID)) - sp
	if offset != mibIfRow2InterfaceGUIDOffset {
		t.Errorf("MibIfRow2.InterfaceGUID offset is %d although %d is expected", offset, mibIfRow2InterfaceGUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.alias)) - sp
	if offset != mibIfRow2AliasOffset {
		t.Errorf("MibIfRow2.alias offset is %d although %d is expected", offset, mibIfRow2AliasOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.description)) - sp
	if offset != mibIfRow2DescriptionOffset {
		t.Errorf("MibIfRow2.description offset is %d although %d is expected", offset, mibIfRow2DescriptionOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.physicalAddressLength)) - sp
	if offset != mibIfRow2PhysicalAddressLengthOffset {
		t.Errorf("MibIfRow2.physicalAddressLength offset is %d although %d is expected", offset, mibIfRow2PhysicalAddressLengthOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.physicalAddress)) - sp
	if offset != mibIfRow2PhysicalAddressOffset {
		t.Errorf("MibIfRow2.physicalAddress offset is %d although %d is expected", offset, mibIfRow2PhysicalAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.permanentPhysicalAddress)) - sp
	if offset != mibIfRow2PermanentPhysicalAddressOffset {
		t.Errorf("MibIfRow2.permanentPhysicalAddress offset is %d although %d is expected", offset, mibIfRow2PermanentPhysicalAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.MTU)) - sp
	if offset != mibIfRow2MTUOffset {
		t.Errorf("MibIfRow2.MTU offset is %d although %d is expected", offset, mibIfRow2MTUOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Type)) - sp
	if offset != mibIfRow2TypeOffset {
		t.Errorf("MibIfRow2.Type offset is %d although %d is expected", offset, mibIfRow2TypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.TunnelType)) - sp
	if offset != mibIfRow2TunnelTypeOffset {
		t.Errorf("MibIfRow2.TunnelType offset is %d although %d is expected", offset, mibIfRow2TunnelTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.MediaType)) - sp
	if offset != mibIfRow2MediaTypeOffset {
		t.Errorf("MibIfRow2.MediaType offset is %d although %d is expected", offset, mibIfRow2MediaTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.PhysicalMediumType)) - sp
	if offset != mibIfRow2PhysicalMediumTypeOffset {
		t.Errorf("MibIfRow2.PhysicalMediumType offset is %d although %d is expected", offset, mibIfRow2PhysicalMediumTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.AccessType)) - sp
	if offset != mibIfRow2AccessTypeOffset {
		t.Errorf("MibIfRow2.AccessType offset is %d although %d is expected", offset, mibIfRow2AccessTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DirectionType)) - sp
	if offset != mibIfRow2DirectionTypeOffset {
		t.Errorf("MibIfRow2.DirectionType offset is %d although %d is expected", offset, mibIfRow2DirectionTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InterfaceAndOperStatusFlags)) - sp
	if offset != mibIfRow2InterfaceAndOperStatusFlagsOffset {
		t.Errorf("MibIfRow2.InterfaceAndOperStatusFlags offset is %d although %d is expected", offset, mibIfRow2InterfaceAndOperStatusFlagsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OperStatus)) - sp
	if offset != mibIfRow2OperStatusOffset {
		t.Errorf("MibIfRow2.OperStatus offset is %d although %d is expected", offset, mibIfRow2OperStatusOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.AdminStatus)) - sp
	if offset != mibIfRow2AdminStatusOffset {
		t.Errorf("MibIfRow2.AdminStatus offset is %d although %d is expected", offset, mibIfRow2AdminStatusOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.MediaConnectState)) - sp
	if offset != mibIfRow2MediaConnectStateOffset {
		t.Errorf("MibIfRow2.MediaConnectState offset is %d although %d is expected", offset, mibIfRow2MediaConnectStateOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.NetworkGUID)) - sp
	if offset != mibIfRow2NetworkGUIDOffset {
		t.Errorf("MibIfRow2.NetworkGUID offset is %d although %d is expected", offset, mibIfRow2NetworkGUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ConnectionType)) - sp
	if offset != mibIfRow2ConnectionTypeOffset {
		t.Errorf("MibIfRow2.ConnectionType offset is %d although %d is expected", offset, mibIfRow2ConnectionTypeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.TransmitLinkSpeed)) - sp
	if offset != mibIfRow2TransmitLinkSpeedOffset {
		t.Errorf("MibIfRow2.TransmitLinkSpeed offset is %d although %d is expected", offset, mibIfRow2TransmitLinkSpeedOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ReceiveLinkSpeed)) - sp
	if offset != mibIfRow2ReceiveLinkSpeedOffset {
		t.Errorf("MibIfRow2.ReceiveLinkSpeed offset is %d although %d is expected", offset, mibIfRow2ReceiveLinkSpeedOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InOctets)) - sp
	if offset != mibIfRow2InOctetsOffset {
		t.Errorf("MibIfRow2.InOctets offset is %d although %d is expected", offset, mibIfRow2InOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InUcastPkts)) - sp
	if offset != mibIfRow2InUcastPktsOffset {
		t.Errorf("MibIfRow2.InUcastPkts offset is %d although %d is expected", offset, mibIfRow2InUcastPktsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InNUcastPkts)) - sp
	if offset != mibIfRow2InNUcastPktsOffset {
		t.Errorf("MibIfRow2.InNUcastPkts offset is %d although %d is expected", offset, mibIfRow2InNUcastPktsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InDiscards)) - sp
	if offset != mibIfRow2InDiscardsOffset {
		t.Errorf("MibIfRow2.InDiscards offset is %d although %d is expected", offset, mibIfRow2InDiscardsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InErrors)) - sp
	if offset != mibIfRow2InErrorsOffset {
		t.Errorf("MibIfRow2.InErrors offset is %d although %d is expected", offset, mibIfRow2InErrorsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InUnknownProtos)) - sp
	if offset != mibIfRow2InUnknownProtosOffset {
		t.Errorf("MibIfRow2.InUnknownProtos offset is %d although %d is expected", offset, mibIfRow2InUnknownProtosOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InUcastOctets)) - sp
	if offset != mibIfRow2InUcastOctetsOffset {
		t.Errorf("MibIfRow2.InUcastOctets offset is %d although %d is expected", offset, mibIfRow2InUcastOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InMulticastOctets)) - sp
	if offset != mibIfRow2InMulticastOctetsOffset {
		t.Errorf("MibIfRow2.InMulticastOctets offset is %d although %d is expected", offset, mibIfRow2InMulticastOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InBroadcastOctets)) - sp
	if offset != mibIfRow2InBroadcastOctetsOffset {
		t.Errorf("MibIfRow2.InBroadcastOctets offset is %d although %d is expected", offset, mibIfRow2InBroadcastOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutOctets)) - sp
	if offset != mibIfRow2OutOctetsOffset {
		t.Errorf("MibIfRow2.OutOctets offset is %d although %d is expected", offset, mibIfRow2OutOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutUcastPkts)) - sp
	if offset != mibIfRow2OutUcastPktsOffset {
		t.Errorf("MibIfRow2.OutUcastPkts offset is %d although %d is expected", offset, mibIfRow2OutUcastPktsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutNUcastPkts)) - sp
	if offset != mibIfRow2OutNUcastPktsOffset {
		t.Errorf("MibIfRow2.OutNUcastPkts offset is %d although %d is expected", offset, mibIfRow2OutNUcastPktsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutDiscards)) - sp
	if offset != mibIfRow2OutDiscardsOffset {
		t.Errorf("MibIfRow2.OutDiscards offset is %d although %d is expected", offset, mibIfRow2OutDiscardsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutErrors)) - sp
	if offset != mibIfRow2OutErrorsOffset {
		t.Errorf("MibIfRow2.OutErrors offset is %d although %d is expected", offset, mibIfRow2OutErrorsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutUcastOctets)) - sp
	if offset != mibIfRow2OutUcastOctetsOffset {
		t.Errorf("MibIfRow2.OutUcastOctets offset is %d although %d is expected", offset, mibIfRow2OutUcastOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutMulticastOctets)) - sp
	if offset != mibIfRow2OutMulticastOctetsOffset {
		t.Errorf("MibIfRow2.OutMulticastOctets offset is %d although %d is expected", offset, mibIfRow2OutMulticastOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutBroadcastOctets)) - sp
	if offset != mibIfRow2OutBroadcastOctetsOffset {
		t.Errorf("MibIfRow2.OutBroadcastOctets offset is %d although %d is expected", offset, mibIfRow2OutBroadcastOctetsOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OutQLen)) - sp
	if offset != mibIfRow2OutQLenOffset {
		t.Errorf("MibIfRow2.OutQLen offset is %d although %d is expected", offset, mibIfRow2OutQLenOffset)
	}
}

func TestMibIfTable2(t *testing.T) {
	s := mibIfTable2{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualmibIfTable2Size = unsafe.Sizeof(s)

	if actualmibIfTable2Size != mibIfTable2Size {
		t.Errorf("Size of mibIfTable2 is %d, although %d is expected.", actualmibIfTable2Size, mibIfTable2Size)
	}

	offset := uintptr(unsafe.Pointer(&s.table)) - sp
	if offset != mibIfTable2TableOffset {
		t.Errorf("mibIfTable2.table offset is %d although %d is expected", offset, mibIfTable2TableOffset)
	}
}

func TestRawSockaddrInet(t *testing.T) {
	s := RawSockaddrInet{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualRawSockaddrInetSize = unsafe.Sizeof(s)

	if actualRawSockaddrInetSize != rawSockaddrInetSize {
		t.Errorf("Size of RawSockaddrInet is %d, although %d is expected.", actualRawSockaddrInetSize, rawSockaddrInetSize)
	}

	offset := uintptr(unsafe.Pointer(&s.data)) - sp
	if offset != rawSockaddrInetDataOffset {
		t.Errorf("RawSockaddrInet.data offset is %d although %d is expected", offset, rawSockaddrInetDataOffset)
	}
}

func TestMibUnicastIPAddressRow(t *testing.T) {
	s := MibUnicastIPAddressRow{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualMibUnicastIPAddressRowSize = unsafe.Sizeof(s)

	if actualMibUnicastIPAddressRowSize != mibUnicastIPAddressRowSize {
		t.Errorf("Size of MibUnicastIPAddressRow is %d, although %d is expected.", actualMibUnicastIPAddressRowSize, mibUnicastIPAddressRowSize)
	}

	offset := uintptr(unsafe.Pointer(&s.InterfaceLUID)) - sp
	if offset != mibUnicastIPAddressRowInterfaceLUIDOffset {
		t.Errorf("MibUnicastIPAddressRow.InterfaceLUID offset is %d although %d is expected", offset, mibUnicastIPAddressRowInterfaceLUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InterfaceIndex)) - sp
	if offset != mibUnicastIPAddressRowInterfaceIndexOffset {
		t.Errorf("MibUnicastIPAddressRow.InterfaceIndex offset is %d although %d is expected", offset, mibUnicastIPAddressRowInterfaceIndexOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.PrefixOrigin)) - sp
	if offset != mibUnicastIPAddressRowPrefixOriginOffset {
		t.Errorf("MibUnicastIPAddressRow.PrefixOrigin offset is %d although %d is expected", offset, mibUnicastIPAddressRowPrefixOriginOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.SuffixOrigin)) - sp
	if offset != mibUnicastIPAddressRowSuffixOriginOffset {
		t.Errorf("MibUnicastIPAddressRow.SuffixOrigin offset is %d although %d is expected", offset, mibUnicastIPAddressRowSuffixOriginOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ValidLifetime)) - sp
	if offset != mibUnicastIPAddressRowValidLifetimeOffset {
		t.Errorf("MibUnicastIPAddressRow.ValidLifetime offset is %d although %d is expected", offset, mibUnicastIPAddressRowValidLifetimeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.PreferredLifetime)) - sp
	if offset != mibUnicastIPAddressRowPreferredLifetimeOffset {
		t.Errorf("MibUnicastIPAddressRow.PreferredLifetime offset is %d although %d is expected", offset, mibUnicastIPAddressRowPreferredLifetimeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.OnLinkPrefixLength)) - sp
	if offset != mibUnicastIPAddressRowOnLinkPrefixLengthOffset {
		t.Errorf("MibUnicastIPAddressRow.OnLinkPrefixLength offset is %d although %d is expected", offset, mibUnicastIPAddressRowOnLinkPrefixLengthOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.SkipAsSource)) - sp
	if offset != mibUnicastIPAddressRowSkipAsSourceOffset {
		t.Errorf("MibUnicastIPAddressRow.SkipAsSource offset is %d although %d is expected", offset, mibUnicastIPAddressRowSkipAsSourceOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DadState)) - sp
	if offset != mibUnicastIPAddressRowDadStateOffset {
		t.Errorf("MibUnicastIPAddressRow.DadState offset is %d although %d is expected", offset, mibUnicastIPAddressRowDadStateOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ScopeID)) - sp
	if offset != mibUnicastIPAddressRowScopeIDOffset {
		t.Errorf("MibUnicastIPAddressRow.ScopeID offset is %d although %d is expected", offset, mibUnicastIPAddressRowScopeIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.CreationTimeStamp)) - sp
	if offset != mibUnicastIPAddressRowCreationTimeStampOffset {
		t.Errorf("MibUnicastIPAddressRow.CreationTimeStamp offset is %d although %d is expected", offset, mibUnicastIPAddressRowCreationTimeStampOffset)
	}
}

func TestMibUnicastIPAddressTable(t *testing.T) {
	s := mibUnicastIPAddressTable{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualmibUnicastIPAddressTableSize = unsafe.Sizeof(s)

	if actualmibUnicastIPAddressTableSize != mibUnicastIPAddressTableSize {
		t.Errorf("Size of mibUnicastIPAddressTable is %d, although %d is expected.", actualmibUnicastIPAddressTableSize, mibUnicastIPAddressTableSize)
	}

	offset := uintptr(unsafe.Pointer(&s.table)) - sp
	if offset != mibUnicastIPAddressTableTableOffset {
		t.Errorf("mibUnicastIPAddressTable.table offset is %d although %d is expected", offset, mibUnicastIPAddressTableTableOffset)
	}
}

func TestMibAnycastIPAddressRow(t *testing.T) {
	s := MibAnycastIPAddressRow{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualMibAnycastIPAddressRowSize = unsafe.Sizeof(s)

	if actualMibAnycastIPAddressRowSize != mibAnycastIPAddressRowSize {
		t.Errorf("Size of MibAnycastIPAddressRow is %d, although %d is expected.", actualMibAnycastIPAddressRowSize, mibAnycastIPAddressRowSize)
	}

	offset := uintptr(unsafe.Pointer(&s.InterfaceLUID)) - sp
	if offset != mibAnycastIPAddressRowInterfaceLUIDOffset {
		t.Errorf("MibAnycastIPAddressRow.InterfaceLUID offset is %d although %d is expected", offset, mibAnycastIPAddressRowInterfaceLUIDOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.InterfaceIndex)) - sp
	if offset != mibAnycastIPAddressRowInterfaceIndexOffset {
		t.Errorf("MibAnycastIPAddressRow.InterfaceIndex offset is %d although %d is expected", offset, mibAnycastIPAddressRowInterfaceIndexOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ScopeID)) - sp
	if offset != mibAnycastIPAddressRowScopeIDOffset {
		t.Errorf("MibAnycastIPAddressRow.ScopeID offset is %d although %d is expected", offset, mibAnycastIPAddressRowScopeIDOffset)
	}
}

func TestMibAnycastIPAddressTable(t *testing.T) {
	s := mibAnycastIPAddressTable{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualmibAnycastIPAddressTableSize = unsafe.Sizeof(s)

	if actualmibAnycastIPAddressTableSize != mibAnycastIPAddressTableSize {
		t.Errorf("Size of mibAnycastIPAddressTable is %d, although %d is expected.", actualmibAnycastIPAddressTableSize, mibAnycastIPAddressTableSize)
	}

	offset := uintptr(unsafe.Pointer(&s.table)) - sp
	if offset != mibAnycastIPAddressTableTableOffset {
		t.Errorf("mibAnycastIPAddressTable.table offset is %d although %d is expected", offset, mibAnycastIPAddressTableTableOffset)
	}
}

func TestIPAddressPrefix(t *testing.T) {
	s := IPAddressPrefix{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualIPAddressPrefixSize = unsafe.Sizeof(s)

	if actualIPAddressPrefixSize != ipAddressPrefixSize {
		t.Errorf("Size of IPAddressPrefix is %d, although %d is expected.", actualIPAddressPrefixSize, ipAddressPrefixSize)
	}

	offset := uintptr(unsafe.Pointer(&s.PrefixLength)) - sp
	if offset != ipAddressPrefixPrefixLengthOffset {
		t.Errorf("IPAddressPrefix.PrefixLength offset is %d although %d is expected", offset, ipAddressPrefixPrefixLengthOffset)

	}
}

func TestMibIPforwardRow2(t *testing.T) {
	s := MibIPforwardRow2{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualMibIPforwardRow2Size = unsafe.Sizeof(s)

	if actualMibIPforwardRow2Size != mibIPforwardRow2Size {
		t.Errorf("Size of MibIPforwardRow2 is %d, although %d is expected.", actualMibIPforwardRow2Size, mibIPforwardRow2Size)
	}

	offset := uintptr(unsafe.Pointer(&s.InterfaceIndex)) - sp
	if offset != mibIPforwardRow2InterfaceIndexOffset {
		t.Errorf("MibIPforwardRow2.InterfaceIndex offset is %d although %d is expected", offset, mibIPforwardRow2InterfaceIndexOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.DestinationPrefix)) - sp
	if offset != mibIPforwardRow2DestinationPrefixOffset {
		t.Errorf("MibIPforwardRow2.DestinationPrefix offset is %d although %d is expected", offset, mibIPforwardRow2DestinationPrefixOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.NextHop)) - sp
	if offset != mibIPforwardRow2NextHopOffset {
		t.Errorf("MibIPforwardRow2.NextHop offset is %d although %d is expected", offset, mibIPforwardRow2NextHopOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.SitePrefixLength)) - sp
	if offset != mibIPforwardRow2SitePrefixLengthOffset {
		t.Errorf("MibIPforwardRow2.SitePrefixLength offset is %d although %d is expected", offset, mibIPforwardRow2SitePrefixLengthOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.ValidLifetime)) - sp
	if offset != mibIPforwardRow2ValidLifetimeOffset {
		t.Errorf("MibIPforwardRow2.ValidLifetime offset is %d although %d is expected", offset, mibIPforwardRow2ValidLifetimeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.PreferredLifetime)) - sp
	if offset != mibIPforwardRow2PreferredLifetimeOffset {
		t.Errorf("MibIPforwardRow2.PreferredLifetime offset is %d although %d is expected", offset, mibIPforwardRow2PreferredLifetimeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Metric)) - sp
	if offset != mibIPforwardRow2MetricOffset {
		t.Errorf("MibIPforwardRow2.Metric offset is %d although %d is expected", offset, mibIPforwardRow2MetricOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Protocol)) - sp
	if offset != mibIPforwardRow2ProtocolOffset {
		t.Errorf("MibIPforwardRow2.Protocol offset is %d although %d is expected", offset, mibIPforwardRow2ProtocolOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Loopback)) - sp
	if offset != mibIPforwardRow2LoopbackOffset {
		t.Errorf("MibIPforwardRow2.Loopback offset is %d although %d is expected", offset, mibIPforwardRow2LoopbackOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.AutoconfigureAddress)) - sp
	if offset != mibIPforwardRow2AutoconfigureAddressOffset {
		t.Errorf("MibIPforwardRow2.AutoconfigureAddress offset is %d although %d is expected", offset, mibIPforwardRow2AutoconfigureAddressOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Publish)) - sp
	if offset != mibIPforwardRow2PublishOffset {
		t.Errorf("MibIPforwardRow2.Publish offset is %d although %d is expected", offset, mibIPforwardRow2PublishOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Immortal)) - sp
	if offset != mibIPforwardRow2ImmortalOffset {
		t.Errorf("MibIPforwardRow2.Immortal offset is %d although %d is expected", offset, mibIPforwardRow2ImmortalOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Age)) - sp
	if offset != mibIPforwardRow2AgeOffset {
		t.Errorf("MibIPforwardRow2.Age offset is %d although %d is expected", offset, mibIPforwardRow2AgeOffset)
	}

	offset = uintptr(unsafe.Pointer(&s.Origin)) - sp
	if offset != mibIPforwardRow2OriginOffset {
		t.Errorf("MibIPforwardRow2.Origin offset is %d although %d is expected", offset, mibIPforwardRow2OriginOffset)
	}
}

func TestMibIPforwardTable2(t *testing.T) {
	s := mibIPforwardTable2{}
	sp := uintptr(unsafe.Pointer(&s))
	const actualmibIPforwardTable2Size = unsafe.Sizeof(s)

	if actualmibIPforwardTable2Size != mibIPforwardTable2Size {
		t.Errorf("Size of mibIPforwardTable2 is %d, although %d is expected.", actualmibIPforwardTable2Size, mibIPforwardTable2Size)
	}

	offset := uintptr(unsafe.Pointer(&s.table)) - sp
	if offset != mibIPforwardTable2TableOffset {
		t.Errorf("mibIPforwardTable2.table offset is %d although %d is expected", offset, mibIPforwardTable2TableOffset)
	}
}
