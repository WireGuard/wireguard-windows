/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// LUID represents a network interface.
type LUID uint64

// IPInterface method retrieves IP information for the specified interface on the local computer.
func (luid LUID) IPInterface(family AddressFamily) (*MibIPInterfaceRow, error) {
	row := &MibIPInterfaceRow{}
	row.Init()
	row.InterfaceLUID = luid
	row.Family = family
	err := row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

// Interface method retrieves information for the specified adapter on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getifentry2
func (luid LUID) Interface() (*MibIfRow2, error) {
	row := &MibIfRow2{}
	row.InterfaceLUID = luid
	err := row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GUID method converts a locally unique identifier (LUID) for a network interface to a globally unique identifier (GUID) for the interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceluidtoguid
func (luid LUID) GUID() (*windows.GUID, error) {
	guid := &windows.GUID{}
	err := convertInterfaceLUIDToGUID(&luid, guid)
	if err != nil {
		return nil, err
	}
	return guid, nil
}

// LUIDFromGUID function converts a globally unique identifier (GUID) for a network interface to the locally unique identifier (LUID) for the interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceguidtoluid
func LUIDFromGUID(guid *windows.GUID) (LUID, error) {
	var luid LUID
	err := convertInterfaceGUIDToLUID(guid, &luid)
	if err != nil {
		return 0, err
	}
	return luid, nil
}

// IPAddress method returns MibUnicastIPAddressRow struct that matches to provided 'ip' argument. Corresponds to GetUnicastIpAddressEntry
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getunicastipaddressentry)
func (luid LUID) IPAddress(ip net.IP) (*MibUnicastIPAddressRow, error) {
	row := &MibUnicastIPAddressRow{InterfaceLUID: luid}

	err := row.Address.SetIP(ip, 0)
	if err != nil {
		return nil, err
	}

	err = row.get()
	if err != nil {
		return nil, err
	}

	return row, nil
}

// AddIPAddress method adds new unicast IP address to the interface. Corresponds to CreateUnicastIpAddressEntry function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
func (luid LUID) AddIPAddress(address net.IPNet) error {
	row := &MibUnicastIPAddressRow{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.Address.SetIP(address.IP, 0)
	if err != nil {
		return err
	}
	ones, _ := address.Mask.Size()
	row.OnLinkPrefixLength = uint8(ones)
	return row.Create()
}

// AddIPAddresses method adds multiple new unicast IP addresses to the interface. Corresponds to CreateUnicastIpAddressEntry function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
func (luid LUID) AddIPAddresses(addresses []net.IPNet) error {
	for i := range addresses {
		err := luid.AddIPAddress(addresses[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// SetIPAddresses method sets new unicast IP addresses to the interface.
func (luid LUID) SetIPAddresses(addresses []net.IPNet) error {
	err := luid.FlushIPAddresses(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
	return luid.AddIPAddresses(addresses)
}

// SetIPAddressesForFamily method sets new unicast IP addresses for a specific family to the interface.
func (luid LUID) SetIPAddressesForFamily(family AddressFamily, addresses []net.IPNet) error {
	err := luid.FlushIPAddresses(family)
	if err != nil {
		return err
	}
	for i := range addresses {
		asV4 := addresses[i].IP.To4()
		if asV4 == nil && family == windows.AF_INET {
			continue
		} else if asV4 != nil && family == windows.AF_INET6 {
			continue
		}
		err := luid.AddIPAddress(addresses[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteIPAddress method deletes interface's unicast IP address. Corresponds to DeleteUnicastIpAddressEntry function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteunicastipaddressentry).
func (luid LUID) DeleteIPAddress(address net.IPNet) error {
	row := &MibUnicastIPAddressRow{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.Address.SetIP(address.IP, 0)
	if err != nil {
		return err
	}
	// Note: OnLinkPrefixLength member is ignored by DeleteUnicastIpAddressEntry().
	ones, _ := address.Mask.Size()
	row.OnLinkPrefixLength = uint8(ones)
	return row.Delete()
}

// FlushIPAddresses method deletes all interface's unicast IP addresses.
func (luid LUID) FlushIPAddresses(family AddressFamily) error {
	var tab *mibUnicastIPAddressTable
	err := getUnicastIPAddressTable(family, &tab)
	if err != nil {
		return err
	}
	t := tab.get()
	for i := range t {
		if t[i].InterfaceLUID == luid {
			t[i].Delete()
		}
	}
	tab.free()
	return nil
}

// Route method returns route determined with the input arguments. Corresponds to GetIpForwardEntry2 function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipforwardentry2).
// NOTE: If the corresponding route isn't found, the method will return error.
func (luid LUID) Route(destination net.IPNet, nextHop net.IP) (*MibIPforwardRow2, error) {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.DestinationPrefix.SetIPNet(destination)
	if err != nil {
		return nil, err
	}
	err = row.NextHop.SetIP(nextHop, 0)
	if err != nil {
		return nil, err
	}

	err = row.get()
	if err != nil {
		return nil, err
	}
	return row, nil
}

// AddRoute method adds a route to the interface. Corresponds to CreateIpForwardEntry2 function, with added splitDefault feature.
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createipforwardentry2)
func (luid LUID) AddRoute(destination net.IPNet, nextHop net.IP, metric uint32) error {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.DestinationPrefix.SetIPNet(destination)
	if err != nil {
		return err
	}
	err = row.NextHop.SetIP(nextHop, 0)
	if err != nil {
		return err
	}
	row.Metric = metric
	return row.Create()
}

// AddRoutes method adds multiple routes to the interface.
func (luid LUID) AddRoutes(routesData []*RouteData) error {
	for _, rd := range routesData {
		err := luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetRoutes method sets (flush than add) multiple routes to the interface.
func (luid LUID) SetRoutes(routesData []*RouteData) error {
	err := luid.FlushRoutes(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
	return luid.AddRoutes(routesData)
}

// SetRoutesForFamily method sets (flush than add) multiple routes for a specific family to the interface.
func (luid LUID) SetRoutesForFamily(family AddressFamily, routesData []*RouteData) error {
	err := luid.FlushRoutes(family)
	if err != nil {
		return err
	}
	for _, rd := range routesData {
		asV4 := rd.Destination.IP.To4()
		if asV4 == nil && family == windows.AF_INET {
			continue
		} else if asV4 != nil && family == windows.AF_INET6 {
			continue
		}
		err := luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteRoute method deletes a route that matches the criteria. Corresponds to DeleteIpForwardEntry2 function
// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteipforwardentry2).
func (luid LUID) DeleteRoute(destination net.IPNet, nextHop net.IP) error {
	row := &MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	err := row.DestinationPrefix.SetIPNet(destination)
	if err != nil {
		return err
	}
	err = row.NextHop.SetIP(nextHop, 0)
	if err != nil {
		return err
	}
	err = row.get()
	if err != nil {
		return err
	}
	return row.Delete()
}

// FlushRoutes method deletes all interface's routes.
// It continues on failures, and returns the last error afterwards.
func (luid LUID) FlushRoutes(family AddressFamily) error {
	var tab *mibIPforwardTable2
	err := getIPForwardTable2(family, &tab)
	if err != nil {
		return err
	}
	t := tab.get()
	for i := range t {
		if t[i].InterfaceLUID == luid {
			err2 := t[i].Delete()
			if err2 != nil {
				err = err2
			}
		}
	}
	tab.free()
	return err
}

// DNS method returns all DNS server addresses associated with the adapter.
func (luid LUID) DNS() ([]net.IP, error) {
	addresses, err := GetAdaptersAddresses(windows.AF_UNSPEC, GAAFlagDefault)
	if err != nil {
		return nil, err
	}
	r := make([]net.IP, 0, len(addresses))
	for _, addr := range addresses {
		if addr.LUID == luid {
			for dns := addr.FirstDNSServerAddress; dns != nil; dns = dns.Next {
				if ip := dns.Address.IP(); ip != nil {
					r = append(r, ip)
				} else {
					return nil, windows.ERROR_INVALID_PARAMETER
				}
			}
		}
	}
	return r, nil
}

const (
	netshCmdTemplateFlush4 = "interface ipv4 set dnsservers name=%d source=static address=none validate=no register=both"
	netshCmdTemplateFlush6 = "interface ipv6 set dnsservers name=%d source=static address=none validate=no register=both"
	netshCmdTemplateAdd4   = "interface ipv4 add dnsservers name=%d address=%s validate=no"
	netshCmdTemplateAdd6   = "interface ipv6 add dnsservers name=%d address=%s validate=no"
)

// FlushDNS method clears all DNS servers associated with the adapter.
func (luid LUID) FlushDNS() error {
	cmds := make([]string, 0, 2)
	ipif4, err := luid.IPInterface(windows.AF_INET)
	if err == nil {
		cmds = append(cmds, fmt.Sprintf(netshCmdTemplateFlush4, ipif4.InterfaceIndex))
	}
	ipif6, err := luid.IPInterface(windows.AF_INET6)
	if err == nil {
		cmds = append(cmds, fmt.Sprintf(netshCmdTemplateFlush6, ipif6.InterfaceIndex))
	}

	if len(cmds) == 0 {
		return nil
	}
	return runNetsh(cmds)
}

// AddDNS method associates additional DNS servers with the adapter.
func (luid LUID) AddDNS(dnses []net.IP) error {
	var ipif4, ipif6 *MibIPInterfaceRow
	var err error
	cmds := make([]string, 0, len(dnses))
	for i := 0; i < len(dnses); i++ {
		if v4 := dnses[i].To4(); v4 != nil {
			if ipif4 == nil {
				ipif4, err = luid.IPInterface(windows.AF_INET)
				if err != nil {
					return err
				}
			}
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd4, ipif4.InterfaceIndex, v4.String()))
		} else if v6 := dnses[i].To16(); v6 != nil {
			if ipif6 == nil {
				ipif6, err = luid.IPInterface(windows.AF_INET6)
				if err != nil {
					return err
				}
			}
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd6, ipif6.InterfaceIndex, v6.String()))
		}
	}

	if len(cmds) == 0 {
		return nil
	}
	return runNetsh(cmds)
}

// SetDNS method clears previous and associates new DNS servers with the adapter.
func (luid LUID) SetDNS(dnses []net.IP) error {
	cmds := make([]string, 0, 2+len(dnses))
	ipif4, err := luid.IPInterface(windows.AF_INET)
	if err == nil {
		cmds = append(cmds, fmt.Sprintf(netshCmdTemplateFlush4, ipif4.InterfaceIndex))
	}
	ipif6, err := luid.IPInterface(windows.AF_INET6)
	if err == nil {
		cmds = append(cmds, fmt.Sprintf(netshCmdTemplateFlush6, ipif6.InterfaceIndex))
	}
	for i := 0; i < len(dnses); i++ {
		if v4 := dnses[i].To4(); v4 != nil {
			if ipif4 == nil {
				return windows.ERROR_NOT_SUPPORTED
			}
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd4, ipif4.InterfaceIndex, v4.String()))
		} else if v6 := dnses[i].To16(); v6 != nil {
			if ipif6 == nil {
				return windows.ERROR_NOT_SUPPORTED
			}
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd6, ipif6.InterfaceIndex, v6.String()))
		}
	}

	if len(cmds) == 0 {
		return nil
	}
	return runNetsh(cmds)
}

// SetDNSForFamily method clears previous and associates new DNS servers with the adapter for a specific family.
func (luid LUID) SetDNSForFamily(family AddressFamily, dnses []net.IP) error {
	var templateFlush string
	if family == windows.AF_INET {
		templateFlush = netshCmdTemplateFlush4
	} else if family == windows.AF_INET6 {
		templateFlush = netshCmdTemplateFlush6
	}

	cmds := make([]string, 0, 1+len(dnses))
	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	cmds = append(cmds, fmt.Sprintf(templateFlush, ipif.InterfaceIndex))
	for i := 0; i < len(dnses); i++ {
		if v4 := dnses[i].To4(); v4 != nil && family == windows.AF_INET {
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd4, ipif.InterfaceIndex, v4.String()))
		} else if v6 := dnses[i].To16(); v4 == nil && v6 != nil && family == windows.AF_INET6 {
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd6, ipif.InterfaceIndex, v6.String()))
		}
	}
	return runNetsh(cmds)
}
