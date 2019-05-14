/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const (
	PRODUCT_UNDEFINED                           = 0x00000000
	PRODUCT_ULTIMATE                            = 0x00000001
	PRODUCT_HOME_BASIC                          = 0x00000002
	PRODUCT_HOME_PREMIUM                        = 0x00000003
	PRODUCT_ENTERPRISE                          = 0x00000004
	PRODUCT_HOME_BASIC_N                        = 0x00000005
	PRODUCT_BUSINESS                            = 0x00000006
	PRODUCT_STANDARD_SERVER                     = 0x00000007
	PRODUCT_DATACENTER_SERVER                   = 0x00000008
	PRODUCT_SMALLBUSINESS_SERVER                = 0x00000009
	PRODUCT_ENTERPRISE_SERVER                   = 0x0000000A
	PRODUCT_STARTER                             = 0x0000000B
	PRODUCT_DATACENTER_SERVER_CORE              = 0x0000000C
	PRODUCT_STANDARD_SERVER_CORE                = 0x0000000D
	PRODUCT_ENTERPRISE_SERVER_CORE              = 0x0000000E
	PRODUCT_ENTERPRISE_SERVER_IA64              = 0x0000000F
	PRODUCT_BUSINESS_N                          = 0x00000010
	PRODUCT_WEB_SERVER                          = 0x00000011
	PRODUCT_CLUSTER_SERVER                      = 0x00000012
	PRODUCT_HOME_SERVER                         = 0x00000013
	PRODUCT_STORAGE_EXPRESS_SERVER              = 0x00000014
	PRODUCT_STORAGE_STANDARD_SERVER             = 0x00000015
	PRODUCT_STORAGE_WORKGROUP_SERVER            = 0x00000016
	PRODUCT_STORAGE_ENTERPRISE_SERVER           = 0x00000017
	PRODUCT_SERVER_FOR_SMALLBUSINESS            = 0x00000018
	PRODUCT_SMALLBUSINESS_SERVER_PREMIUM        = 0x00000019
	PRODUCT_HOME_PREMIUM_N                      = 0x0000001A
	PRODUCT_ENTERPRISE_N                        = 0x0000001B
	PRODUCT_ULTIMATE_N                          = 0x0000001C
	PRODUCT_WEB_SERVER_CORE                     = 0x0000001D
	PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT    = 0x0000001E
	PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY      = 0x0000001F
	PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING     = 0x00000020
	PRODUCT_SERVER_FOUNDATION                   = 0x00000021
	PRODUCT_HOME_PREMIUM_SERVER                 = 0x00000022
	PRODUCT_SERVER_FOR_SMALLBUSINESS_V          = 0x00000023
	PRODUCT_STANDARD_SERVER_V                   = 0x00000024
	PRODUCT_DATACENTER_SERVER_V                 = 0x00000025
	PRODUCT_ENTERPRISE_SERVER_V                 = 0x00000026
	PRODUCT_DATACENTER_SERVER_CORE_V            = 0x00000027
	PRODUCT_STANDARD_SERVER_CORE_V              = 0x00000028
	PRODUCT_ENTERPRISE_SERVER_CORE_V            = 0x00000029
	PRODUCT_HYPERV                              = 0x0000002A
	PRODUCT_STORAGE_EXPRESS_SERVER_CORE         = 0x0000002B
	PRODUCT_STORAGE_STANDARD_SERVER_CORE        = 0x0000002C
	PRODUCT_STORAGE_WORKGROUP_SERVER_CORE       = 0x0000002D
	PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE      = 0x0000002E
	PRODUCT_STARTER_N                           = 0x0000002F
	PRODUCT_PROFESSIONAL                        = 0x00000030
	PRODUCT_PROFESSIONAL_N                      = 0x00000031
	PRODUCT_SB_SOLUTION_SERVER                  = 0x00000032
	PRODUCT_SERVER_FOR_SB_SOLUTIONS             = 0x00000033
	PRODUCT_STANDARD_SERVER_SOLUTIONS           = 0x00000034
	PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE      = 0x00000035
	PRODUCT_SB_SOLUTION_SERVER_EM               = 0x00000036
	PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM          = 0x00000037
	PRODUCT_SOLUTION_EMBEDDEDSERVER             = 0x00000038
	PRODUCT_SOLUTION_EMBEDDEDSERVER_CORE        = 0x00000039
	PRODUCT_PROFESSIONAL_EMBEDDED               = 0x0000003A
	PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT       = 0x0000003B
	PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL       = 0x0000003C
	PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC    = 0x0000003D
	PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC    = 0x0000003E
	PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE   = 0x0000003F
	PRODUCT_CLUSTER_SERVER_V                    = 0x00000040
	PRODUCT_EMBEDDED                            = 0x00000041
	PRODUCT_STARTER_E                           = 0x00000042
	PRODUCT_HOME_BASIC_E                        = 0x00000043
	PRODUCT_HOME_PREMIUM_E                      = 0x00000044
	PRODUCT_PROFESSIONAL_E                      = 0x00000045
	PRODUCT_ENTERPRISE_E                        = 0x00000046
	PRODUCT_ULTIMATE_E                          = 0x00000047
	PRODUCT_ENTERPRISE_EVALUATION               = 0x00000048
	PRODUCT_MULTIPOINT_STANDARD_SERVER          = 0x0000004C
	PRODUCT_MULTIPOINT_PREMIUM_SERVER           = 0x0000004D
	PRODUCT_STANDARD_EVALUATION_SERVER          = 0x0000004F
	PRODUCT_DATACENTER_EVALUATION_SERVER        = 0x00000050
	PRODUCT_ENTERPRISE_N_EVALUATION             = 0x00000054
	PRODUCT_EMBEDDED_AUTOMOTIVE                 = 0x00000055
	PRODUCT_EMBEDDED_INDUSTRY_A                 = 0x00000056
	PRODUCT_THINPC                              = 0x00000057
	PRODUCT_EMBEDDED_A                          = 0x00000058
	PRODUCT_EMBEDDED_INDUSTRY                   = 0x00000059
	PRODUCT_EMBEDDED_E                          = 0x0000005A
	PRODUCT_EMBEDDED_INDUSTRY_E                 = 0x0000005B
	PRODUCT_EMBEDDED_INDUSTRY_A_E               = 0x0000005C
	PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER = 0x0000005F
	PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER  = 0x00000060
	PRODUCT_CORE_ARM                            = 0x00000061
	PRODUCT_CORE_N                              = 0x00000062
	PRODUCT_CORE_COUNTRYSPECIFIC                = 0x00000063
	PRODUCT_CORE_SINGLELANGUAGE                 = 0x00000064
	PRODUCT_CORE                                = 0x00000065
	PRODUCT_PROFESSIONAL_WMC                    = 0x00000067
	PRODUCT_EMBEDDED_INDUSTRY_EVAL              = 0x00000069
	PRODUCT_EMBEDDED_INDUSTRY_E_EVAL            = 0x0000006A
	PRODUCT_EMBEDDED_EVAL                       = 0x0000006B
	PRODUCT_EMBEDDED_E_EVAL                     = 0x0000006C
	PRODUCT_NANO_SERVER                         = 0x0000006D
	PRODUCT_CLOUD_STORAGE_SERVER                = 0x0000006E
	PRODUCT_CORE_CONNECTED                      = 0x0000006F
	PRODUCT_PROFESSIONAL_STUDENT                = 0x00000070
	PRODUCT_CORE_CONNECTED_N                    = 0x00000071
	PRODUCT_PROFESSIONAL_STUDENT_N              = 0x00000072
	PRODUCT_CORE_CONNECTED_SINGLELANGUAGE       = 0x00000073
	PRODUCT_CORE_CONNECTED_COUNTRYSPECIFIC      = 0x00000074
	PRODUCT_CONNECTED_CAR                       = 0x00000075
	PRODUCT_INDUSTRY_HANDHELD                   = 0x00000076
	PRODUCT_PPI_PRO                             = 0x00000077
	PRODUCT_ARM64_SERVER                        = 0x00000078
	PRODUCT_EDUCATION                           = 0x00000079
	PRODUCT_EDUCATION_N                         = 0x0000007A
	PRODUCT_IOTUAP                              = 0x0000007B
	PRODUCT_CLOUD_HOST_INFRASTRUCTURE_SERVER    = 0x0000007C
	PRODUCT_ENTERPRISE_S                        = 0x0000007D
	PRODUCT_ENTERPRISE_S_N                      = 0x0000007E
	PRODUCT_PROFESSIONAL_S                      = 0x0000007F
	PRODUCT_PROFESSIONAL_S_N                    = 0x00000080
	PRODUCT_ENTERPRISE_S_EVALUATION             = 0x00000081
	PRODUCT_ENTERPRISE_S_N_EVALUATION           = 0x00000082
	PRODUCT_HOLOGRAPHIC                         = 0x00000087
	PRODUCT_PRO_SINGLE_LANGUAGE                 = 0x0000008A
	PRODUCT_PRO_CHINA                           = 0x0000008B
	PRODUCT_ENTERPRISE_SUBSCRIPTION             = 0x0000008C
	PRODUCT_ENTERPRISE_SUBSCRIPTION_N           = 0x0000008D
	PRODUCT_DATACENTER_NANO_SERVER              = 0x0000008F
	PRODUCT_STANDARD_NANO_SERVER                = 0x00000090
	PRODUCT_DATACENTER_A_SERVER_CORE            = 0x00000091
	PRODUCT_STANDARD_A_SERVER_CORE              = 0x00000092
	PRODUCT_DATACENTER_WS_SERVER_CORE           = 0x00000093
	PRODUCT_STANDARD_WS_SERVER_CORE             = 0x00000094
	PRODUCT_UTILITY_VM                          = 0x00000095
	PRODUCT_DATACENTER_EVALUATION_SERVER_CORE   = 0x0000009F
	PRODUCT_STANDARD_EVALUATION_SERVER_CORE     = 0x000000A0
	PRODUCT_PRO_WORKSTATION                     = 0x000000A1
	PRODUCT_PRO_WORKSTATION_N                   = 0x000000A2
	PRODUCT_PRO_FOR_EDUCATION                   = 0x000000A4
	PRODUCT_PRO_FOR_EDUCATION_N                 = 0x000000A5
	PRODUCT_AZURE_SERVER_CORE                   = 0x000000A8
	PRODUCT_AZURE_NANO_SERVER                   = 0x000000A9
	PRODUCT_ENTERPRISEG                         = 0x000000AB
	PRODUCT_ENTERPRISEGN                        = 0x000000AC
	PRODUCT_SERVERRDSH                          = 0x000000AF
	PRODUCT_CLOUD                               = 0x000000B2
	PRODUCT_CLOUDN                              = 0x000000B3
	PRODUCT_HUBOS                               = 0x000000B4
	PRODUCT_ONECOREUPDATEOS                     = 0x000000B6
	PRODUCT_CLOUDE                              = 0x000000B7
	PRODUCT_ANDROMEDA                           = 0x000000B8
	PRODUCT_IOTOS                               = 0x000000B9
	PRODUCT_CLOUDEN                             = 0x000000BA
	PRODUCT_UNLICENSED                          = 0xABCDABCD
)

type OsVersionInfo struct {
	osVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CsdVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	_                 byte
}

//sys	rtlGetVersion(versionInfo *OsVersionInfo) (err error) [failretval!=0] = ntdll.RtlGetVersion

func OsVersion() (versionInfo OsVersionInfo, err error) {
	versionInfo.osVersionInfoSize = uint32(unsafe.Sizeof(versionInfo))
	err = rtlGetVersion(&versionInfo)
	return
}

func OsIsCore() bool {
	versionInfo := OsVersionInfo{osVersionInfoSize: uint32(unsafe.Sizeof(OsVersionInfo{}))}
	err := rtlGetVersion(&versionInfo)
	if err != nil {
		return false
	}

	if versionInfo.MajorVersion > 6 || (versionInfo.MajorVersion == 6 && versionInfo.MinorVersion >= 2) {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels`, registry.READ)
		if err != nil {
			return false
		}
		nanoServerInteger, _, err1 := k.GetIntegerValue("NanoServer")
		serverCoreInteger, _, err2 := k.GetIntegerValue("ServerCore")
		serverGuiInteger, _, err3 := k.GetIntegerValue("Server-Gui-Shell")
		nanoServer := nanoServerInteger == 1 && err1 == nil
		serverCore := serverCoreInteger == 1 && err2 == nil
		serverGui := serverGuiInteger == 1 && err3 == nil
		k.Close()
		return (nanoServer || serverCore) && !serverGui
	}

	switch versionInfo.ProductType {
	case PRODUCT_DATACENTER_SERVER_CORE, PRODUCT_STANDARD_SERVER_CORE, PRODUCT_ENTERPRISE_SERVER_CORE, PRODUCT_WEB_SERVER_CORE, PRODUCT_DATACENTER_SERVER_CORE_V, PRODUCT_STANDARD_SERVER_CORE_V, PRODUCT_ENTERPRISE_SERVER_CORE_V, PRODUCT_STORAGE_EXPRESS_SERVER_CORE, PRODUCT_STORAGE_STANDARD_SERVER_CORE, PRODUCT_STORAGE_WORKGROUP_SERVER_CORE, PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE, PRODUCT_DATACENTER_A_SERVER_CORE, PRODUCT_STANDARD_A_SERVER_CORE, PRODUCT_DATACENTER_WS_SERVER_CORE, PRODUCT_STANDARD_WS_SERVER_CORE, PRODUCT_DATACENTER_EVALUATION_SERVER_CORE, PRODUCT_STANDARD_EVALUATION_SERVER_CORE, PRODUCT_AZURE_SERVER_CORE, PRODUCT_NANO_SERVER, PRODUCT_DATACENTER_NANO_SERVER, PRODUCT_STANDARD_NANO_SERVER, PRODUCT_AZURE_NANO_SERVER:
		return true
	}
	return false
}

func OsName() string {
	versionInfo, err := OsVersion()
	if err != nil {
		return "Windows Unknown"
	}
	winType := ""
	switch versionInfo.ProductType {
	case 3:
		winType = " Server"
	case 2:
		winType = " Controller"
	}
	if OsIsCore() {
		winType += " Core"
	}
	return fmt.Sprintf("Windows%s %d.%d.%d", winType, versionInfo.MajorVersion, versionInfo.MinorVersion, versionInfo.BuildNumber)
}
