// Copyright 2013 The win Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package win

import (
	"syscall"
	"unsafe"
)

// PDH error codes, which can be returned by all Pdh* functions.
const (
	PDH_CSTATUS_VALID_DATA      = 0x00000000 // The returned data is valid.
	PDH_CSTATUS_INVALID_DATA    = 0xC0000BBA // The counter was successfully found, but the data returned is not valid.
	PDH_CSTATUS_NEW_DATA        = 0x00000001 // The return data value is valid and different from the last sample.
	PDH_CSTATUS_NO_MACHINE      = 0x800007D0 // Unable to connect to the specified computer, or the computer is offline.
	PDH_CSTATUS_BAD_COUNTERNAME = 0xC0000BC0 // Unable to parse the counter path. Check the format and syntax of the specified path.
	PDH_INVALID_ARGUMENT        = 0xC0000BBD // Required argument is missing or incorrect.
	PDH_INVALID_DATA            = 0xC0000BC6 // specified counter does not contain valid data or a successful status code.
)

// Formatting options for GetFormattedCounterValue().
const (
	PDH_FMT_RAW          = 0x00010
	PDH_FMT_ANSI         = 0x00020
	PDH_FMT_UNICODE      = 0x00040
	PDH_FMT_LONG         = 0x00100 // Return data as a long int.
	PDH_FMT_DOUBLE       = 0x00200 // Return data as a double precision floating point real. 
	PDH_FMT_LARGE        = 0x00400 // Return data as a 64 bit integer.
	PDH_FMT_NOSCALE      = 0x01000 // can be OR-ed: Do not apply the counter's default scaling factor.
	PDH_FMT_1000         = 0x02000 // can be OR-ed: multiply the actual value by 1,000.
	PDH_FMT_NODATA       = 0x04000 // can be OR-ed: unknown what this is for, MSDN says nothing.
	PDH_FMT_NOCAP100     = 0x08000 // can be OR-ed: do not cap values > 100.
	PERF_DETAIL_COSTLY   = 0x10000
	PERF_DETAIL_STANDARD = 0x0FFFF
)

type (
	PDH_HQUERY   HANDLE // query handle
	PDH_HCOUNTER HANDLE // counter handle
)

type PDH_FMT_COUNTERVALUE struct {
	CStatus         uint32
	LongValue       int32
	DoubleValue     float64
	LargeValue      int64
	AnsiStringValue uintptr // Not supported according to MSDN
	WideStringValue uintptr // Not supported according to MSDN
}

// PdhBrowseCounters configuration struct. Untested.
type PDH_BROWSE_DLG_CONFIG struct {
	BIncludeInstanceIndex    uint32
	BSingleCounterPerAdd     uint32
	BSingleCounterPerDialog  uint32
	BLocalCountersOnly       uint32
	BWildCardInstance        uint32
	BHideDetailBox           uint32
	BInitializePath          uint32
	BDisableMachineSelection uint32
	BIncludeCostlyObjects    uint32
	BShowObjectBrowser       uint32
	BReserved                uint32
	HwndOwner                HWND
	SzDataSource             uintptr
	SzReturnPathBuffer       uintptr
	CchReturnPathLength      uint32
	PCallBack                int // CounterPathCallBack
	DwCallBackArg            uintptr
	CallBackStatus           uint32 // PDH error status code
	DwDefaultDetailLevel     uint32
	SzDialogBoxCaption       uintptr // pointer to a string
}

var (
	// Library
	libpdhDll *syscall.DLL

	// Functions
	pdh_AddCounterW              *syscall.Proc
	pdh_AddEnglishCounterW       *syscall.Proc
	pdh_BrowseCounters           *syscall.Proc
	pdh_CloseQuery               *syscall.Proc
	pdh_CollectQueryData         *syscall.Proc
	pdh_GetFormattedCounterValue *syscall.Proc
	pdh_OpenQuery                *syscall.Proc
	pdh_ValidatePath             *syscall.Proc
)

func init() {
	// Library
	libpdhDll = syscall.MustLoadDLL("pdh.dll")

	// Functions
	pdh_AddCounterW = libpdhDll.MustFindProc("PdhAddCounterW")
	pdh_AddEnglishCounterW = libpdhDll.MustFindProc("PdhAddEnglishCounterW")
	pdh_BrowseCounters = libpdhDll.MustFindProc("PdhBrowseCountersW")
	pdh_CloseQuery = libpdhDll.MustFindProc("PdhCloseQuery")
	pdh_CollectQueryData = libpdhDll.MustFindProc("PdhCollectQueryData")
	pdh_GetFormattedCounterValue = libpdhDll.MustFindProc("PdhGetFormattedCounterValue")
	pdh_OpenQuery = libpdhDll.MustFindProc("PdhOpenQuery")
	pdh_ValidatePath = libpdhDll.MustFindProc("PdhValidatePathW")
}

// Adds the specified counter to the query. This is the NON-ENGLISH version. Preferably, use the
// function PdhAddEnglishCounter instead. hQuery is the query handle, which has been fetched by PdhOpenQuery.
// szFullCounterPath is a full, internationalized counter path (this will differ per Windows language version).
// dwUserData is a 'user-defined value', which becomes part of the counter information. To retrieve this value
// later, call PdhGetCounterInfo() and access dwQueryUserData of the PDH_COUNTER_INFO structure.
//
// Examples of szFullCounterPath (in an English version of Windows):
//
//	\\Processor(_Total)\\% Idle Time
//	\\Processor(_Total)\\% Processor Time
//	\\LogicalDisk(C:)\% Free Space
//
// To view all available counters on a system, try the PdhBrowseCounters() function.
func PdhAddCounter(hQuery PDH_HQUERY, szFullCounterPath string, dwUserData uintptr, phCounter *PDH_HCOUNTER) uint32 {
	ptxt, _ := syscall.UTF16PtrFromString(szFullCounterPath)
	ret, _, _ := pdh_AddCounterW.Call(uintptr(hQuery),
		uintptr(unsafe.Pointer(ptxt)),
		dwUserData,
		uintptr(unsafe.Pointer(phCounter)))

	return uint32(ret)
}

// Adds the specified language-neutral counter to the query. See the PdhAddCounter function.
func PdhAddEnglishCounter(hQuery PDH_HQUERY, szFullCounterPath string, dwUserData uintptr, phCounter *PDH_HCOUNTER) uint32 {
	ptxt, _ := syscall.UTF16PtrFromString(szFullCounterPath)
	ret, _, _ := pdh_AddEnglishCounterW.Call(uintptr(hQuery),
		uintptr(unsafe.Pointer(ptxt)),
		dwUserData,
		uintptr(unsafe.Pointer(phCounter)))

	return uint32(ret)
}

// Creates a new query that is used to manage the collection of performance data.
// szDataSource is a null terminated string that specifies the name of the log file from which to
// retrieve the performance data. If 0, performance data is collected from a real-time data source.
// dwUserData is a user-defined value to associate with this query. To retrieve the user data later,
// call PdhGetCounterInfo and access dwQueryUserData of the PDH_COUNTER_INFO structure. phQuery is
// the handle to the query, and must be used in subsequent calls. This function returns a PDH_
// constant error code, or 0 if the call succeeded.
func PdhOpenQuery(szDataSource uintptr, dwUserData uintptr, phQuery *PDH_HQUERY) uint32 {
	ret, _, _ := pdh_OpenQuery.Call(szDataSource,
		dwUserData,
		uintptr(unsafe.Pointer(phQuery)))

	return uint32(ret)
}

// Closes all counters contained in the specified query, closes all handles related to the query,
// and frees all memory associated with the query.
func PdhCloseQuery(hQuery PDH_HQUERY) uint32 {
	ret, _, _ := pdh_CloseQuery.Call(uintptr(hQuery))

	return uint32(ret)
}

// Collects the current raw data value for all counters in the specified query and updates the status
// code of each counter. With some counters, this function needs to be repeatedly called before the value
// of the counter can be extracted with PdhGetFormattedCounterValue(). For example, the following code
// requires at least two calls:
//
// 	var handle win.PDH_HQUERY
// 	var counterHandle win.PDH_HCOUNTER
// 	ret := win.PdhOpenQuery(0, 0, &handle)
//	ret = win.PdhAddEnglishCounter(handle, "\\Processor(_Total)\\% Idle Time", 0, &counterHandle)
//	var derp win.PDH_FMT_COUNTERVALUE
//
//	ret = win.PdhCollectQueryData(handle)
//	fmt.Printf("Collect return code is %x\n", ret) // return code will be PDH_CSTATUS_INVALID_DATA
//	ret = win.PdhGetFormattedCounterValue(counterHandle, win.PDH_FMT_DOUBLE, 0, &derp)
//
//	ret = win.PdhCollectQueryData(handle)
//	fmt.Printf("Collect return code is %x\n", ret) // return code will be ERROR_SUCCESS
//	ret = win.PdhGetFormattedCounterValue(counterHandle, win.PDH_FMT_DOUBLE, 0, &derp)
//
// The PdhCollectQueryData will return an error in the first call because it needs two values for
// displaying the correct data for the processor idle time. The second call will have a 0 return code.
func PdhCollectQueryData(hQuery PDH_HQUERY) uint32 {
	ret, _, _ := pdh_CollectQueryData.Call(uintptr(hQuery))

	return uint32(ret)
}

// Formats a counter hCounter according the dwFormat. The result is set in the PDH_FMT_COUNTERVALUE struct, pValue.
func PdhGetFormattedCounterValue(hCounter PDH_HCOUNTER, dwFormat uint32, lpdwType uintptr, pValue *PDH_FMT_COUNTERVALUE) uint32 {
	ret, _, _ := pdh_GetFormattedCounterValue.Call(uintptr(hCounter),
		uintptr(dwFormat),
		uintptr(unsafe.Pointer(lpdwType)),
		uintptr(unsafe.Pointer(pValue)))

	return uint32(ret)
}

// Displays a Browse Counters dialog box that the user can use to select one or more counters
// that they want to add to the query. This function returns a PDH error code, or 0 of the call succeeded.
// This call is pretty much untested. On my machine, it displays a dialog box perfectly with specifying
// a practical 'unfilled' struct, but that's all I've tested.
func PdhBrowseCounters(pBrowseDlgData *PDH_BROWSE_DLG_CONFIG) uint32 {
	ret, _, _ := pdh_BrowseCounters.Call(uintptr(unsafe.Pointer(pBrowseDlgData)))

	return uint32(ret)
}

// Validates a path. Will return ERROR_SUCCESS when ok, or PDH_CSTATUS_BAD_COUNTERNAME when the path is
// erroneous.
func PdhValidatePath(path string) uint32 {
	ptxt, _ := syscall.UTF16PtrFromString(path)
	ret, _, _ := pdh_ValidatePath.Call(uintptr(unsafe.Pointer(ptxt)))

	return uint32(ret)
}
