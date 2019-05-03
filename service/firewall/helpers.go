/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"fmt"
	"golang.org/x/sys/windows"
	"runtime"
	"syscall"
)

func (m wtFwpMatchType) String() string {
	switch m {
	case cFWP_MATCH_EQUAL:
		return "FWP_MATCH_EQUAL"
	case cFWP_MATCH_GREATER:
		return "FWP_MATCH_GREATER"
	case cFWP_MATCH_LESS:
		return "FWP_MATCH_LESS"
	case cFWP_MATCH_GREATER_OR_EQUAL:
		return "FWP_MATCH_GREATER_OR_EQUAL"
	case cFWP_MATCH_LESS_OR_EQUAL:
		return "FWP_MATCH_LESS_OR_EQUAL"
	case cFWP_MATCH_RANGE:
		return "FWP_MATCH_RANGE"
	case cFWP_MATCH_FLAGS_ALL_SET:
		return "FWP_MATCH_FLAGS_ALL_SET"
	case cFWP_MATCH_FLAGS_ANY_SET:
		return "FWP_MATCH_FLAGS_ANY_SET"
	case cFWP_MATCH_FLAGS_NONE_SET:
		return "FWP_MATCH_FLAGS_NONE_SET"
	case cFWP_MATCH_EQUAL_CASE_INSENSITIVE:
		return "FWP_MATCH_EQUAL_CASE_INSENSITIVE"
	case cFWP_MATCH_NOT_EQUAL:
		return "FWP_MATCH_NOT_EQUAL"
	case cFWP_MATCH_PREFIX:
		return "FWP_MATCH_PREFIX"
	case cFWP_MATCH_NOT_PREFIX:
		return "FWP_MATCH_NOT_PREFIX"
	case cFWP_MATCH_TYPE_MAX:
		return "FWP_MATCH_TYPE_MAX"
	default:
		return fmt.Sprintf("FwpMatchType_UNKNOWN(%d)", m)
	}
}

func (ff wtFwpmFilterFlags) String() string {
	switch ff {
	case cFWPM_FILTER_FLAG_NONE:
		return "FWPM_FILTER_FLAG_NONE"
	case cFWPM_FILTER_FLAG_PERSISTENT:
		return "FWPM_FILTER_FLAG_PERSISTENT"
	case cFWPM_FILTER_FLAG_BOOTTIME:
		return "FWPM_FILTER_FLAG_BOOTTIME"
	case cFWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT:
		return "FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT"
	case cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT:
		return "FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT"
	case cFWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED:
		return "FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED"
	case cFWPM_FILTER_FLAG_DISABLED:
		return "FWPM_FILTER_FLAG_DISABLED"
	case cFWPM_FILTER_FLAG_INDEXED:
		return "FWPM_FILTER_FLAG_INDEXED"
	case cFWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT:
		return "FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT"
	case cFWPM_FILTER_FLAG_SYSTEMOS_ONLY:
		return "FWPM_FILTER_FLAG_SYSTEMOS_ONLY"
	case cFWPM_FILTER_FLAG_GAMEOS_ONLY:
		return "FWPM_FILTER_FLAG_GAMEOS_ONLY"
	case cFWPM_FILTER_FLAG_SILENT_MODE:
		return "FWPM_FILTER_FLAG_SILENT_MODE"
	case cFWPM_FILTER_FLAG_IPSEC_NO_ACQUIRE_INITIATE:
		return "FWPM_FILTER_FLAG_IPSEC_NO_ACQUIRE_INITIATE"
	default:
		return fmt.Sprintf("FwpmFilterFlags_UNKNOWN(%d)", ff)
	}
}

func (dt wtFwpDataType) String() string {
	switch dt {
	case cFWP_EMPTY:
		return "FWP_EMPTY"
	case cFWP_UINT8:
		return "FWP_UINT8"
	case cFWP_UINT16:
		return "FWP_UINT16"
	case cFWP_UINT32:
		return "FWP_UINT32"
	case cFWP_UINT64:
		return "FWP_UINT64"
	case cFWP_INT8:
		return "FWP_INT8"
	case cFWP_INT16:
		return "FWP_INT16"
	case cFWP_INT32:
		return "FWP_INT32"
	case cFWP_INT64:
		return "FWP_INT64"
	case cFWP_FLOAT:
		return "FWP_FLOAT"
	case cFWP_DOUBLE:
		return "FWP_DOUBLE"
	case cFWP_BYTE_ARRAY16_TYPE:
		return "FWP_BYTE_ARRAY16_TYPE"
	case cFWP_BYTE_BLOB_TYPE:
		return "FWP_BYTE_BLOB_TYPE"
	case cFWP_SID:
		return "FWP_SID"
	case cFWP_SECURITY_DESCRIPTOR_TYPE:
		return "FWP_SECURITY_DESCRIPTOR_TYPE"
	case cFWP_TOKEN_INFORMATION_TYPE:
		return "FWP_TOKEN_INFORMATION_TYPE"
	case cFWP_TOKEN_ACCESS_INFORMATION_TYPE:
		return "FWP_TOKEN_ACCESS_INFORMATION_TYPE"
	case cFWP_UNICODE_STRING_TYPE:
		return "FWP_UNICODE_STRING_TYPE"
	case cFWP_BYTE_ARRAY6_TYPE:
		return "FWP_BYTE_ARRAY6_TYPE"
	case cFWP_BITMAP_INDEX_TYPE:
		return "FWP_BITMAP_INDEX_TYPE"
	case cFWP_BITMAP_ARRAY64_TYPE:
		return "FWP_BITMAP_ARRAY64_TYPE"
	case cFWP_SINGLE_DATA_TYPE_MAX:
		return "FWP_SINGLE_DATA_TYPE_MAX"
	case cFWP_V4_ADDR_MASK:
		return "FWP_V4_ADDR_MASK"
	case cFWP_V6_ADDR_MASK:
		return "FWP_V6_ADDR_MASK"
	case cFWP_RANGE_TYPE:
		return "FWP_RANGE_TYPE"
	case cFWP_DATA_TYPE_MAX:
		return "FWP_DATA_TYPE_MAX"
	default:
		return fmt.Sprintf("FwpDataType_UNKNOWN(%d)", dt)
	}
}

func runTransaction(session uintptr, operation wfpObjectInstaller) error {
	err := fwpmTransactionBegin0(session, 0)
	if err != nil {
		return wrapErr(err)
	}

	err = operation(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	err = fwpmTransactionCommit0(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	return nil
}

func createWtFwpmDisplayData0(name, description string) (*wtFwpmDisplayData0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, wrapErr(err)
	}

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, wrapErr(err)
	}

	return &wtFwpmDisplayData0{
		name:        namePtr,
		description: descriptionPtr,
	}, nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}

func wrapErr(err error) error {
	if _, ok := err.(syscall.Errno); !ok {
		return err
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("Firewall error at unknown location: %v", err)
	} else {
		return fmt.Errorf("Firewall error at %s:%d: %v", file, line, err)
	}
}
