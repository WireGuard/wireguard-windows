// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

#include <windows.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <shlwapi.h>
#include <stdbool.h>
#include <tchar.h>

#define MANAGER_SERVICE_NAME TEXT("WireGuardManager")
#define TUNNEL_SERVICE_PREFIX TEXT("WireGuardTunnel$")
#define ENUM_SERVICE_STATUS_PROCESS_SIZE 0x10000

typedef enum
{
	LOG_LEVEL_INFO = 0,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERR
} log_level_t;

static TCHAR *format_message(const TCHAR *template, const DWORD_PTR argv[])
{
	TCHAR *formatted_message = NULL;
	if (!FormatMessage(
		FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_MAX_WIDTH_MASK,
		template,
		0,
		0,
		(VOID *)&formatted_message,
		0,
		(va_list *)argv))
		return NULL;
	return formatted_message;
}

static void log_message(MSIHANDLE installer, log_level_t level, const TCHAR *log_line)
{
	MSIHANDLE record = MsiCreateRecord(2);
	if (!record)
		return;
	TCHAR *template;
	INSTALLMESSAGE type;
	switch (level) {
	case LOG_LEVEL_INFO:
		template = TEXT("Custom action: [1]");
		type = INSTALLMESSAGE_INFO;
		break;
	case LOG_LEVEL_WARN:
		template = TEXT("Custom action warning: [1]");
		type = INSTALLMESSAGE_INFO;
		break;
	case LOG_LEVEL_ERR:
		template = TEXT("Custom action error: [1]");
		type = INSTALLMESSAGE_ERROR;
		break;
	default:
		goto cleanup;
	}
	MsiRecordSetString(record, 0, template);
	MsiRecordSetString(record, 1, log_line);
	MsiProcessMessage(installer, type, record);
cleanup:
	MsiCloseHandle(record);
}

static void log_messagef(MSIHANDLE installer, log_level_t level, const TCHAR *template, const DWORD_PTR argv[])
{
	TCHAR *formatted_message = format_message(template, argv);
	if (formatted_message) {
		log_message(installer, level, formatted_message);
		LocalFree(formatted_message);
	}
}

static void log_error(MSIHANDLE installer, DWORD error_code, const TCHAR *prefix)
{
	TCHAR *system_message = NULL;
	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
		NULL,
		HRESULT_FROM_SETUPAPI(error_code),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(VOID *)&system_message,
		0,
		NULL);
	log_messagef(
		installer,
		LOG_LEVEL_ERR,
		system_message ? TEXT("%1: %3(Code 0x%2!08X!)") : TEXT("%1: Code 0x%2!08X!"),
		(DWORD_PTR[]){ (DWORD_PTR)prefix, error_code, (DWORD_PTR)system_message });
	LocalFree(system_message);
}

static void log_errorf(MSIHANDLE installer, DWORD error_code, const TCHAR *template, const DWORD_PTR argv[])
{
	TCHAR *formatted_message = format_message(template, argv);
	if (formatted_message) {
		log_error(installer, error_code, formatted_message);
		LocalFree(formatted_message);
	}
}

static bool is_valid_tunnel_name(const TCHAR *tunnel_name)
{
	for (size_t i = 0; ; i++) {
		TCHAR c = tunnel_name[i];
		if (!c)
			return i > 0;
		if (i >= 32)
			return false;
		if ((c < TEXT('a') || c > TEXT('z')) &&
			(c < TEXT('A') || c > TEXT('Z')) &&
			(c < TEXT('0') || c > TEXT('9')) &&
			c != TEXT('_') &&
			c != TEXT('=') &&
			c != TEXT('+') &&
			c != TEXT('.') &&
			c != TEXT('-'))
			return false;
	}
}

static void replace_msi_operators(TCHAR *dest, const TCHAR *src, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		TCHAR c = src[i];
		switch (c) {
			case 0:
				dest[i] = 0;
				return;
			case TEXT('='):
			case TEXT('+'):
			case TEXT('-'):
				dest[i] = TEXT('_');
				break;
			default:
				dest[i] = c;
		}
	}
}

static bool is_service_started(MSIHANDLE installer, SC_HANDLE scm, const TCHAR *service_name)
{
	bool ret = false;
	SC_HANDLE service = NULL;
	SERVICE_STATUS_PROCESS service_status;
	DWORD service_status_size = 0;
	const DWORD_PTR log_argv[] = { (DWORD_PTR)__FUNCTION__, (DWORD_PTR)service_name };

	service = OpenService(scm, MANAGER_SERVICE_NAME, SERVICE_QUERY_STATUS);
	if (!service) {
		log_errorf(installer, GetLastError(), TEXT("%1!hs!: OpenService failed for service %2"), log_argv);
		goto cleanup;
	}
	if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&service_status, sizeof(service_status), &service_status_size)) {
		log_errorf(installer, GetLastError(), TEXT("%1!hs!: QueryServiceStatusEx failed for service %2"), log_argv);
		goto cleanup;
	}
	if (service_status.dwCurrentState != SERVICE_STOPPED && service_status.dwCurrentState != SERVICE_STOP_PENDING)
		ret = true;

cleanup:
	if (service)
		CloseServiceHandle(service);
	return ret;
}

static UINT insert_service_control(MSIHANDLE installer, MSIHANDLE view, const TCHAR *service_name, bool start)
{
	UINT ret = ERROR_INSTALL_FAILURE;
	MSIHANDLE record = 0;
	const DWORD_PTR log_argv[] = { (DWORD_PTR)__FUNCTION__, (DWORD_PTR)service_name };
	size_t service_name_len;
	TCHAR *sanitized_service_name = NULL, *service_control_stop = NULL, *service_control_start = NULL;
	static unsigned int index = 0;

	record = MsiCreateRecord(5);
	if (!record)
		goto cleanup;

	service_name_len = _tcslen(service_name) + 1;
	sanitized_service_name = LocalAlloc(LMEM_FIXED, sizeof(TCHAR) * service_name_len);
	if (!sanitized_service_name) {
		ret = GetLastError();
		log_errorf(installer, ret, TEXT("%1!hs!: LocalAlloc failed for service %2"), log_argv);
		goto cleanup;
	}
	replace_msi_operators(sanitized_service_name, service_name, service_name_len);

	log_messagef(installer, LOG_LEVEL_INFO, TEXT("%1!hs!: Scheduling stop on upgrade or removal on uninstall of service %2"), log_argv);
	service_control_stop = format_message(TEXT("stop_%1%2!u!"), (DWORD_PTR[]){ (DWORD_PTR)sanitized_service_name, index++ });
	if (!service_control_stop) {
		ret = GetLastError();
		log_errorf(installer, ret, TEXT("%1!hs!: FormatMessage failed for service %2"), log_argv);
		goto cleanup;
	}
	MsiRecordSetString (record, 1/*ServiceControl*/, service_control_stop);
	MsiRecordSetString (record, 2/*Name          */, service_name);
	MsiRecordSetInteger(record, 3/*Event         */, msidbServiceControlEventStop | msidbServiceControlEventUninstallStop | msidbServiceControlEventUninstallDelete);
	MsiRecordSetString (record, 4/*Component_    */, TEXT("WireGuardExecutable"));
	MsiRecordSetInteger(record, 5/*Wait          */, 1); /* Waits 30 seconds. */
	ret = MsiViewExecute(view, record);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, ret, TEXT("%1!hs!: MsiViewExecute failed for service %2"), log_argv);
		goto cleanup;
	}
	if (!start)
		goto cleanup;

	log_messagef(installer, LOG_LEVEL_INFO, TEXT("%1!hs!: Scheduling start on upgrade of service %2"), log_argv);
	service_control_start = format_message(TEXT("start_%1%2!u!"), (DWORD_PTR[]){ (DWORD_PTR)sanitized_service_name, index++ });
	if (!service_control_start) {
		ret = GetLastError();
		log_errorf(installer, ret, TEXT("%1!hs!: FormatMessage failed for service %2"), log_argv);
		goto cleanup;
	}
	MsiRecordSetString (record, 1/*ServiceControl*/, service_control_start);
	MsiRecordSetString (record, 2/*Name          */, service_name);
	MsiRecordSetInteger(record, 3/*Event         */, msidbServiceControlEventStart);
	MsiRecordSetString (record, 4/*Component_    */, TEXT("WireGuardExecutable"));
	MsiRecordSetInteger(record, 5/*Wait          */, 0); /* No wait, so that failure to restart again isn't fatal. */
	ret = MsiViewExecute(view, record);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, ret, TEXT("%1!hs!: MsiViewExecute failed for service %2"), log_argv);
		goto cleanup;
	}

cleanup:
	if (service_control_start)
		LocalFree(service_control_start);
	if (service_control_stop)
		LocalFree(service_control_stop);
	if (sanitized_service_name)
		LocalFree(sanitized_service_name);
	if (record)
		MsiCloseHandle(record);
	return ret;
}

static bool remove_folder(MSIHANDLE installer, TCHAR path[MAX_PATH])
{
	HANDLE find_handle;
	WIN32_FIND_DATA find_data;
	TCHAR *path_end;
	const DWORD_PTR log_argv[] = { (DWORD_PTR)__FUNCTION__, (DWORD_PTR)path };

	path_end = path + _tcsnlen(path, MAX_PATH);
	if (!PathAppend(path, TEXT("*.*"))) {
		log_messagef(installer, LOG_LEVEL_ERR, TEXT("%1!hs!: PathAppend(%2) failed"), log_argv);
		return false;
	}
	find_handle = FindFirstFileEx(path, FindExInfoBasic, &find_data, FindExSearchNameMatch, NULL, 0);
	if (find_handle == INVALID_HANDLE_VALUE) {
		log_errorf(installer, GetLastError(), TEXT("%1!hs!: FindFirstFileEx(%2) failed"), log_argv);
		return false;
	}
	do {
		if (find_data.cFileName[0] == TEXT('.') && (!find_data.cFileName[1] || (find_data.cFileName[1] == TEXT('.') && !find_data.cFileName[2])))
			continue;

		path_end[0] = 0;
		if (!PathAppend(path, find_data.cFileName)) {
			log_messagef(installer, LOG_LEVEL_ERR, TEXT("%1!hs!: PathAppend(%2) failed"), log_argv);
			continue;
		}

		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			remove_folder(installer, path);
			continue;
		}

		if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) && !SetFileAttributes(path, find_data.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY))
			log_errorf(installer, GetLastError(), TEXT("%1!hs!: SetFileAttributes(%2) failed"), log_argv);

		if (DeleteFile(path))
			log_messagef(installer, LOG_LEVEL_INFO, TEXT("%1!hs!: %2 removed"), log_argv);
		else
			log_errorf(installer, GetLastError(), TEXT("%1!hs!: DeleteFile(%2) failed"), log_argv);
	} while (FindNextFile(find_handle, &find_data));
	FindClose(find_handle);

	path_end[0] = 0;
	if (RemoveDirectory(path)) {
		log_messagef(installer, LOG_LEVEL_INFO, TEXT("%1!hs!: %2 removed"), log_argv);
		return true;
	} else {
		log_errorf(installer, GetLastError(), TEXT("%1!hs!: RemoveDirectory(%2) failed"), log_argv);
		return false;
	}
}

__declspec(dllexport) UINT __stdcall EvaluateWireGuardServices(MSIHANDLE installer)
{
	UINT ret = ERROR_INSTALL_FAILURE;
	BOOL is_com_initialized = SUCCEEDED(CoInitialize(NULL));
	MSIHANDLE db = 0, view = 0;
	SC_HANDLE scm = NULL;
	ENUM_SERVICE_STATUS_PROCESS *service_status = NULL;
	DWORD service_status_resume = 0;
	const DWORD_PTR log_argv[] = { (DWORD_PTR)__FUNCTION__ };

	db = MsiGetActiveDatabase(installer);
	if (!db) {
		log_messagef(installer, LOG_LEVEL_ERR, TEXT("%1!hs!: MsiGetActiveDatabase failed"), log_argv);
		goto cleanup;
	}
	ret = MsiDatabaseOpenView(
		db,
		TEXT("INSERT INTO `ServiceControl` (`ServiceControl`, `Name`, `Event`, `Component_`, `Wait`) VALUES(?, ?, ?, ?, ?) TEMPORARY"),
		&view);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, ret, TEXT("%1!hs!: MsiDatabaseOpenView failed"), log_argv);
		goto cleanup;
	}
	scm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (!scm) {
		ret = GetLastError();
		log_errorf(installer, ret, TEXT("%1!hs!: OpenSCManager failed"), log_argv);
		goto cleanup;
	}

	insert_service_control(installer, view, MANAGER_SERVICE_NAME, is_service_started(installer, scm, MANAGER_SERVICE_NAME));

	service_status = LocalAlloc(LMEM_FIXED, ENUM_SERVICE_STATUS_PROCESS_SIZE);
	if (!service_status) {
		ret = GetLastError();
		log_errorf(installer, ret, TEXT("%1!hs!: LocalAlloc failed"), log_argv);
		goto cleanup;
	}
	for (bool more_services = true; more_services;) {
		DWORD service_status_size = 0, service_status_count = 0;
		if (EnumServicesStatusEx(
			scm,
			SC_ENUM_PROCESS_INFO,
			SERVICE_WIN32,
			SERVICE_STATE_ALL,
			(LPBYTE)service_status,
			ENUM_SERVICE_STATUS_PROCESS_SIZE,
			&service_status_size,
			&service_status_count,
			&service_status_resume,
			NULL))
			more_services = false;
		else {
			ret = GetLastError();
			if (ret != ERROR_MORE_DATA) {
				log_errorf(installer, ret, TEXT("%1!hs!: EnumServicesStatusEx failed"), log_argv);
				break;
			}
		}

		for (DWORD i = 0; i < service_status_count; i++) {
			if (_tcsnicmp(service_status[i].lpServiceName, TUNNEL_SERVICE_PREFIX, _countof(TUNNEL_SERVICE_PREFIX) - 1) == 0) {
				const TCHAR *tunnel_name = service_status[i].lpServiceName + _countof(TUNNEL_SERVICE_PREFIX) - 1;
				if (is_valid_tunnel_name(tunnel_name))
					insert_service_control(
						installer,
						view,
						service_status[i].lpServiceName,
						service_status[i].ServiceStatusProcess.dwCurrentState != SERVICE_STOPPED && service_status[i].ServiceStatusProcess.dwCurrentState != SERVICE_STOP_PENDING);
			}
		}
	}

	ret = ERROR_SUCCESS;

cleanup:
	if (service_status)
		LocalFree(service_status);
	if (scm)
		CloseServiceHandle(scm);
	if (view)
		MsiCloseHandle(view);
	if (db)
		MsiCloseHandle(db);
	if (is_com_initialized)
		CoUninitialize();
	return ret == ERROR_SUCCESS ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
}

__declspec(dllexport) UINT __stdcall RemoveConfigFolder(MSIHANDLE installer)
{
	LSTATUS result;
	TCHAR path[MAX_PATH];

	result = SHRegGetPath(
		HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18"),
		TEXT("ProfileImagePath"),
		path,
		0);
	if (result != ERROR_SUCCESS) {
		log_errorf(installer, result, TEXT("%1!hs!: SHRegGetPath failed"), (DWORD_PTR[]){ (DWORD_PTR)__FUNCTION__ });
		return ERROR_SUCCESS;
	}
	PathAppend(path, TEXT("AppData\\Local\\WireGuard"));
	remove_folder(installer, path);
	return ERROR_SUCCESS;
}
