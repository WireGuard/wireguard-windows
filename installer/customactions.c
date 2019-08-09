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

enum log_level { LOG_LEVEL_INFO, LOG_LEVEL_WARN, LOG_LEVEL_ERR };

static void log_messagef(MSIHANDLE installer, enum log_level level, const TCHAR *format, ...)
{
	MSIHANDLE record = MsiCreateRecord(2);
	TCHAR *template, *line = NULL;
	INSTALLMESSAGE type;
	va_list args;

	if (!record)
		return;

	va_start(args, format);
	FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
		      format, 0, 0, (void *)&line, 0, &args);
	va_end(args);
	if (!line)
		goto out;

	switch (level) {
	case LOG_LEVEL_INFO:
		template = TEXT("WireGuard: [1]");
		type = INSTALLMESSAGE_INFO;
		break;
	case LOG_LEVEL_WARN:
		template = TEXT("WireGuard warning: [1]");
		type = INSTALLMESSAGE_INFO;
		break;
	case LOG_LEVEL_ERR:
		template = TEXT("WireGuard error: [1]");
		type = INSTALLMESSAGE_ERROR;
		break;
	default:
		goto out;
	}
	MsiRecordSetString(record, 0, template);
	MsiRecordSetString(record, 1, line);
	MsiProcessMessage(installer, type, record);
out:
	LocalFree(line);
	MsiCloseHandle(record);
}

static void log_errorf(MSIHANDLE installer, enum log_level level, DWORD error_code, const TCHAR *prefix_format, ...)
{
	TCHAR *system_message = NULL, *prefix = NULL;
	va_list args;

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
		      NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		      (void *)&system_message, 0, NULL);
	va_start(args, prefix_format);
	FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
		      prefix_format, 0, 0, (void *)&prefix, 0, &args);
	va_end(args);
	log_messagef(installer, level, system_message ? TEXT("%1: %3(Code 0x%2!08X!)") : TEXT("%1: Code 0x%2!08X!"),
		     prefix ?: TEXT("Error"), error_code, system_message);
	LocalFree(prefix);
	LocalFree(system_message);
}

static UINT insert_service_control(MSIHANDLE installer, MSIHANDLE view, const TCHAR *service_name, bool start)
{
	static unsigned int index = 0;
	UINT ret;
	MSIHANDLE record;
	TCHAR row_identifier[_countof(TEXT("wireguard_service_control_4294967296"))];

	if (_sntprintf(row_identifier, _countof(row_identifier), TEXT("wireguard_service_control_%u"), ++index) >= _countof(row_identifier))
		return ERROR_INSTALL_FAILURE;
	record = MsiCreateRecord(5);
	if (!record)
		return ERROR_INSTALL_FAILURE;

	MsiRecordSetString (record, 1/*ServiceControl*/, row_identifier);
	MsiRecordSetString (record, 2/*Name          */, service_name);
	MsiRecordSetInteger(record, 3/*Event         */, msidbServiceControlEventStop | msidbServiceControlEventUninstallStop | msidbServiceControlEventUninstallDelete);
	MsiRecordSetString (record, 4/*Component_    */, TEXT("WireGuardExecutable"));
	MsiRecordSetInteger(record, 5/*Wait          */, 1); /* Waits 30 seconds. */
	log_messagef(installer, LOG_LEVEL_INFO, TEXT("Scheduling stop on upgrade or removal on uninstall of service %1"), service_name);
	ret = MsiViewExecute(view, record);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiViewExecute failed for service %1"), service_name);
		goto out;
	}

	if (!start)
		goto out;

	ret = ERROR_INSTALL_FAILURE;
	if (_sntprintf(row_identifier, _countof(row_identifier), TEXT("wireguard_service_control_%u"), ++index) >= _countof(row_identifier))
		goto out;
	MsiRecordSetString (record, 1/*ServiceControl*/, row_identifier);
	MsiRecordSetString (record, 2/*Name          */, service_name);
	MsiRecordSetInteger(record, 3/*Event         */, msidbServiceControlEventStart);
	MsiRecordSetString (record, 4/*Component_    */, TEXT("WireGuardExecutable"));
	MsiRecordSetInteger(record, 5/*Wait          */, 0); /* No wait, so that failure to restart again isn't fatal. */
	log_messagef(installer, LOG_LEVEL_INFO, TEXT("Scheduling start on upgrade of service %1"), service_name);
	ret = MsiViewExecute(view, record);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiViewExecute failed for service %1"), service_name);
		goto out;
	}

out:
	MsiCloseHandle(record);
	return ret;
}

static bool remove_directory_recursive(MSIHANDLE installer, TCHAR path[MAX_PATH], unsigned int max_depth)
{
	HANDLE find_handle;
	WIN32_FIND_DATA find_data;
	TCHAR *path_end;

	if (!max_depth) {
		log_messagef(installer, LOG_LEVEL_WARN, TEXT("Too many levels of nesting at \"%1\""), path);
		return false;
	}

	path_end = path + _tcsnlen(path, MAX_PATH);
	if (!PathAppend(path, TEXT("*.*"))) {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("PathAppend(\"%1\", \"*.*\") failed"), path);
		return false;
	}
	find_handle = FindFirstFileEx(path, FindExInfoBasic, &find_data, FindExSearchNameMatch, NULL, 0);
	if (find_handle == INVALID_HANDLE_VALUE) {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("FindFirstFileEx(\"%1\") failed"), path);
		return false;
	}
	do {
		if (find_data.cFileName[0] == TEXT('.') && (find_data.cFileName[1] == TEXT('\0') || (find_data.cFileName[1] == TEXT('.') && find_data.cFileName[2] == TEXT('\0'))))
			continue;

		path_end[0] = TEXT('\0');
		if (!PathAppend(path, find_data.cFileName)) {
			log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("PathAppend(\"%1\", \"%2\") failed"), path, find_data.cFileName);
			continue;
		}

		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			remove_directory_recursive(installer, path, max_depth - 1);
			continue;
		}

		if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) && !SetFileAttributes(path, find_data.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY))
			log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("SetFileAttributes(\"%1\") failed"), path);

		if (DeleteFile(path))
			log_messagef(installer, LOG_LEVEL_INFO, TEXT("Deleted \"%1\""), path);
		else
			log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("DeleteFile(\"%1\") failed"), path);
	} while (FindNextFile(find_handle, &find_data));
	FindClose(find_handle);

	path_end[0] = TEXT('\0');
	if (RemoveDirectory(path)) {
		log_messagef(installer, LOG_LEVEL_INFO, TEXT("Removed \"%1\""), path);
		return true;
	} else {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("RemoveDirectory(\"%1\") failed"), path);
		return false;
	}
}

__declspec(dllexport) UINT __stdcall EvaluateWireGuardServices(MSIHANDLE installer)
{
	UINT ret = ERROR_INSTALL_FAILURE;
	bool is_com_initialized = SUCCEEDED(CoInitialize(NULL));
	MSIHANDLE db, view = 0;
	SC_HANDLE scm = NULL;
	ENUM_SERVICE_STATUS_PROCESS *service_status = NULL;
	DWORD service_status_resume = 0;
	enum { SERVICE_STATUS_PROCESS_SIZE = 0x10000 };

	db = MsiGetActiveDatabase(installer);
	if (!db) {
		log_messagef(installer, LOG_LEVEL_ERR, TEXT("MsiGetActiveDatabase failed"));
		goto out;
	}
	ret = MsiDatabaseOpenView(db,
				  TEXT("INSERT INTO `ServiceControl` (`ServiceControl`, `Name`, `Event`, `Component_`, `Wait`) VALUES(?, ?, ?, ?, ?) TEMPORARY"),
				  &view);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiDatabaseOpenView failed"));
		goto out;
	}
	scm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (!scm) {
		ret = GetLastError();
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("OpenSCManager failed"));
		goto out;
	}

	service_status = LocalAlloc(LMEM_FIXED, SERVICE_STATUS_PROCESS_SIZE);
	if (!service_status) {
		ret = GetLastError();
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("LocalAlloc failed"));
		goto out;
	}
	for (bool more_services = true; more_services;) {
		DWORD service_status_size = 0, service_status_count = 0;
		if (EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)service_status,
					 SERVICE_STATUS_PROCESS_SIZE, &service_status_size, &service_status_count,
					 &service_status_resume, NULL))
			more_services = false;
		else {
			ret = GetLastError();
			if (ret != ERROR_MORE_DATA) {
				log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("EnumServicesStatusEx failed"));
				break;
			}
		}

		for (DWORD i = 0; i < service_status_count; ++i) {
			if (_tcsicmp(service_status[i].lpServiceName, MANAGER_SERVICE_NAME) &&
			    _tcsnicmp(service_status[i].lpServiceName, TUNNEL_SERVICE_PREFIX, _countof(TUNNEL_SERVICE_PREFIX) - 1))
				continue;
			insert_service_control(installer, view, service_status[i].lpServiceName,
					       service_status[i].ServiceStatusProcess.dwCurrentState != SERVICE_STOPPED &&
					       service_status[i].ServiceStatusProcess.dwCurrentState != SERVICE_STOP_PENDING);
		}
	}
	ret = ERROR_SUCCESS;

out:
	LocalFree(service_status);
	if (scm)
		CloseServiceHandle(scm);
	if (view)
		MsiCloseHandle(view);
	if (db)
		MsiCloseHandle(db);
	if (is_com_initialized)
		CoUninitialize();
	return ret == ERROR_SUCCESS ? ret : ERROR_INSTALL_FAILURE;
}

__declspec(dllexport) UINT __stdcall RemoveConfigFolder(MSIHANDLE installer)
{
	LSTATUS ret;
	TCHAR path[MAX_PATH];
	bool is_com_initialized = SUCCEEDED(CoInitialize(NULL));

	ret = SHRegGetPath(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18"),
			   TEXT("ProfileImagePath"), path, 0);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_WARN, ret, TEXT("SHRegGetPath failed"));
		goto out;
	}
	if (!PathAppend(path, TEXT("AppData\\Local\\WireGuard"))) {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("PathAppend(\"%1\", \"AppData\\Local\\WireGuard\") failed"), path);
		goto out;
	}
	remove_directory_recursive(installer, path, 10);
out:
	if (is_com_initialized)
		CoUninitialize();
	return ERROR_SUCCESS;
}
