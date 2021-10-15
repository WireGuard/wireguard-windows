// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

#include <windows.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <msi.h>
#include <msidefs.h>
#include <msiquery.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <stdbool.h>
#include <tchar.h>

#define MANAGER_SERVICE_NAME TEXT("WireGuardManager")
#define TUNNEL_SERVICE_PREFIX TEXT("WireGuardTunnel$")

enum log_level { LOG_LEVEL_INFO, LOG_LEVEL_WARN, LOG_LEVEL_ERR, LOG_LEVEL_MSIERR };

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
	case LOG_LEVEL_MSIERR:
		template = TEXT("[1]");
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

__declspec(dllexport) UINT __stdcall CheckWow64(MSIHANDLE installer)
{
	UINT ret = ERROR_SUCCESS;
	bool is_com_initialized = SUCCEEDED(CoInitialize(NULL));
	HMODULE kernel32 = GetModuleHandle(TEXT("kernel32.dll"));
	BOOL(WINAPI *IsWow64Process2)(HANDLE hProcess, USHORT *pProcessMachine, USHORT *pNativeMachine);
	USHORT process_machine, native_machine;
	BOOL is_wow64_process;

	if (!kernel32) {
		ret = GetLastError();
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("Failed to get kernel32.dll handle"));
		goto out;
	}
	*(FARPROC *)&IsWow64Process2 = GetProcAddress(kernel32, "IsWow64Process2");
	if (IsWow64Process2) {
		if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine)) {
			ret = GetLastError();
			log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("Failed to determine Wow64 status from IsWow64Process2"));
			goto out;
		}
		if (process_machine == IMAGE_FILE_MACHINE_UNKNOWN)
			goto out;
	} else {
		if (!IsWow64Process(GetCurrentProcess(), &is_wow64_process)) {
			ret = GetLastError();
			log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("Failed to determine Wow64 status from IsWow64Process"));
			goto out;
		}
		if (!is_wow64_process)
			goto out;
	}
	log_messagef(installer, LOG_LEVEL_MSIERR, TEXT("You must use the native version of WireGuard on this computer."));
	ret = ERROR_INSTALL_FAILURE;
out:
	if (is_com_initialized)
		CoUninitialize();
	return ret;
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

__declspec(dllexport) UINT __stdcall LaunchApplicationAndAbort(MSIHANDLE installer)
{
	UINT ret = ERROR_INSTALL_FAILURE;
	TCHAR path[MAX_PATH];
	DWORD path_len = _countof(path);
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { .cb = sizeof(STARTUPINFO) };

	ret = MsiGetProperty(installer, TEXT("WireGuardFolder"), path, &path_len);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_WARN, ret, TEXT("MsiGetProperty(\"WireGuardFolder\") failed"));
		goto out;
	}
	if (!path[0] || !PathAppend(path, TEXT("wireguard.exe")))
		goto out;
	log_messagef(installer, LOG_LEVEL_INFO, TEXT("Launching %1"), path);
	if (!CreateProcess(path, TEXT("wireguard"), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("Failed to create \"%1\" process"), path);
		goto out;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
out:
	return ERROR_INSTALL_USEREXIT;
}

__declspec(dllexport) UINT __stdcall EvaluateWireGuardComponents(MSIHANDLE installer)
{
	UINT ret = ERROR_INSTALL_FAILURE;
	bool is_com_initialized = SUCCEEDED(CoInitialize(NULL));
	INSTALLSTATE component_installed, component_action;
	TCHAR path[MAX_PATH];
	DWORD path_len = _countof(path);

	ret = MsiGetComponentState(installer, TEXT("WireGuardExecutable"), &component_installed, &component_action);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiGetComponentState(\"WireGuardExecutable\") failed"));
		goto out;
	}
	ret = MsiGetProperty(installer, TEXT("WireGuardFolder"), path, &path_len);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiGetProperty(\"WireGuardFolder\") failed"));
		goto out;
	}

	if (component_action >= INSTALLSTATE_LOCAL) {
		/* WireGuardExecutable component shall be installed. */
		ret = MsiSetProperty(installer, TEXT("KillWireGuardProcesses"), path);
		if (ret != ERROR_SUCCESS) {
			log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiSetProperty(\"KillWireGuardProcesses\") failed"));
			goto out;
		}
	} else if (component_action >= INSTALLSTATE_REMOVED) {
		/* WireGuardExecutable component shall be uninstalled. */
		ret = MsiSetProperty(installer, TEXT("KillWireGuardProcesses"), path);
		if (ret != ERROR_SUCCESS) {
			log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiSetProperty(\"KillWireGuardProcesses\") failed"));
			goto out;
		}
		ret = MsiSetProperty(installer, TEXT("RemoveConfigFolder"), path);
		if (ret != ERROR_SUCCESS) {
			log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiSetProperty(\"RemoveConfigFolder\") failed"));
			goto out;
		}
		ret = MsiSetProperty(installer, TEXT("RemoveAdapters"), path);
		if (ret != ERROR_SUCCESS) {
			log_errorf(installer, LOG_LEVEL_ERR, ret, TEXT("MsiSetProperty(\"RemoveAdapters\") failed"));
			goto out;
		}
	}
	ret = ERROR_SUCCESS;

out:
	if (is_com_initialized)
		CoUninitialize();
	return ret == ERROR_SUCCESS ? ret : ERROR_INSTALL_FAILURE;
}

struct file_id { DWORD volume, index_high, index_low; };

static bool calculate_file_id(const TCHAR *path, struct file_id *id)
{
	BY_HANDLE_FILE_INFORMATION file_info = { 0 };
	HANDLE file;
	bool ret;

	file = CreateFile(path, 0, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	ret = GetFileInformationByHandle(file, &file_info);
	CloseHandle(file);
	if (!ret)
		return false;
	id->volume = file_info.dwVolumeSerialNumber;
	id->index_high = file_info.nFileIndexHigh;
	id->index_low = file_info.nFileIndexLow;
	return true;
}

__declspec(dllexport) UINT __stdcall KillWireGuardProcesses(MSIHANDLE installer)
{
	HANDLE snapshot, process;
	PROCESSENTRY32 entry = { .dwSize = sizeof(PROCESSENTRY32) };
	TCHAR process_path[MAX_PATH], executable[MAX_PATH];
	DWORD process_path_len = _countof(process_path);
	struct file_id file_ids[3], file_id;
	size_t file_ids_len = 0;
	bool is_com_initialized = SUCCEEDED(CoInitialize(NULL));
	LSTATUS mret;

	mret = MsiGetProperty(installer, TEXT("CustomActionData"), process_path, &process_path_len);
	if (mret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_WARN, mret, TEXT("MsiGetProperty(\"CustomActionData\") failed"));
		goto out;
	}
	if (!process_path[0])
		goto out;

	log_messagef(installer, LOG_LEVEL_INFO, TEXT("Detecting running processes"));

	if (PathCombine(executable, process_path, TEXT("wg.exe")) && calculate_file_id(executable, &file_ids[file_ids_len]))
		++file_ids_len;
	if (PathCombine(executable, process_path, TEXT("wireguard.exe")) && calculate_file_id(executable, &file_ids[file_ids_len]))
		++file_ids_len;
	if (!file_ids_len)
		goto out;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		goto out;

	for (bool ret = Process32First(snapshot, &entry); ret; ret = Process32Next(snapshot, &entry)) {
		if (_tcsicmp(entry.szExeFile, TEXT("wireguard.exe")) && _tcsicmp(entry.szExeFile, TEXT("wg.exe")))
			continue;
		process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, entry.th32ProcessID);
		if (!process)
			continue;
		process_path_len = _countof(process_path);
		if (!QueryFullProcessImageName(process, 0, process_path, &process_path_len))
			goto next;
		if (!calculate_file_id(process_path, &file_id))
			goto next;
		ret = false;
		for (size_t i = 0; i < file_ids_len; ++i) {
			if (!memcmp(&file_id, &file_ids[i], sizeof(file_id))) {
				ret = true;
				break;
			}
		}
		if (!ret)
			goto next;
		if (TerminateProcess(process, STATUS_DLL_INIT_FAILED_LOGOFF)) {
			WaitForSingleObject(process, INFINITE);
			log_messagef(installer, LOG_LEVEL_INFO, TEXT("Killed \"%1\" (pid %2!d!)"), process_path, entry.th32ProcessID);
		}
	next:
		CloseHandle(process);
	}
	CloseHandle(snapshot);

out:
	if (is_com_initialized)
		CoUninitialize();
	return ERROR_SUCCESS;
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

__declspec(dllexport) UINT __stdcall RemoveConfigFolder(MSIHANDLE installer)
{
	LSTATUS ret;
	TCHAR path[MAX_PATH];
	DWORD path_len = _countof(path);
	bool is_com_initialized = SUCCEEDED(CoInitialize(NULL));

	ret = MsiGetProperty(installer, TEXT("CustomActionData"), path, &path_len);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_WARN, ret, TEXT("MsiGetProperty(\"CustomActionData\") failed"));
		goto out;
	}
	if (!path[0] || !PathAppend(path, TEXT("Data")))
		goto out;
	remove_directory_recursive(installer, path, 10);
	RegDeleteKey(HKEY_LOCAL_MACHINE, TEXT("Software\\WireGuard")); // Assumes no WOW.
out:
	if (is_com_initialized)
		CoUninitialize();
	return ERROR_SUCCESS;
}

__declspec(dllexport) UINT __stdcall RemoveAdapters(MSIHANDLE installer)
{
	UINT ret;
	bool is_com_initialized = SUCCEEDED(CoInitialize(NULL));
	TCHAR path[MAX_PATH];
	DWORD path_len = _countof(path);
	HANDLE pipe;
	char buf[0x200];
	DWORD offset = 0, size_read;
	PROCESS_INFORMATION pi;
	STARTUPINFO si = {
		.cb = sizeof(STARTUPINFO),
		.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
		.wShowWindow = SW_HIDE
	};

	ret = MsiGetProperty(installer, TEXT("CustomActionData"), path, &path_len);
	if (ret != ERROR_SUCCESS) {
		log_errorf(installer, LOG_LEVEL_WARN, ret, TEXT("MsiGetProperty(\"CustomActionData\") failed"));
		goto out;
	}
	if (!path[0] || !PathAppend(path, TEXT("wireguard.exe")))
		goto out;

	if (!CreatePipe(&pipe, &si.hStdOutput, NULL, 0)) {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("CreatePipe failed"));
		goto out;
	}
	if (!SetHandleInformation(si.hStdOutput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("SetHandleInformation failed"));
		goto cleanup_pipe_w;
	}
	if (!CreateProcess(path, TEXT("wireguard /removedriver"), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		log_errorf(installer, LOG_LEVEL_WARN, GetLastError(), TEXT("Failed to create \"%1\" process"), path);
		goto cleanup_pipe_w;
	}
	CloseHandle(si.hStdOutput);
	buf[sizeof(buf) - 1] = '\0';
	while (ReadFile(pipe, buf + offset, sizeof(buf) - offset - 1, &size_read, NULL)) {
		char *nl;
		buf[offset + size_read] = '\0';
		nl = strchr(buf, '\n');
		if (!nl) {
			offset = size_read;
			continue;
		}
		nl[0] = '\0';
		log_messagef(installer, LOG_LEVEL_INFO, TEXT("%1!hs!"), buf);
		offset = strlen(&nl[1]);
		memmove(buf, &nl[1], offset);
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	goto cleanup_pipe_r;

cleanup_pipe_w:
	CloseHandle(si.hStdOutput);
cleanup_pipe_r:
	CloseHandle(pipe);
out:
	if (is_com_initialized)
		CoUninitialize();
	return ERROR_SUCCESS;
}
