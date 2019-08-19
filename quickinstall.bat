@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

setlocal
cd /d %~dp0 || exit /b 1
echo [+] Building wireguard.exe
call .\build.bat || exit /b 1
echo [+] Building installer
call .\installer\build.bat || exit /b 1
echo [+] Uninstalling old versions
for /f %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s /d /c /e /f WireGuard ^| findstr CurrentVersion\Uninstall') do msiexec /qb /x %%~na
echo [+] Installing new version
for /f "tokens=3" %%a in ('findstr /r "WIREGUARD_WINDOWS_VERSION_STRING.*[0-9.]*" .\version.h') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%
msiexec /qb /i installer\dist\wireguard-%PROCESSOR_ARCHITECTURE%-%WIREGUARD_VERSION%.msi
