@echo off
rem SPDX-License-Identifier: MIT
rem rem Copyright (C) 2019 WireGuard LLC. All Rights Reserved.

echo [+] Building wireguard.exe
call .\build.bat || exit /b 1
echo [+] Building installer
cd .\installer
call .\build.bat || exit /b 1
echo [+] Uninstalling old versions
for /f %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s /d /c /e /f WireGuard ^| findstr CurrentVersion\Uninstall') do msiexec /qb /x %%~na
echo [+] Installing new version
for /f "tokens=3" %%a in ('findstr /r "[0-9.]*" ..\version.h') do set WIREGUARD_VERSION=%%a
set WIREGUARD_VERSION=%WIREGUARD_VERSION:"=%
@echo on
cd .\dist
msiexec /qb /i wireguard-amd64-%WIREGUARD_VERSION%.msi
cd ..\..
