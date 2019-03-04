@echo off
set STARTDIR=%cd%
set OLDPATH=%PATH%
if not exist deps\.prepared call :installdeps
set PATH=%STARTDIR%\deps\x86_64-w64-mingw32-native\bin\;%STARTDIR%\deps\go\bin\;%PATH%
set CC=x86_64-w64-mingw32-gcc.exe
set GOOS=windows
set GOARCH=amd64
set GOPATH=%STARTDIR%\deps\gopath
set GOROOT=%STARTDIR%\deps\go
set CGO_ENABLED=1
echo Assembling resources
go run github.com/akavel/rsrc -manifest ui/manifest.xml -ico ui/icon/icon.ico -arch amd64 -o resources.syso || goto :error
echo Building program
go build -ldflags="-H windowsgui" -o wireguard.exe || goto :error
goto :out

:installdeps
	rmdir /s /q deps 2> NUL
	mkdir deps || goto :error
	cd deps || goto :error
	echo Downloading golang
	curl -#o go.zip https://dl.google.com/go/go1.12.windows-amd64.zip || goto :error
	echo Downloading mingw
	curl -#o mingw.tar.gz http://musl.cc/x86_64-w64-mingw32-native.tgz || goto :error
	echo Extracting golang
	tar -xf go.zip || goto :error
	echo Extracting gcc
	rem We don't goto error here because the symlinks make it always fail
	tar -xf mingw.tar.gz
	move x86_64-w64-mingw32-native/include x86_64-w64-mingw32-native/x86_64-w64-mingw32/ > NUL || goto :error
	echo Cleaning up
	del go.zip mingw.tar.gz || goto :error
	copy /y NUL .prepared > NUL || goto :error
	cd .. || goto :error
	exit /b

:error
	echo Failed with error #%errorlevel%.
:out
	set PATH=%OLDPATH%
	cd %STARTDIR%
	exit /b %errorlevel%
