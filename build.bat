@echo off
set STARTDIR=%cd%
set OLDPATH=%PATH%
if not exist deps\.prepared call :installdeps
set PATH=%STARTDIR%\deps\tdm\bin\;%STARTDIR%\deps\go\bin\;%PATH%
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
	echo Downloading gcc
	curl -#Lo gcc.zip https://sourceforge.net/projects/tdm-gcc/files/TDM-GCC%%205%%20series/5.1.0-tdm64-1/gcc-5.1.0-tdm64-1-core.zip || goto :error
	echo Downloading binutils
	curl -#Lo binutils.zip https://sourceforge.net/projects/tdm-gcc/files/GNU%%20binutils/binutils-2.25-tdm64-1.zip || goto :error
	echo Downloading mingw64rt
	curl -#Lo mingw64rt.zip https://sourceforge.net/projects/tdm-gcc/files/MinGW-w64%%20runtime/GCC%%205%%20series/mingw64runtime-v4-git20150618-gcc5-tdm64-1.zip
	echo Extracting golang
	tar -xf go.zip || goto :error
	mkdir tdm || goto :error
	cd tdm || goto :error
	echo Extracting gcc
	tar -xf ..\gcc.zip || goto :error
	echo Extracting binutils
	tar -xf ..\binutils.zip || goto :error
	echo Extracting mingw64rt
	tar -xf ..\mingw64rt.zip || goto :error
	cd .. || goto :error
	echo Cleaning up
	del go.zip gcc.zip binutils.zip mingw64rt.zip || goto :error
	copy /y NUL .prepared > NUL || goto :error
	cd .. || goto :error
	exit /b

:error
	echo Failed with error #%errorlevel%.
:out
	set PATH=%OLDPATH%
	cd %STARTDIR%
	exit /b %errorlevel%
