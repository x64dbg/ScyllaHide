@echo off
setlocal enableextensions
setlocal enabledelayedexpansion

@rem build release

cd %~dp0

set PROGRAMFILES32=%PROGRAMFILES(x86)%
if not exist "%PROGRAMFILES(x86)%" set PROGRAMFILES32=%PROGRAMFILES%

set VSWHERE=%PROGRAMFILES32%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
	echo VS2017/VS2019 installation directory does not exist, or the vswhere.exe tool is missing.
	exit
)

@rem Test if the vswhere tool is actually up to date enough to understand -find syntax (the one on Appveyor isn't)
"%VSWHERE%" -nologo -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 1>nul 2>&1
if not %ERRORLEVEL%==0 (
	@rem Fetch some version that gets it
	echo Fetching vswhere.exe...
	curl -O -L https://github.com/microsoft/vswhere/releases/download/2.6.7/vswhere.exe 1>nul
	set VSWHERE=vswhere.exe
)

set MSBUILD=
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -nologo -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
	set MSBUILD=%%i
)
del vswhere.exe 1>nul 2>&1

if "%MSBUILD%"=="" (
	echo Failed to find MSBuild installation directory.
	exit
)

@rem TODO: the following only works on Appveyor because the file is password protected, and is only needed for building the IDA plugin.
@rem This should be fixed so people who don't want to deal with this shit can still run this file to build the rest of ScyllaHide
echo Downloading IDA SDK...
curl -O -L https://github.com/x64dbg/ScyllaHide/releases/download/docs-2019-05-17/idasdk_password_protected_dont_bother.7z 1>nul
if not %ERRORLEVEL%==0 (
	echo Failed to fetch IDA SDK.
	exit
)

set SEVENZIP=%PROGRAMFILES%\7-Zip\7z.exe
if not exist "%SEVENZIP%" set SEVENZIP=%PROGRAMFILES32%\7-Zip\7z.exe
if not exist "%SEVENZIP%" (
	echo Missing 7-zip installation.
	exit
)

set PASSWORD=%APPVEYOR_ACCOUNT_NAME%%APPVEYOR_PROJECT_ID%%APPVEYOR_PROJECT_SLUG%%APPVEYOR_BUILD_FOLDER%
"%SEVENZIP%" x -y -p"%PASSWORD%" -o3rdparty idasdk_password_protected_dont_bother.7z 1>nul
if not %ERRORLEVEL%==0 (
	echo Failed to extract IDA SDK; the IDA plugin will fail to build.
)
del idasdk_password_protected_dont_bother.7z 1>nul 2>&1

"%MSBUILD%" /m /property:Configuration=Release,Platform=Win32
if not %ERRORLEVEL%==0 exit

"%MSBUILD%" /m /property:Configuration=Release,Platform=x64
if not %ERRORLEVEL%==0 exit

rmdir /S /Q Release
xcopy /S /Y ConfigCollection Release\

@rem plugins
mkdir Release\plugins
copy /y /b build\Release\Win32\ScyllaHideGenericPluginx86.dll Release\plugins
copy /y /b build\Release\x64\ScyllaHideGenericPluginx64.dll Release\plugins
copy /y /b build\Release\Win32\ScyllaHideOlly1Plugin.dll Release\plugins
copy /y /b build\Release\Win32\ScyllaHideOlly2Plugin.dll Release\plugins
copy /y /b build\Release\Win32\ScyllaHideTEPluginx86.dll Release\plugins
copy /y /b build\Release\x64\ScyllaHideTEPluginx64.dll Release\plugins
copy /y /b build\Release\Win32\ScyllaHideX64DBGPlugin.dp32 Release\plugins
copy /y /b build\Release\x64\ScyllaHideX64DBGPlugin.dp64 Release\plugins
copy /y /b build\Release\Win32\ScyllaHideIDAProPlugin.plw Release\plugins

@rem tools
xcopy /S /Y build\Release\Win32\*.exe Release
xcopy /S /Y build\Release\x64\*.exe Release
copy /y /b build\Release\Win32\HookLibraryx86.dll Release
copy /y /b build\Release\x64\HookLibraryx64.dll Release

rmdir /S /Q 3rdparty\idasdk 1>nul 2>&1
