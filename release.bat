@echo off
setlocal enabledelayedexpansion

cd %~dp0

@rem build release
set VSWHERE=%PROGRAMFILES(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
	echo VS2017/VS2019 installation directory does not exist, or the vswhere.exe tool is missing.
	exit
)

set MSBUILD=
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
	set MSBUILD=%%i
)

if "%MSBUILD%"=="" (
	echo Failed to find MSBuild installation directory.
	exit
)

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
