@echo off
setlocal enableextensions
setlocal enabledelayedexpansion

@rem build release

cd %~dp0

@rem We still support Windows XP in our release builds, and probably will continue to do so for the foreseeable future.
@rem This is controlled by the following env var. Because we don't expect that regular users will want to target XP in their
@rem private local builds, in the normal case (opening VS) this will not be set and the minimum target version is Windows 7.
@rem If you want to make such a "release build", but without XP support and the toolchain requirements that come with it,
@rem call this with USE_XP_TOOLCHAIN set to FALSE
@rem
@rem 'TRUE' is the default value so that if a commit or PR breaks XP compatibility, it will be caught by Github Actions because it runs this build as a CI step.
@rem
@rem The most important (probably not installed on your machine) requirement to build with XP support enabled is *VS2019* with the latest *14.27* VC++ toolchain.
@rem The installer calls this the "16.7 toolchain", the compiler/CRT files themselves are versioned "14.27".
if "%USE_XP_TOOLCHAIN%"=="" (
	set USE_XP_TOOLCHAIN=TRUE
)

set PROGRAMFILES32=%PROGRAMFILES(x86)%
if not exist "%PROGRAMFILES(x86)%" set PROGRAMFILES32=%PROGRAMFILES%

set VSWHERE=%PROGRAMFILES32%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
	echo VS2017/VS2019 installation directory does not exist, or the vswhere.exe tool is missing.
	exit /b
)

@rem Test if the vswhere tool is actually up to date enough to understand -find syntax (the one on Appveyor isn't)
"%VSWHERE%" -nologo -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 1>nul 2>&1
if not %ERRORLEVEL%==0 (
	@rem Fetch some version that gets it
	echo Fetching vswhere.exe...
	curl -O -L https://github.com/microsoft/vswhere/releases/download/3.1.1/vswhere.exe 1>nul
	set VSWHERE=vswhere.exe
)
set MSBUILD=
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -nologo -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
	set MSBUILD=%%i
)
set XPTOOLCHAIN_INSTALLED=
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -nologo -version [16.0^,17^) -requires Microsoft.VisualStudio.Component.VC.14.27.x86.x64`) do (
	set XPTOOLCHAIN_INSTALLED=%%i
)
set VS2019INSTALLDIR=
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -nologo -version [16.0^,17^) -property installationPath`) do (
	set VS2019INSTALLDIR=%%i
)
set VS2019SETUP=
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -nologo -version [16.0^,17^) -property properties_setupEngineFilePath`) do (
	set VS2019SETUP=%%i
)
del vswhere.exe 1>nul 2>&1

if "%MSBUILD%"=="" (
	echo Failed to find MSBuild installation directory.
	exit /b
)
@rem Alternatively if github continues to fuck this up, we can curl the latest VS2019 setup from the hardcoded URL https://aka.ms/vs/16/release/vs_enterprise.exe
if "%USE_XP_TOOLCHAIN%"=="TRUE" (
	if "%VS2019INSTALLDIR%"=="" (
		echo XP toolchain build was requested, but VS2019 install dir could not be found. Set USE_XP_TOOLCHAIN to something other than TRUE if you don't actually need it.
		exit /b
	)
	if "%XPTOOLCHAIN_INSTALLED%"=="" (
		if "%VS2019SETUP%"=="" (
			echo XP toolchain build was requested, but VS2019 setup.exe could not be found. Set USE_XP_TOOLCHAIN to something other than TRUE if you don't actually need it.
			exit /b
		)
		echo Sorry buddy, but you need some more VS stuff. Installing it for you now, don't worry. We're gonna take care of this for ya...
		@rem Despite '--quiet', this command is not actually quiet. AT ALL. Redirect stdout spam
		"%VS2019SETUP%" modify --installPath "%VS2019INSTALLDIR%" --add "Microsoft.VisualStudio.Component.VC.14.27.x86.x64" --add "Microsoft.VisualStudio.Component.VC.14.27.MFC" --add "Microsoft.VisualStudio.Component.VC.14.27.ATL" --norestart --force --quiet 1>nul
		if not %ERRORLEVEL%==0 (
			echo Installation failed!
			exit /b
		)
		echo Installation successful.
	)
	@rem Finally, ascend to 14.27 toolchain environment
	call "%VS2019INSTALLDIR%\VC\Auxiliary\Build\vcvarsall.bat" amd64 -vcvars_ver=14.27
)

"%MSBUILD%" /m /property:Configuration=Release,Platform=Win32
if not %ERRORLEVEL%==0 exit /b

"%MSBUILD%" /m /property:Configuration=Release,Platform=x64
if not %ERRORLEVEL%==0 exit /b

rmdir /S /Q Release
xcopy /S /Y ConfigCollection Release\

@rem Release structure
mkdir Release\x64dbg\x32\plugins
mkdir Release\x64dbg\x64\plugins
mkdir Release\Olly1
mkdir Release\Olly2
mkdir Release\TitanEngine
mkdir Release\Generic
mkdir Release\IDA

copy /y /b build\Release\Win32\ScyllaHideGenericPluginx86.dll Release\Generic\
copy /y /b build\Release\x64\ScyllaHideGenericPluginx64.dll Release\Generic\
copy /y /b build\Release\Win32\ScyllaHideOlly1Plugin.dll Release\Olly1\
copy /y /b build\Release\Win32\ScyllaHideOlly2Plugin.dll Release\Olly2\
copy /y /b build\Release\Win32\ScyllaHideTEPluginx86.dll Release\TitanEngine\
copy /y /b build\Release\x64\ScyllaHideTEPluginx64.dll Release\TitanEngine\
copy /y /b build\Release\Win32\ScyllaHideX64DBGPlugin.dp32 Release\x64dbg\x32\plugins\
copy /y /b build\Release\x64\ScyllaHideX64DBGPlugin.dp64 Release\x64dbg\x64\plugins\
copy /y /b build\Release\Win32\ScyllaHideIDAProPlugin.plw Release\IDA\

xcopy /S /Y build\Release\Win32\*.exe Release\
xcopy /S /Y build\Release\x64\*.exe Release\
copy /y /b build\Release\Win32\HookLibraryx86.dll Release\
copy /y /b build\Release\x64\HookLibraryx64.dll Release\

copy /y /b Release\HookLibraryx64.dll Release\x64dbg\x64\plugins\
copy /y /b Release\HookLibraryx86.dll Release\x64dbg\x32\plugins\
copy /y /b Release\scylla_hide.ini Release\x64dbg\x64\plugins\
copy /y /b Release\scylla_hide.ini Release\x64dbg\x32\plugins\

copy /y /b Release\scylla_hide.ini Release\Olly1\
copy /y /b Release\HookLibraryx86.dll Release\Olly1\

copy /y /b Release\scylla_hide.ini Release\Olly2\
copy /y /b Release\HookLibraryx86.dll Release\Olly2\

copy /y /b Release\scylla_hide.ini Release\TitanEngine\
copy /y /b Release\HookLibraryx64.dll Release\TitanEngine\
copy /y /b Release\HookLibraryx86.dll Release\TitanEngine\

copy /y /b Release\scylla_hide.ini Release\Generic\
copy /y /b Release\HookLibraryx64.dll Release\Generic\
copy /y /b Release\HookLibraryx86.dll Release\Generic\

copy /y /b Release\scylla_hide.ini Release\IDA\
copy /y /b Release\HookLibraryx64.dll Release\IDA\
copy /y /b Release\HookLibraryx86.dll Release\IDA\
move Release\ScyllaHideIDAServer* Release\IDA\

exit 0