@echo off

@rem build release
call "%VS120COMNTOOLS%vsvars32.bat"
msbuild /m /property:Configuration=Release,Platform=Win32
msbuild /m /property:Configuration=Release,Platform=x64

rmdir /S /Q Release
xcopy /S /Y ConfigCollection Release\

@rem PDBReader tool
copy /y /b build\Release\Win32\PDBReaderx86.exe Release\NtApiTool\x86
copy /y /b build\Release\x64\PDBReaderx64.exe Release\NtApiTool\x64

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
del /F /Q Release\PdbReader*.exe