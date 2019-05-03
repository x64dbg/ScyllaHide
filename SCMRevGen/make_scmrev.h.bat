@echo off

set GIT_VERSION_NUMBER=0 
set GIT_SHORT_HASH=unknown

where git 1>nul 2>&1
if errorlevel 1 goto :nogit

for /f "usebackq delims=" %%i in (`git rev-list --count HEAD`) do (
	set GIT_VERSION_NUMBER=%%i
)
for /f "usebackq delims=" %%i in (`git rev-parse --short HEAD`) do (
	set GIT_SHORT_HASH=%%i
)

:nogit
set COMPILE_DATE=
for /f "usebackq delims=" %%i in (`date.exe +^"%%F %%H:%%M^"`) do (
	set COMPILE_DATE=%%i
)
set COMPILE_YEAR=
for /f "usebackq delims=" %%i in (`date.exe +^"%%Y^"`) do (
	set COMPILE_YEAR=%%i
)

echo #pragma once> scmrev.h
echo.>> scmrev.h
echo #define GIT_VERSION_NUMBER %GIT_VERSION_NUMBER%>> scmrev.h
echo #define GIT_SHORT_HASH_A "%GIT_SHORT_HASH%">> scmrev.h
echo #define GIT_SHORT_HASH_W L"%GIT_SHORT_HASH%">> scmrev.h
echo #define COMPILE_DATE_A "%COMPILE_DATE%">> scmrev.h
echo #define COMPILE_DATE_W L"%COMPILE_DATE%">> scmrev.h
echo #define COMPILE_YEAR_A "%COMPILE_YEAR%">> scmrev.h
echo #define COMPILE_YEAR_W L"%COMPILE_YEAR%">> scmrev.h
