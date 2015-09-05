#pragma once

#include <windows.h>

bool isWindows64();
bool IsProcessWOW64(HANDLE hProcess);
bool IsSysWow64();

enum eOperatingSystem {
	OS_UNKNOWN,
	OS_INVALID,
	OS_WIN_2000,
	OS_WIN_XP,
	OS_WIN_XP64,
	OS_WIN_VISTA, 
	OS_WIN_7, 
	OS_WIN_8, 
	OS_WIN_81, 
	OS_WIN_10
};

eOperatingSystem GetWindowsVersion();
const char * GetWindowsVersionNameA();
