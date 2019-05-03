#pragma once

#include <windows.h>

namespace scl
{
    enum eOsVersion {
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

    const SYSTEM_INFO *GetNativeSystemInfo();
    const RTL_OSVERSIONINFOEXW* GetVersionExW();

    bool IsWindows64();
    bool IsWow64Process(HANDLE hProcess);
    eOsVersion GetWindowsVersion();
    const char *GetWindowsVersionNameA();
}
