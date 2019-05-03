#include "OsInfo.h"
#include "Peb.h"

/**
 * Operating system                Version number
 * Windows 10                      10.0*
 * Windows Server 2016             10.0*
 * Windows 8.1                     6.3*
 * Windows Server 2012 R2          6.3*
 * Windows 8                       6.2
 * Windows Server 2012             6.2
 * Windows 7                       6.1
 * Windows Server 2008 R2          6.1
 * Windows Server 2008             6.0
 * Windows Vista                   6.0
 * Windows Server 2003 R2          5.2
 * Windows Server 2003             5.2
 * Windows XP 64-Bit Edition       5.2
 * Windows XP                      5.1
 * Windows 2000                    5.0
 */

const SYSTEM_INFO *scl::GetNativeSystemInfo()
{
    static SYSTEM_INFO si = { 0 };
    static auto cached = false;

    if (!cached)
    {
        ::GetNativeSystemInfo(&si);
        cached = true;
    }

    return &si;
}

const RTL_OSVERSIONINFOEXW* scl::GetVersionExW()
{
    static RTL_OSVERSIONINFOEXW osVerInfo = { 0 };
    static auto cached = false;

    if (!cached)
    {
        osVerInfo.dwOSVersionInfoSize = sizeof(osVerInfo);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osVerInfo);
        auto peb = GetPebAddress(GetCurrentProcess());
        if (peb)
        {
            osVerInfo.dwMajorVersion = peb->OSMajorVersion;
            osVerInfo.dwMinorVersion = peb->OSMinorVersion;
        }
        cached = true;
    }

    return &osVerInfo;
}

bool scl::IsWindows64()
{
#ifdef _WIN64
    return true;
#else
    return (GetNativeSystemInfo()->wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
#endif
}

bool scl::IsWow64Process(HANDLE hProcess)
{
    auto fIsWow64 = FALSE;
    return ::IsWow64Process(hProcess, &fIsWow64) && (fIsWow64 == TRUE);
}


scl::eOsVersion scl::GetWindowsVersion()
{
    static auto version = OS_UNKNOWN;

    if (version != OS_UNKNOWN)
        return version;

    version = OS_INVALID;

    const auto osVerInfo = GetVersionExW();

    if (osVerInfo->dwMajorVersion == 5)
    {
        if (osVerInfo->dwMinorVersion == 0)
        {
            version = OS_WIN_2000;
        }
        else if (osVerInfo->dwMinorVersion == 1)
        {
            version = OS_WIN_XP;
        }
        else if (osVerInfo->dwMinorVersion == 2)
        {
            version = OS_WIN_XP64;
        }
    }
    else if (osVerInfo->dwMajorVersion == 6)
    {
        if (osVerInfo->dwMinorVersion == 0)
        {
            version = OS_WIN_VISTA;
        }
        else if (osVerInfo->dwMinorVersion == 1)
        {
            version = OS_WIN_7;
        }
        else if (osVerInfo->dwMinorVersion == 2)
        {
            version = OS_WIN_8;
        }
        else if (osVerInfo->dwMinorVersion == 3)
        {
            version = OS_WIN_81;
        }
    }
    else if (osVerInfo->dwMajorVersion == 10) {
        if (osVerInfo->dwMinorVersion == 0) {
            version = OS_WIN_10;
        }
    }

    return version;
}

const char *scl::GetWindowsVersionNameA()
{
    switch (GetWindowsVersion())
    {
    case OS_WIN_XP:
        return "Windows XP";
    case OS_WIN_XP64:
        return "Windows XP 64 / Server 2003";
    case OS_WIN_VISTA:
        return "Windows Vista / Server 2008";
    case OS_WIN_7:
        return "Windows 7 / Server 2008 R2";
    case OS_WIN_8:
        return "Windows 8 / Server 2012";
    case OS_WIN_81:
        return "Windows 8.1 / Server 2012 R2";
    case OS_WIN_10:
        return "Windows 10 / Server 2016";
    default:
        return "Unknown Windows";
    }
}
