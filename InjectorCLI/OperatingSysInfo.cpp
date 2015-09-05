#include "OperatingSysInfo.h"

typedef void (WINAPI *tGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
typedef BOOL (WINAPI * tIsWow64Process)(HANDLE hProcess,PBOOL Wow64Process);

tGetNativeSystemInfo _GetNativeSystemInfo = 0;
tIsWow64Process fnIsWow64Process = 0;

#ifndef _WIN32_WINNT_WINBLUE
#define _WIN32_WINNT_WINBLUE 0x0603
#endif

#ifndef _WIN32_WINNT_WIN10
#define _WIN32_WINNT_WIN10 0x0A00
#endif

bool _IsWindows8Point1OrGreater();
bool _IsWindows10OrGreater();
bool _IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor);

/*

Operating system	Version number
Windows 10	10.0*
Windows Server 2016	10.0*
Windows 8.1	6.3*
Windows Server 2012 R2	6.3*
Windows 8	6.2
Windows Server 2012	6.2
Windows 7	6.1
Windows Server 2008 R2	6.1
Windows Server 2008	6.0
Windows Vista	6.0
Windows Server 2003 R2	5.2
Windows Server 2003	5.2
Windows XP 64-Bit Edition	5.2
Windows XP	5.1
Windows 2000	5.0
*/

eOperatingSystem currentOs = OS_UNKNOWN;

char * GetWindowsVersionNameA()
{
	GetWindowsVersion();

	if (currentOs == OS_UNKNOWN)
	{
		return "Unknown";
	}
	else if (currentOs == OS_WIN_XP)
	{
		return "Windows XP";
	}
	else if (currentOs == OS_WIN_XP64)
	{
		return "Windows XP 64";
	}
	else if (currentOs == OS_WIN_VISTA)
	{
		return "Windows Vista";
	}
	else if (currentOs == OS_WIN_7)
	{
		return "Windows 7";
	}
	else if (currentOs == OS_WIN_8)
	{
		return "Windows 8";
	}
	else if (currentOs == OS_WIN_81)
	{
		return "Windows 8.1";
	}
	else if (currentOs == OS_WIN_10)
	{
		return "Windows 10";
	}

	return "Invalid";
}

eOperatingSystem GetWindowsVersion()
{
	if (currentOs != OS_UNKNOWN)
	{
		return currentOs;
	}

	OSVERSIONINFOEXW osVersionInfo = {0};
	osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

	if (!GetVersionExW((OSVERSIONINFOW*) &osVersionInfo))
	{
		MessageBoxA(0, "GetVersionExW failed", "ERROR", MB_ICONERROR);
	}

	if (osVersionInfo.dwMajorVersion == 5)
	{
		if (osVersionInfo.dwMinorVersion == 0)
		{
			currentOs = OS_WIN_2000;
		}
		else if (osVersionInfo.dwMinorVersion == 1)
		{
			currentOs = OS_WIN_XP;
		}
		else if (osVersionInfo.dwMinorVersion == 2)
		{
			currentOs = OS_WIN_XP64;
		}
	}
	else if (osVersionInfo.dwMajorVersion == 6)
	{
		if (osVersionInfo.dwMinorVersion == 0)
		{
			currentOs = OS_WIN_VISTA;
		}
		else if (osVersionInfo.dwMinorVersion == 1)
		{
			currentOs = OS_WIN_7;
		}
		else if (osVersionInfo.dwMinorVersion == 2)
		{
			currentOs = OS_WIN_8;
		}
		else
		{
			//win 8.1 and win 10 are special...
			if (_IsWindows10OrGreater())
			{
				currentOs = OS_WIN_10;
			}
			else if (_IsWindows8Point1OrGreater())
			{
				currentOs = OS_WIN_81;
			}
			else
			{
				currentOs = OS_INVALID;
			}
		}
	}
	else
	{
		currentOs = OS_INVALID;
	}

	return currentOs;
}

bool IsSysWow64()
{
#ifdef _WIN64
	return false;
#else
	return isWindows64();
#endif
}



bool isWindows64()
{
	SYSTEM_INFO si = {0};

	if (!_GetNativeSystemInfo)
	{
		_GetNativeSystemInfo = (tGetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetNativeSystemInfo");
	}

	if (_GetNativeSystemInfo)
	{
		_GetNativeSystemInfo(&si);
	}
	else
	{
		GetSystemInfo(&si);
	}

	return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}

bool IsProcessWOW64(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;
	if (!fnIsWow64Process)
	{
		fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
	}


	if (fnIsWow64Process)
	{
		fnIsWow64Process(hProcess, &bIsWow64);
	}

	return (bIsWow64 != FALSE);
}

bool _IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
		VerSetConditionMask(
		0, VER_MAJORVERSION, VER_GREATER_EQUAL),
		VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
}

bool _IsWindows8Point1OrGreater()
{
	return _IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WINBLUE), LOBYTE(_WIN32_WINNT_WINBLUE), 0);
}

bool _IsWindows10OrGreater()
{
	return _IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0);
}
