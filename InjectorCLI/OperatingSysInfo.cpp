#include "OperatingSysInfo.h"
#include "RemotePebHider.h"
#include "Logger.h"

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

const char * GetWindowsVersionNameA()
{
	GetWindowsVersion();

    if (currentOs == OS_WIN_XP)
	{
		return "Windows XP";
	}
	else if (currentOs == OS_WIN_XP64)
	{
		return "Windows XP 64 / Server 2003";
	}
	else if (currentOs == OS_WIN_VISTA)
	{
		return "Windows Vista / Server 2008";
	}
	else if (currentOs == OS_WIN_7)
	{
		return "Windows 7 / Server 2008 R2";
	}
	else if (currentOs == OS_WIN_8)
	{
		return "Windows 8 / Server 2012";
	}
	else if (currentOs == OS_WIN_81)
	{
		return "Windows 8.1 / Server 2012 R2";
	}
	else if (currentOs == OS_WIN_10)
	{
		return "Windows 10 / Server 2016";
	}

	return "Invalid Windows";
}

void GetPEBWindowsMajorMinorVersion(DWORD * major, DWORD * minor)
{
	PEB_CURRENT * currentPeb = (PEB_CURRENT *)calloc(sizeof(PEB_CURRENT), 1); 
	if (currentPeb)
	{
		ReadPebToBuffer(GetCurrentProcess(), (unsigned char *)currentPeb, sizeof(PEB_CURRENT));

		*major = currentPeb->OSMajorVersion;
		*minor = currentPeb->OSMinorVersion;

		free(currentPeb);
	}
	else
	{
		LogErrorBox("GetPEBWindowsMajorMinorVersion -> Failed to calloc");
	}
}

eOperatingSystem GetWindowsVersion()
{
	if (currentOs != OS_UNKNOWN)
	{
		return currentOs;
	}

	currentOs = OS_INVALID;

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
		else
		{
			//win 8.1 and win 10 are special...
			//Applications not manifested for Windows 8.1 or Windows 10 will return the Windows 8 OS version value (6.2)

			PEB_CURRENT * currentPeb = (PEB_CURRENT *)calloc(sizeof(PEB_CURRENT), 1); 
			ReadPebToBuffer(GetCurrentProcess(), (unsigned char *)currentPeb, sizeof(PEB_CURRENT));

			DWORD OSMajorVersion = 0;
			DWORD OSMinorVersion = 0;
			GetPEBWindowsMajorMinorVersion(&OSMajorVersion, &OSMinorVersion);

			if (OSMajorVersion == 10 && OSMinorVersion == 0)
			{
				currentOs = OS_WIN_10;
			}
			else if (OSMajorVersion == 6 && OSMinorVersion == 3)
			{
				currentOs = OS_WIN_81;
			}
			else if (osVersionInfo.dwMinorVersion == 2)
			{
				currentOs = OS_WIN_8;
			}

			free(currentPeb);
		}
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
	else
	{
		LogError("IsWow64Process not found");
	}

	return (bIsWow64 != FALSE);
}


bool _IsWindows8Point1OrGreater()
{
	if (GetWindowsVersion() == OS_WIN_81 || 
		GetWindowsVersion() == OS_WIN_10)
	{
		return true;
	}

	return false;
}

bool _IsWindows10OrGreater()
{
	if (GetWindowsVersion() == OS_WIN_10)
	{
		return true;
	}

	return false;
}
