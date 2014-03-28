#include "HookHelper.h"
#include "ntdll.h"
#include <tlhelp32.h>

const WCHAR * BadProcessnameList[] = {
	L"ollydbg.exe",
	L"idag.exe",
	L"idag64.exe",
	L"idaw.exe",
	L"idaw64.exe",
	L"scylla.exe",
	L"scylla_x64.exe",
	L"scylla_x86.exe",
	L"protection_id.exe",
	L"x64_dbg.exe",
	L"windbg.exe",
	L"reshacker.exe",
	L"ImportREC.exe",
	L"IMMUNITYDEBUGGER.EXE"
};

const WCHAR * BadWindowList[] = {
	L"OLLYDBG",
	L"Zeta Debugger",
	L"Rock Debugger",
	L"ObsidianGUI",
	L"ID", //Immunity Debugger
	L"WinDbgFrameClass" //WinDBG
};

extern t_NtQueryInformationProcess dNtQueryInformationProcess;
extern t_NtQueryObject dNtQueryObject;

bool IsProcessBad(const WCHAR * name, int nameSizeInBytes)
{
	WCHAR nameCopy[400] = { 0 };

	if (!name || !nameSizeInBytes)
	{
		return false;
	}

	memcpy(nameCopy, name, nameSizeInBytes);

	for (int i = 0; i < _countof(BadProcessnameList); i++)
	{
		if (!lstrcmpiW(nameCopy, BadProcessnameList[i]))
		{
			return true;
		}
	}

	return false;
}

bool IsValidProcessHandle(HANDLE hProcess)
{
	if (hProcess == 0)
	{
		return false;
	}
	else if (hProcess == NtCurrentProcess)
	{
		return true;
	}
	else
	{
		return IsValidHandle(hProcess);
	}
}

bool IsValidThreadHandle(HANDLE hThread)
{
	if (hThread == 0)
	{
		return false;
	}
	else if (hThread == NtCurrentThread)
	{
		return true;
	}
	else
	{
		return IsValidHandle(hThread);
	}
}

bool IsAtleastVista()
{
	static bool isAtleastVista = false;
	static bool isSet = false;
	if (isSet)
		return isAtleastVista;
	OSVERSIONINFO versionInfo = { 0 };
	versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&versionInfo);
	isAtleastVista = versionInfo.dwMajorVersion >= 6;
	isSet = true;
	return isAtleastVista;
}

bool IsValidHandle(HANDLE hHandle)
{
	//return !!GetHandleInformation(hThread, &flags); //calls NtQueryObject ObjectHandleFlagInformation
	ULONG retLen = 0;
	OBJECT_HANDLE_FLAG_INFORMATION flags;
	flags.ProtectFromClose = 0;
	flags.Inherit = 0;
	return NtQueryObject(hHandle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), &retLen) >= 0;
}


DWORD GetProcessIdByProcessHandle(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;

	if (dNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
	{
		return (DWORD)pbi.UniqueProcessId;
	}
	
	return 0;
}

DWORD GetThreadIdByThreadHandle(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION tbi;

	if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0)))
	{
		return (DWORD)tbi.ClientId.UniqueThread;
	}

	return 0;
}

DWORD GetProcessIdByThreadHandle(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION tbi;

	if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0)))
	{
		return (DWORD)tbi.ClientId.UniqueProcess;
	}

	return 0;
}

static DWORD dwExplorerPid = 0;

DWORD GetExplorerProcessId()
{
	if (!dwExplorerPid)
	{
		dwExplorerPid = GetProcessIdByName(L"explorer.exe");
	}
	return dwExplorerPid;
}

DWORD GetCsrssProcessId()
{
	return GetProcessIdByName(L"csrss.exe");
}

DWORD GetProcessIdByName(const WCHAR * processName)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}

	DWORD pid = 0;

	do
	{
		if (!lstrcmpiW(pe32.szExeFile, processName))
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return pid;
}