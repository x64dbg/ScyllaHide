#include "HookHelper.h"
#include "HookedFunctions.h"
#include "HookMain.h"
#include <tlhelp32.h>
#include "ntdllext.h"

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

const WCHAR * BadWindowTextList[] = {
	L"OLLYDBG",
	L"ida",
	L"disassembly",
	L"scylla",
	L"Debug",
	L"[CPU",
	L"Immunity",
	L"Windbg",
	L"x32_dbg",
	L"x64_dbg",
	L"Windbg",
	L"Import reconstructor"
};

const WCHAR * BadWindowClassList[] = {
	L"OLLYDBG",
	L"Zeta Debugger",
	L"Rock Debugger",
	L"ObsidianGUI",
	L"ID", //Immunity Debugger
	L"WinDbgFrameClass", //WinDBG
	L"idawindow",
	L"tnavbox",
	L"idaview",
	L"tgrzoom"
};

extern HOOK_DLL_EXCHANGE DllExchange;
extern SAVE_DEBUG_REGISTERS ArrayDebugRegister[100];

bool IsProcessBad(PUNICODE_STRING process)
{
	WCHAR nameCopy[400];

	if (!process || process->Length == 0)
	{
		return false;
	}

	memset(nameCopy, 0, sizeof(nameCopy));

	if (process->Length > (sizeof(nameCopy)-sizeof(WCHAR)))
	{
		return false;
	}

	memcpy(nameCopy, process->Buffer, process->Length);

	for (int i = 0; i < _countof(BadProcessnameList); i++)
	{
		if (!lstrcmpiW(nameCopy, BadProcessnameList[i]))
		{
			return true;
		}
	}

	return false;
}

bool IsWindowClassBad(PUNICODE_STRING lpszClass)
{
	WCHAR nameCopy[400];

	if (!lpszClass || lpszClass->Length == 0)
	{
		return false;
	}

	memset(nameCopy, 0, sizeof(nameCopy));

	if (lpszClass->Length > (sizeof(nameCopy)-sizeof(WCHAR)))
	{
		return false;
	}
	memcpy(nameCopy, lpszClass->Buffer, lpszClass->Length);

	for (int i = 0; i < _countof(BadWindowClassList); i++)
	{
		if (wcsistr(nameCopy, BadWindowClassList[i]))
		{
			return true;
		}
	}

	return false;

}

bool IsWindowNameBad(PUNICODE_STRING lpszWindow)
{
	WCHAR nameCopy[400];

	if (!lpszWindow || lpszWindow->Length == 0)
	{
		return false;
	}

	memset(nameCopy, 0, sizeof(nameCopy));

	if (lpszWindow->Length > (sizeof(nameCopy)-sizeof(WCHAR)))
	{
		return false;
	}
	memcpy(nameCopy, lpszWindow->Buffer, lpszWindow->Length);

	for (int i = 0; i < _countof(BadWindowTextList); i++)
	{
		if (wcsistr(nameCopy, BadWindowTextList[i]))
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

OSVERSIONINFO versionInfo = { 0 };

bool IsAtleastVista()
{
	static bool isAtleastVista = false;
	static bool isSet = false;
	if (isSet)
		return isAtleastVista;
	versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
	GetVersionExW(&versionInfo);
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

	if (DllExchange.dNtQueryInformationProcess)
	{
		if (DllExchange.dNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
		{
			return (DWORD)pbi.UniqueProcessId;
		}
	}
	else
	{ //maybe not hooked
		if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
		{
			return (DWORD)pbi.UniqueProcessId;
		}
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

bool wcsistr(const wchar_t *s, const wchar_t *t)
{
	size_t l1 = _wcslen(s);
	size_t l2 = _wcslen(t);

	if (l1 < l2)
		return false;

	if (l1 == l2)
	{
		if (!_wcsicmp(s, t))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	for (int off = 0; off < (int)(l1 - l2); ++off)
	{
		if (!_wcsnicmp(s + off, t, l2))
			return true;
	}

	return false;
}

size_t _strlen(const char* sc)
{
	size_t count = 0;
	while (sc[count] != '\0')
		count++;
	return count;
}

size_t _wcslen(const wchar_t* sc)
{
	size_t count = 0;
	while (sc[count] != L'\0')
		count++;
	return count;
}

void ThreadDebugContextRemoveEntry(const int index)
{
	ArrayDebugRegister[index].dwThreadId = 0;
}

void ThreadDebugContextSaveContext(const int index, const PCONTEXT ThreadContext)
{
	ArrayDebugRegister[index].dwThreadId = GetCurrentThreadId();
	ArrayDebugRegister[index].Dr0 = ThreadContext->Dr0;
	ArrayDebugRegister[index].Dr1 = ThreadContext->Dr1;
	ArrayDebugRegister[index].Dr2 = ThreadContext->Dr2;
	ArrayDebugRegister[index].Dr3 = ThreadContext->Dr3;
	ArrayDebugRegister[index].Dr6 = ThreadContext->Dr6;
	ArrayDebugRegister[index].Dr7 = ThreadContext->Dr7;
}

int ThreadDebugContextFindExistingSlotIndex()
{
	for (int i = 0; i < _countof(ArrayDebugRegister); i++)
	{
		if (ArrayDebugRegister[i].dwThreadId != 0)
		{
			if (ArrayDebugRegister[i].dwThreadId == GetCurrentThreadId())
			{
				return i;
			}
		}
	}

	return -1;
}

int ThreadDebugContextFindFreeSlotIndex()
{
	for (int i = 0; i < _countof(ArrayDebugRegister); i++)
	{
		if (ArrayDebugRegister[i].dwThreadId == 0)
		{
			return i;
		}
	}

	return -1;
}