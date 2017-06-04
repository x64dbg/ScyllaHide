#include "HookHelper.h"

#include <tlhelp32.h>
#include <ntdll/ntdll.h>

#include "HookedFunctions.h"
#include "HookMain.h"

const WCHAR * BadProcessnameList[] =
{
	L"ollydbg.exe",
	L"idag.exe",
	L"idag64.exe",
	L"idaw.exe",
	L"idaw64.exe",
	L"scylla.exe",
	L"scylla_x64.exe",
	L"scylla_x86.exe",
	L"protection_id.exe",
	L"x64dbg.exe",
    L"x32dbg.exe",
	L"windbg.exe",
	L"reshacker.exe",
	L"ImportREC.exe",
	L"IMMUNITYDEBUGGER.EXE"
};

const WCHAR * BadWindowTextList[] =
{
	L"OLLYDBG",
	L"ida",
	L"disassembly",
	L"scylla",
	L"Debug",
	L"[CPU",
	L"Immunity",
	L"Windbg",
	L"x32dbg",
	L"x64dbg",
	L"Windbg",
	L"Import reconstructor"
};

const WCHAR * BadWindowClassList[] =
{
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

extern HOOK_DLL_DATA HookDllData;
extern SAVE_DEBUG_REGISTERS ArrayDebugRegister[100];

bool IsProcessBad(PUNICODE_STRING process)
{
	WCHAR nameCopy[400];

	if (!process || process->Length == 0 || !process->Buffer)
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
		if (_wcsicmp(nameCopy, BadProcessnameList[i]) == 0)
		{
			return true;
		}
	}

	return false;
}

bool IsWindowClassBad(PUNICODE_STRING lpszClass)
{
	WCHAR nameCopy[400];

	if (!lpszClass || lpszClass->Length == 0 || !lpszClass->Buffer)
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

	if (!lpszWindow || lpszWindow->Length == 0 || !lpszWindow->Buffer)
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

static LUID ConvertLongToLuid(LONG value)
{
	LUID luid;
	LARGE_INTEGER largeInt;
	largeInt.QuadPart = value;
	luid.LowPart = largeInt.LowPart;
	luid.HighPart = largeInt.HighPart;
	return luid;
}

bool HasDebugPrivileges(HANDLE hProcess)
{
	HANDLE hToken;
	NTSTATUS status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (!NT_SUCCESS(status))
		return false;

	const LONG SE_DEBUG_PRIVILEGE = 20;
	const LUID SeDebugPrivilege = ConvertLongToLuid(SE_DEBUG_PRIVILEGE);

	PRIVILEGE_SET privilegeSet;
	privilegeSet.PrivilegeCount = 1;
	privilegeSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privilegeSet.Privilege[0].Luid = SeDebugPrivilege;
	privilegeSet.Privilege[0].Attributes = 0;

	BOOLEAN hasDebugPrivileges = FALSE;
	NtPrivilegeCheck(hToken, &privilegeSet, &hasDebugPrivileges);

	NtClose(hToken);
	return hasDebugPrivileges == TRUE;
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

void * GetPEBRemote(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;

	if (HookDllData.dNtQueryInformationProcess)
	{
		if (HookDllData.dNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
		{
			return pbi.PebBaseAddress;
		}
	}
	else
	{
		//maybe not hooked
		if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
		{
			return pbi.PebBaseAddress;
		}
	}


	return 0;
}


DWORD GetProcessIdByProcessHandle(HANDLE hProcess)
{
	PROCESS_BASIC_INFORMATION pbi;

	if (HookDllData.dNtQueryInformationProcess)
	{
		if (HookDllData.dNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
		{
			return (ULONG)pbi.UniqueProcessId;
		}
	}
	else
	{
		//maybe not hooked
		if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
		{
			return (ULONG)pbi.UniqueProcessId;
		}
	}


	return 0;
}

DWORD GetThreadIdByThreadHandle(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION tbi;

	if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0)))
	{
		return HandleToULong(tbi.ClientId.UniqueThread);
	}

	return 0;
}

DWORD GetProcessIdByThreadHandle(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION tbi;

	if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0)))
	{
		return HandleToULong(tbi.ClientId.UniqueProcess);
	}

	return 0;
}

void TerminateProcessByProcessId(DWORD dwProcess)
{
	if (dwProcess)
	{
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, dwProcess);
		if (hProcess)
		{
			TerminateProcess(hProcess, 0);
			NtClose(hProcess);
		}
	}
}

DWORD dwExplorerPid = 0;
WCHAR ExplorerProcessName[] = L"explorer.exe";

DWORD GetExplorerProcessId()
{
	if (!dwExplorerPid)
	{
		dwExplorerPid = GetProcessIdByName(ExplorerProcessName);
	}
	return dwExplorerPid;
}

DWORD GetProcessIdByName(const WCHAR * processName)
{
	ULONG size;
	if (NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size) != STATUS_INFO_LENGTH_MISMATCH)
		return 0;
	PSYSTEM_PROCESS_INFORMATION systemProcessInfo =
		static_cast<PSYSTEM_PROCESS_INFORMATION>(RtlAllocateHeap(RtlProcessHeap(), 0, 2 * size));
	NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation,
												systemProcessInfo,
												2 * size,
												nullptr);
	if (!NT_SUCCESS(status))
		return 0;

	DWORD pid = 0;
	PSYSTEM_PROCESS_INFORMATION process = systemProcessInfo;
	while (process->NextEntryOffset != 0)
	{
		if (process->ImageName.Buffer != nullptr &&
			_wcsicmp(process->ImageName.Buffer, processName) == 0)
		{
			pid = HandleToULong(process->UniqueProcessId);
			break;
		}
		process = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)process + process->NextEntryOffset);
	}

	RtlFreeHeap(RtlProcessHeap(), 0, systemProcessInfo);
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

wchar_t * _wcscat(wchar_t *dest, const wchar_t *src)
{
	wchar_t *ret = dest;
	while (*dest)
		dest++;
	while (*dest++ = *src++)
		;
	return ret;
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

void IncreaseSystemTime(LPSYSTEMTIME lpTime)
{
	lpTime->wMilliseconds++;

	//The hour. The valid values for this member are 0 through 23.
	//The minute. The valid values for this member are 0 through 59.
	//The second. The valid values for this member are 0 through 59.
	//The millisecond. The valid values for this member are 0 through 999.

	if (lpTime->wMilliseconds > 999)
	{
		lpTime->wSecond++;
		lpTime->wMilliseconds = 0;

		if (lpTime->wSecond > 59)
		{
			lpTime->wMinute++;
			lpTime->wSecond = 0;

			if (lpTime->wMinute > 59)
			{
				lpTime->wHour++;
				lpTime->wMinute = 0;

				if (lpTime->wHour > 23)
				{
					lpTime->wDay++;
					lpTime->wDayOfWeek++;
					lpTime->wHour = 0;
				}
			}
		}
	}
}


BYTE memory[sizeof(IMAGE_NT_HEADERS) + 0x100] = {0};

void DumpMalware(DWORD dwProcessId)
{
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, 0, dwProcessId);
	if (hProcess)
	{
		PPEB peb = (PPEB)GetPEBRemote(hProcess);
		if (peb)
		{
			DWORD_PTR imagebase = 0;
			ReadProcessMemory(hProcess, (void *)&peb->ImageBaseAddress, &imagebase, sizeof(DWORD_PTR), 0);

			ReadProcessMemory(hProcess, (void *)imagebase, memory, sizeof(memory), 0);

			PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)memory;
			if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
			{
				PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);
				if (pNt->Signature == IMAGE_NT_SIGNATURE)
				{
					void *tempMem = VirtualAlloc(0, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
					if (tempMem)
					{
						ReadProcessMemory(hProcess,(void *)imagebase, tempMem, pNt->OptionalHeader.SizeOfImage, 0);
						
						WriteMalwareToDisk(tempMem, pNt->OptionalHeader.SizeOfImage, imagebase);

						VirtualFree(tempMem, 0, MEM_RELEASE);
					}
				}
			}
		}
		NtClose(hProcess);
	}
}

WCHAR MalwareFile[MAX_PATH] = {0};
const WCHAR MalwareFilename[] = L"Unpacked.exe";

bool WriteMalwareToDisk(LPCVOID buffer, DWORD bufferSize, DWORD_PTR imagebase)
{
	if (MalwareFile[0] == 0)
	{
		PUNICODE_STRING imagePath = &NtCurrentPeb()->ProcessParameters->ImagePathName;
		ULONG size = MIN(sizeof(MalwareFile) - 1, imagePath->Length);
		RtlCopyMemory(MalwareFile, imagePath->Buffer, size);
		MalwareFile[size / sizeof(WCHAR)] = L'\0';

		for (int i = (int)(size / sizeof(WCHAR)) - 1; i >= 0; i--)
		{
			if (MalwareFile[i] == L'\\')
			{
				MalwareFile[i+1] = L'\0';
				break;
			}
		}

		_wcscat(MalwareFile, MalwareFilename);
	}

	return WriteMemoryToFile(MalwareFile, buffer,bufferSize, imagebase);
}

bool WriteMemoryToFile(const WCHAR * filename, LPCVOID buffer, DWORD bufferSize, DWORD_PTR imagebase)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	//pNt->OptionalHeader.ImageBase = imagebase;

	UNICODE_STRING NtPath;
	if (!RtlDosPathNameToNtPathName_U(filename, &NtPath, nullptr, nullptr))
		return false;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	InitializeObjectAttributes(&objectAttributes, &NtPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE hFile;
	NTSTATUS status = NtCreateFile(&hFile,
								FILE_GENERIC_WRITE,
								&objectAttributes,
								&ioStatusBlock,
								nullptr,
								FILE_ATTRIBUTE_NORMAL,
								FILE_SHARE_READ,
								FILE_OVERWRITE_IF,
								FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
								nullptr,
								0);
	if (!NT_SUCCESS(status))
		return false;

	status = NtWriteFile(hFile, nullptr, nullptr, nullptr, &ioStatusBlock, (PVOID)buffer,
		pNt->OptionalHeader.SizeOfHeaders, nullptr, nullptr);

	for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		status = NtWriteFile(hFile, nullptr, nullptr, nullptr, &ioStatusBlock, (BYTE *)buffer + pSection->VirtualAddress,
			pSection->SizeOfRawData, nullptr, nullptr);
		pSection++;
	}
	NtClose(hFile);

	return NT_SUCCESS(status);
}
