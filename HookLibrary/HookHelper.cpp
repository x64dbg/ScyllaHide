#include "HookHelper.h"

#include <ntdll/ntdll.h>

#include "HookedFunctions.h"
#include "HookMain.h"

const WCHAR * BadProcessnameList[] =
{
	L"ollydbg.exe",
	L"ida.exe",
	L"ida64.exe",
	L"idag.exe",
	L"idag64.exe",
	L"idaw.exe",
	L"idaw64.exe",
	L"idaq.exe",
	L"idaq64.exe",
	L"idau.exe",
	L"idau64.exe",
	L"scylla.exe",
	L"scylla_x64.exe",
	L"scylla_x86.exe",
	L"protection_id.exe",
	L"x64dbg.exe",
	L"x32dbg.exe",
	L"windbg.exe",
	L"reshacker.exe",
	L"ImportREC.exe",
	L"IMMUNITYDEBUGGER.EXE",
	L"devenv.exe"
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
	L"WinDbg",
	L"x32dbg",
	L"x64dbg",
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

extern "C" void InstrumentationCallbackAsm();

extern HOOK_DLL_DATA HookDllData;
extern SAVE_DEBUG_REGISTERS ArrayDebugRegister[100];

static USHORT DebugObjectTypeIndex = 0;
static USHORT ProcessTypeIndex = 0;
static USHORT ThreadTypeIndex = 0;

bool IsProcessNameBad(PUNICODE_STRING processName)
{
	if (processName == nullptr || processName->Length == 0 || processName->Buffer == nullptr)
		return false;

	UNICODE_STRING badProcessName;
	for (int i = 0; i < _countof(BadProcessnameList); i++)
	{
		RtlInitUnicodeString(&badProcessName, const_cast<PWSTR>(BadProcessnameList[i]));
		if (RtlEqualUnicodeString(processName, &badProcessName, TRUE))
			return true;
	}
	return false;
}

bool IsWindowClassNameBad(PUNICODE_STRING className)
{
	if (className == nullptr || className->Length == 0 || className->Buffer == nullptr)
		return false;

	UNICODE_STRING badWindowClassName;
	for (int i = 0; i < _countof(BadWindowClassList); i++)
	{
		RtlInitUnicodeString(&badWindowClassName, const_cast<PWSTR>(BadWindowClassList[i]));
		if (RtlUnicodeStringContains(className, &badWindowClassName, TRUE))
			return true;
	}
	return false;
}

bool IsWindowNameBad(PUNICODE_STRING windowName)
{
	if (windowName == nullptr || windowName->Length == 0 || windowName->Buffer == nullptr)
		return false;

	UNICODE_STRING badWindowName;
	for (int i = 0; i < _countof(BadWindowTextList); i++)
	{
		RtlInitUnicodeString(&badWindowName, const_cast<PWSTR>(BadWindowTextList[i]));
		if (RtlUnicodeStringContains(windowName, &badWindowName, TRUE))
			return true;
	}
	return false;
}

bool IsWindowBad(HWND hWnd)
{
	if (HookDllData.EnableProtectProcessId)
	{
		const ULONG Pid = HookDllData.dNtUserQueryWindow != nullptr
			? HandleToULong(HookDllData.dNtUserQueryWindow(hWnd, WindowProcess))
			: HandleToULong(HookDllData.NtUserQueryWindow(hWnd, WindowProcess));
		if (Pid == HookDllData.dwProtectedProcessId)
			return true;
	}

	DECLARE_UNICODE_STRING_SIZE(ClassName, 256);
	DECLARE_UNICODE_STRING_SIZE(WindowText, 512);

	ClassName.Length = (USHORT)HookDllData.NtUserGetClassName(hWnd, FALSE, &ClassName) * sizeof(WCHAR);
	ClassName.Buffer[ClassName.Length / sizeof(WCHAR)] = UNICODE_NULL;
	if (IsWindowClassNameBad(&ClassName))
		return true;

	WindowText.Length = (USHORT)HookDllData.NtUserInternalGetWindowText(hWnd, WindowText.Buffer, (INT)(WindowText.MaximumLength / sizeof(WCHAR))) * sizeof(WCHAR);
	WindowText.Buffer[WindowText.Length / sizeof(WCHAR)] = UNICODE_NULL;
	return IsWindowNameBad(&WindowText);
}

static void GetBadObjectTypes()
{
	// If NtQSI is not hooked, this function is N/A
	if (HookDllData.dNtQuerySystemInformation == nullptr)
		return;

	// Only get the object type indices once
	if (DebugObjectTypeIndex != 0 || ProcessTypeIndex != 0 || ThreadTypeIndex != 0)
		return;

	// Create handles to three bad object types: an empty debug object and our own process and thread
	HANDLE DebugObjectHandle = nullptr, ProcessHandle = nullptr, ThreadHandle = nullptr;
	OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID ClientId = NtCurrentTeb()->ClientId;
	NtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, &ObjectAttributes, 0);
	NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
	NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, &ClientId);
	
	SYSTEM_HANDLE_INFORMATION_EX Dummy; // Prevent getting STATUS_INFO_LENGTH_MISMATCH twice
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = &Dummy;
	ULONG Size;
	NTSTATUS Status;
	if ((Status = HookDllData.dNtQuerySystemInformation(SystemExtendedHandleInformation,
														HandleInfo,
														sizeof(Dummy),
														&Size)) != STATUS_INFO_LENGTH_MISMATCH)
		goto exit;

	HandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)RtlAllocateHeap(RtlProcessHeap(), 0, 2 * Size);
	Status = HookDllData.dNtQuerySystemInformation(SystemExtendedHandleInformation,
													HandleInfo,
													2 * Size,
													nullptr);
	if (!NT_SUCCESS(Status))
		goto exit;

	// Enumerate all handles
	for (ULONG i = 0; i < HandleInfo->NumberOfHandles; ++i)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Entry = HandleInfo->Handles[i];
		if (Entry.UniqueProcessId != (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess)
			continue; // Not our process

		if (Entry.HandleValue == (ULONG_PTR)DebugObjectHandle)
			DebugObjectTypeIndex = Entry.ObjectTypeIndex;
		else if (Entry.HandleValue == (ULONG_PTR)ProcessHandle)
			ProcessTypeIndex = Entry.ObjectTypeIndex;
		else if (Entry.HandleValue == (ULONG_PTR)ThreadHandle)
			ThreadTypeIndex = Entry.ObjectTypeIndex;
	}

exit:
	if (DebugObjectHandle != nullptr)
		NtClose(DebugObjectHandle);
	if (ProcessHandle != nullptr)
		NtClose(ProcessHandle);
	if (ThreadHandle != nullptr)
		NtClose(ThreadHandle);
	if (HandleInfo != &Dummy)
		RtlFreeHeap(RtlProcessHeap(), 0, HandleInfo);
}

bool IsObjectTypeBad(USHORT objectTypeIndex)
{
	GetBadObjectTypes();
	return objectTypeIndex == DebugObjectTypeIndex ||
		objectTypeIndex == ProcessTypeIndex ||
		objectTypeIndex == ThreadTypeIndex;
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

bool IsWow64Process(HANDLE ProcessHandle)
{
	PPEB WoW64Peb = nullptr;
	const NTSTATUS Status = NtQueryInformationProcess(ProcessHandle,
													ProcessWow64Information,
													&WoW64Peb,
													sizeof(WoW64Peb),
													nullptr);

	return NT_SUCCESS(Status) && WoW64Peb != nullptr;
}

NTSTATUS
InstallInstrumentationCallbackHook(
	_In_ HANDLE ProcessHandle,
	_In_ BOOLEAN Remove
	)
{
	const PVOID pInstrumentationCallbackAsm = (PVOID)InstrumentationCallbackAsm;
	NTSTATUS Status = STATUS_NOT_SUPPORTED;

	if (RtlNtMajorVersion() > 6)
	{
		// Windows 10
		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION InstrumentationCallbackInfo;
#ifdef _WIN64
		InstrumentationCallbackInfo.Version = 0;
#else
		// Native x86 instrumentation callbacks don't work correctly
		if (!IsWow64Process(ProcessHandle))
		{
			//InstrumentationCallbackInfo.Version = 1; // Value to use if they did
			return Status;
		}

		// WOW64: set the callback pointer in the version field
		InstrumentationCallbackInfo.Version = (ULONG)(ULONG_PTR)(Remove ? nullptr : pInstrumentationCallbackAsm);
#endif
		InstrumentationCallbackInfo.Reserved = 0;
		InstrumentationCallbackInfo.Callback = Remove ? nullptr : pInstrumentationCallbackAsm;

		Status = HookDllData.dNtSetInformationProcess != nullptr
			? HookDllData.dNtSetInformationProcess(ProcessHandle,
													ProcessInstrumentationCallback,
													&InstrumentationCallbackInfo,
													sizeof(InstrumentationCallbackInfo))
			: NtSetInformationProcess(ProcessHandle,
									ProcessInstrumentationCallback,
									&InstrumentationCallbackInfo,
									sizeof(InstrumentationCallbackInfo));
	}
#ifdef _WIN64 // Windows 7-8.1 do not support x86/WOW64 instrumentation callbacks
	else if (RtlNtMajorVersion() == 6 && RtlNtMinorVersion() >= 1)
	{
		// Windows 7-8.1 require SE_DEBUG for this to work, even on the current process
		BOOLEAN SeDebugWasEnabled;
		Status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
		if (!NT_SUCCESS(Status))
			return Status;

		Status = HookDllData.dNtSetInformationProcess != nullptr
			? HookDllData.dNtSetInformationProcess(ProcessHandle,
													ProcessInstrumentationCallback,
													Remove ? nullptr : (PVOID)&pInstrumentationCallbackAsm,
													sizeof(pInstrumentationCallbackAsm))
			: NtSetInformationProcess(ProcessHandle,
									ProcessInstrumentationCallback,
									Remove ? nullptr : (PVOID)&pInstrumentationCallbackAsm,
									sizeof(pInstrumentationCallbackAsm));

		RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, SeDebugWasEnabled, FALSE, &SeDebugWasEnabled);
	}
#endif

	return Status;
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
			return HandleToULong(pbi.UniqueProcessId);
		}
	}
	else
	{
		//maybe not hooked
		if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0) >= 0)
		{
			return HandleToULong(pbi.UniqueProcessId);
		}
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
	if (dwProcess == 0)
		return;

	OBJECT_ATTRIBUTES attributes = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID clientId = { ULongToHandle(dwProcess) };
	HANDLE hProcess;
	NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_TERMINATE, &attributes, &clientId);
	if (NT_SUCCESS(status))
	{
		NtTerminateProcess(hProcess, STATUS_SUCCESS);
		NtClose(hProcess);
	}
}

static DWORD dwExplorerPid = 0;

DWORD GetExplorerProcessId()
{
	if (dwExplorerPid == 0)
	{
		UNICODE_STRING explorerName = RTL_CONSTANT_STRING(L"explorer.exe");
		dwExplorerPid = GetProcessIdByName(&explorerName);
	}
	return dwExplorerPid;
}

DWORD GetProcessIdByName(PUNICODE_STRING processName)
{
	ULONG size;
	if (NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size) != STATUS_INFO_LENGTH_MISMATCH)
		return 0;
	const PSYSTEM_PROCESS_INFORMATION systemProcessInfo =
		static_cast<PSYSTEM_PROCESS_INFORMATION>(RtlAllocateHeap(RtlProcessHeap(), 0, 2 * size));
	NTSTATUS status;
	if (HookDllData.dNtQuerySystemInformation != nullptr)
	{
		status = HookDllData.dNtQuerySystemInformation(SystemProcessInformation,
													systemProcessInfo,
													2 * size,
													nullptr);
	}
	else
	{
		status = NtQuerySystemInformation(SystemProcessInformation,
											systemProcessInfo,
											2 * size,
											nullptr);
	}
	if (!NT_SUCCESS(status))
		return 0;

	DWORD pid = 0;
	PSYSTEM_PROCESS_INFORMATION process = systemProcessInfo;
	while (true)
	{
		if (RtlEqualUnicodeString(&process->ImageName, processName, TRUE))
		{
			pid = HandleToULong(process->UniqueProcessId);
			break;
		}

		if (process->NextEntryOffset == 0)
			break;
		process = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)process + process->NextEntryOffset);
	}

	RtlFreeHeap(RtlProcessHeap(), 0, systemProcessInfo);
	return pid;
}

bool RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == nullptr || SubStr == nullptr || Str->Length < SubStr->Length)
		return false;

	const USHORT numCharsDiff = (Str->Length - SubStr->Length) / sizeof(WCHAR);
	UNICODE_STRING slice = *Str;
	slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= numCharsDiff; ++i, ++slice.Buffer, slice.MaximumLength -= sizeof(WCHAR))
	{
		if (RtlEqualUnicodeString(&slice, SubStr, CaseInsensitive))
			return true;
	}
	return false;
}

void ThreadDebugContextRemoveEntry(const int index)
{
	ArrayDebugRegister[index].dwThreadId = 0;
}

void ThreadDebugContextSaveContext(const int index, const PCONTEXT ThreadContext)
{
	ArrayDebugRegister[index].dwThreadId = HandleToULong(NtCurrentTeb()->ClientId.UniqueThread);
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
			if (ArrayDebugRegister[i].dwThreadId == HandleToULong(NtCurrentTeb()->ClientId.UniqueThread))
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

// GetSystemTime and GetLocalTime are reimplemented here because the KernelBase functions use
// RIP-relative addressing which breaks hooking. https://github.com/x64dbg/ScyllaHide/issues/31
void NTAPI RealGetSystemTime(PSYSTEMTIME lpSystemTime)
{
	TIME_FIELDS TimeFields;
	RtlTimeToTimeFields((PLARGE_INTEGER)& SharedUserData->SystemTime, &TimeFields);

	lpSystemTime->wYear = TimeFields.Year;
	lpSystemTime->wMonth = TimeFields.Month;
	lpSystemTime->wDay = TimeFields.Day;
	lpSystemTime->wHour = TimeFields.Hour;
	lpSystemTime->wMinute = TimeFields.Minute;
	lpSystemTime->wSecond = TimeFields.Second;
	lpSystemTime->wMilliseconds = TimeFields.Milliseconds;
	lpSystemTime->wDayOfWeek = TimeFields.Weekday;
}

void NTAPI RealGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	TIME_FIELDS TimeFields;
	LARGE_INTEGER SystemTime = *(PLARGE_INTEGER)& SharedUserData->SystemTime;
	LARGE_INTEGER TimeZoneBias = *(PLARGE_INTEGER)& SharedUserData->TimeZoneBias;

	SystemTime.QuadPart -= TimeZoneBias.QuadPart;
	RtlTimeToTimeFields(&SystemTime, &TimeFields);

	lpSystemTime->wYear = TimeFields.Year;
	lpSystemTime->wMonth = TimeFields.Month;
	lpSystemTime->wDay = TimeFields.Day;
	lpSystemTime->wHour = TimeFields.Hour;
	lpSystemTime->wMinute = TimeFields.Minute;
	lpSystemTime->wSecond = TimeFields.Second;
	lpSystemTime->wMilliseconds = TimeFields.Milliseconds;
	lpSystemTime->wDayOfWeek = TimeFields.Weekday;
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
	OBJECT_ATTRIBUTES attributes = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID clientId = { ULongToHandle(dwProcessId) };
	HANDLE hProcess;
	NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &attributes, &clientId);
	if (!NT_SUCCESS(status))
		return;

	PPEB peb = (PPEB)GetPEBRemote(hProcess);
	if (peb)
	{
		DWORD_PTR imagebase = 0;
		NtReadVirtualMemory(hProcess, &peb->ImageBaseAddress, &imagebase, sizeof(DWORD_PTR), nullptr);

		NtReadVirtualMemory(hProcess, (PVOID)imagebase, memory, sizeof(memory), nullptr);

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)memory;
		if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);
			if (pNt->Signature == IMAGE_NT_SIGNATURE)
			{
				PVOID tempMem = nullptr;
				SIZE_T size = pNt->OptionalHeader.SizeOfImage;
				status = NtAllocateVirtualMemory(NtCurrentProcess, &tempMem, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (NT_SUCCESS(status))
				{
					NtReadVirtualMemory(hProcess, (PVOID)imagebase, tempMem, pNt->OptionalHeader.SizeOfImage, nullptr);
						
					WriteMalwareToDisk(tempMem, pNt->OptionalHeader.SizeOfImage, imagebase);

					size = 0;
					NtFreeVirtualMemory(NtCurrentProcess, &tempMem, &size, MEM_RELEASE);
				}
			}
		}
	}
	NtClose(hProcess);
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

		wcscat(MalwareFile, MalwareFilename);
	}

	return WriteMemoryToFile(MalwareFile, buffer,bufferSize, imagebase);
}

bool WriteMemoryToFile(const WCHAR * filename, LPCVOID buffer, DWORD bufferSize, DWORD_PTR imagebase)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

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
