#include "HookMain.h"

#pragma intrinsic(_ReturnAddress)

HOOK_DLL_DATA HookDllData = { 0 };

#include "HookedFunctions.h"
#include "HookHelper.h"

void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo);
void FilterHandleInfo(PSYSTEM_HANDLE_INFORMATION pHandleInfo, PULONG pReturnLengthAdjust);
void FilterHandleInfoEx(PSYSTEM_HANDLE_INFORMATION_EX pHandleInfoEx, PULONG pReturnLengthAdjust);
void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo);
void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes);
void FilterObject(POBJECT_TYPE_INFORMATION pObject, bool zeroTotal);
void FilterHwndList(HWND * phwndFirst, PUINT pcHwndNeeded);

SAVE_DEBUG_REGISTERS ArrayDebugRegister[100] = { 0 }; //Max 100 threads

NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    if (ThreadInformationClass == ThreadHideFromDebugger && ThreadInformationLength == 0) // NB: ThreadInformation is not checked, this is deliberate
    {
        if (ThreadHandle == NtCurrentThread ||
			HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
        {
            return STATUS_SUCCESS;
        }
    }
    return HookDllData.dNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    if (SystemInformationClass == SystemKernelDebuggerInformation ||
        SystemInformationClass == SystemProcessInformation ||
        SystemInformationClass == SystemSessionProcessInformation ||
        SystemInformationClass == SystemHandleInformation ||
        SystemInformationClass == SystemExtendedHandleInformation ||
        SystemInformationClass == SystemExtendedProcessInformation ||   // Vista+
        SystemInformationClass == SystemCodeIntegrityInformation ||     // Vista+
        SystemInformationClass == SystemKernelDebuggerInformationEx ||  // 8.1+
        SystemInformationClass == SystemKernelDebuggerFlags ||          // 10+
        SystemInformationClass == SystemCodeIntegrityUnlockInformation) // 10+
    {
        NTSTATUS ntStat = HookDllData.dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        if (NT_SUCCESS(ntStat) && SystemInformation != nullptr && SystemInformationLength != 0)
        {
            ULONG backupReturnLength = 0;
            ULONG returnLengthAdjust = 0;
            if (ReturnLength != nullptr &&
                (ULONG_PTR)ReturnLength >= (ULONG_PTR)SystemInformation &&
                (ULONG_PTR)ReturnLength <= (ULONG_PTR)SystemInformation + SystemInformationLength)
            {
                backupReturnLength = *ReturnLength;
            }

            if (SystemInformationClass == SystemKernelDebuggerInformation)
            {
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
            }
            else if (SystemInformationClass == SystemHandleInformation)
            {
                FilterHandleInfo((PSYSTEM_HANDLE_INFORMATION)SystemInformation, &returnLengthAdjust);
            }
            else if (SystemInformationClass == SystemExtendedHandleInformation)
            {
                FilterHandleInfoEx((PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation, &returnLengthAdjust);
            }
            else if (SystemInformationClass == SystemProcessInformation ||
                    SystemInformationClass == SystemSessionProcessInformation ||
                    SystemInformationClass == SystemExtendedProcessInformation)
            {
                PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
                if (SystemInformationClass == SystemSessionProcessInformation)
                    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;

                FilterProcess(ProcessInfo);
                FakeCurrentParentProcessId(ProcessInfo);
            }
            else if (SystemInformationClass == SystemCodeIntegrityInformation)
            {
                ((PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation)->CodeIntegrityOptions = CODEINTEGRITY_OPTION_ENABLED;
            }
            else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
            {
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;
            }
            else if (SystemInformationClass == SystemKernelDebuggerFlags)
            {
                *(PUCHAR)SystemInformation = 0;
            }
            else if (SystemInformationClass == SystemCodeIntegrityUnlockInformation)
            {
                // The size of the buffer for this class changed from 4 to 36, but the output should still be all zeroes
                RtlZeroMemory(SystemInformation, SystemInformationLength);
            }

            if (backupReturnLength != 0) // TODO: or if returnLengthAdjust != 0, but we don't normally know if ReturnLength can be safely dereferenced w/o SEH
            {
                if (returnLengthAdjust <= backupReturnLength)
                    backupReturnLength -= returnLengthAdjust;
                *ReturnLength = backupReturnLength;
            }
        }

        return ntStat;
    }
    return HookDllData.dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

static ULONG ValueProcessBreakOnTermination = FALSE;
static ULONG ValueProcessDebugFlags = PROCESS_DEBUG_INHERIT; // actual value is no inherit
static bool IsProcessHandleTracingEnabled = false;

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((DWORD   )0xC000000DL)
#endif

NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    if ((ProcessInformationClass == ProcessDebugFlags ||
        ProcessInformationClass == ProcessDebugObjectHandle ||
        ProcessInformationClass == ProcessDebugPort ||
        ProcessInformationClass == ProcessBasicInformation ||
        ProcessInformationClass == ProcessBreakOnTermination ||
        ProcessInformationClass == ProcessHandleTracing) &&
        (ProcessHandle == NtCurrentProcess || HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByProcessHandle(ProcessHandle)))
    {
        NTSTATUS ntStat = HookDllData.dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

        if (NT_SUCCESS(ntStat) && ProcessInformation != 0 && ProcessInformationLength != 0)
        {
            ULONG backupReturnLength = 0;
            if (ReturnLength != nullptr &&
                (ULONG_PTR)ReturnLength >= (ULONG_PTR)ProcessInformation &&
                (ULONG_PTR)ReturnLength <= (ULONG_PTR)ProcessInformation + ProcessInformationLength)
            {
                backupReturnLength = *ReturnLength;
            }

            if (ProcessInformationClass == ProcessDebugFlags)
            {
                *((ULONG *)ProcessInformation) = ((ValueProcessDebugFlags & PROCESS_NO_DEBUG_INHERIT) != 0) ? 0 : PROCESS_DEBUG_INHERIT;
            }
            else if (ProcessInformationClass == ProcessDebugObjectHandle)
            {
                *((HANDLE *)ProcessInformation) = 0;
                ntStat = STATUS_PORT_NOT_SET;
            }
            else if (ProcessInformationClass == ProcessDebugPort)
            {
                *((HANDLE *)ProcessInformation) = 0;
            }
            else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
            {
                ((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = ULongToHandle(GetExplorerProcessId());
            }
            else if (ProcessInformationClass == ProcessBreakOnTermination)
            {
                *((ULONG *)ProcessInformation) = ValueProcessBreakOnTermination;
            }
			else if (ProcessInformationClass == ProcessHandleTracing)
			{
                ntStat = IsProcessHandleTracingEnabled ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
			}

            if (backupReturnLength != 0)
                *ReturnLength = backupReturnLength;
        }

        return ntStat;
    }
    return HookDllData.dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	if (ProcessHandle == NtCurrentProcess || HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByProcessHandle(ProcessHandle))
    {
        if (ProcessInformationClass == ProcessBreakOnTermination)
        {
			if (ProcessInformationLength != sizeof(ULONG))
			{
				return STATUS_INFO_LENGTH_MISMATCH;
			}

			// NtSetInformationProcess will happily dereference this pointer
			if (ProcessInformation == NULL)
			{
				return STATUS_ACCESS_VIOLATION;
			}

			// A process must have debug privileges enabled to set the ProcessBreakOnTermination flag
			if (!HasDebugPrivileges(NtCurrentProcess))
			{
				return STATUS_PRIVILEGE_NOT_HELD;
			}

            ValueProcessBreakOnTermination = *((ULONG *)ProcessInformation);
            return STATUS_SUCCESS;
        }

		// Don't allow changing the debug inherit flag, and keep track of the new value to report in NtQIP
		if (ProcessInformationClass == ProcessDebugFlags)
		{
			if (ProcessInformationLength != sizeof(ULONG))
			{
				return STATUS_INFO_LENGTH_MISMATCH;
			}

			if (ProcessInformation == NULL)
			{
				return STATUS_ACCESS_VIOLATION;
			}

			ULONG Flags = *(ULONG*)ProcessInformation;
			if ((Flags & ~PROCESS_DEBUG_INHERIT) != 0)
			{
				return STATUS_INVALID_PARAMETER;
			}

			if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
			{
				ValueProcessDebugFlags &= ~PROCESS_NO_DEBUG_INHERIT;
			}
			else
			{
				ValueProcessDebugFlags |= PROCESS_NO_DEBUG_INHERIT;
			}
			return STATUS_SUCCESS;
		}

		//PROCESS_HANDLE_TRACING_ENABLE -> ULONG, PROCESS_HANDLE_TRACING_ENABLE_EX -> ULONG,ULONG
		if (ProcessInformationClass == ProcessHandleTracing)
		{
			bool enable = ProcessInformationLength != 0; // A length of 0 is valid and indicates we should disable tracing
			if (enable)
			{
				if (ProcessInformationLength != sizeof(ULONG) && ProcessInformationLength != (sizeof(ULONG) * 2))
				{
					return STATUS_INFO_LENGTH_MISMATCH;
				}

				// NtSetInformationProcess will happily dereference this pointer
				if (ProcessInformation == NULL)
				{
					return STATUS_ACCESS_VIOLATION;
				}

				PPROCESS_HANDLE_TRACING_ENABLE_EX phtEx = (PPROCESS_HANDLE_TRACING_ENABLE_EX)ProcessInformation;
				if (phtEx->Flags != 0)
				{
					return STATUS_INVALID_PARAMETER;
				}
			}

			IsProcessHandleTracingEnabled = enable;
			return STATUS_SUCCESS;
		}
    }
    return HookDllData.dNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS NTAPI HookedNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
    NTSTATUS ntStat = HookDllData.dNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    if ((ObjectInformationClass == ObjectTypesInformation ||
        ObjectInformationClass == ObjectTypeInformation) &&
        (NT_SUCCESS(ntStat) && ObjectInformation))
    {
        ULONG backupReturnLength = 0;
        if (ReturnLength != nullptr &&
            (ULONG_PTR)ReturnLength >= (ULONG_PTR)ObjectInformation &&
            (ULONG_PTR)ReturnLength <= (ULONG_PTR)ObjectInformation + ObjectInformationLength)
        {
            backupReturnLength = *ReturnLength;
        }

        if (ObjectInformationClass == ObjectTypesInformation)
        {
            FilterObjects((POBJECT_TYPES_INFORMATION)ObjectInformation);
        }
        else if (ObjectInformationClass == ObjectTypeInformation)
        {
            FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation, false);
        }

        if (backupReturnLength != 0)
            *ReturnLength = backupReturnLength;
    }

    return ntStat;
}

NTSTATUS NTAPI HookedNtYieldExecution()
{
    HookDllData.dNtYieldExecution();
    return STATUS_ACCESS_DENIED; //better than STATUS_SUCCESS or STATUS_NO_YIELD_PERFORMED
}

NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    DWORD ContextBackup = 0;
    if (ThreadHandle == NtCurrentThread ||
		HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        }
    }

    NTSTATUS ntStat = HookDllData.dNtGetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
    }
    return ntStat;
}

NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    DWORD ContextBackup = 0;
    if (ThreadHandle == NtCurrentThread ||
		HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        }
    }

    NTSTATUS ntStat = HookDllData.dNtSetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
    }

    return ntStat;
}

void NTAPI HandleKiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame)
{
    if (ContextFrame && (ContextFrame->ContextFlags & CONTEXT_DEBUG_REGISTERS))
    {
        int slotIndex = ThreadDebugContextFindFreeSlotIndex();
        if (slotIndex != -1)
        {
            ThreadDebugContextSaveContext(slotIndex, ContextFrame);
        }

        ContextFrame->Dr0 = 0;
        ContextFrame->Dr1 = 0;
        ContextFrame->Dr2 = 0;
        ContextFrame->Dr3 = 0;
        ContextFrame->Dr6 = 0;
        ContextFrame->Dr7 = 0;
    }
}

VOID NAKED NTAPI HookedKiUserExceptionDispatcher()// (PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame) //remove DRx Registers
{
    //MOV ECX,DWORD PTR SS:[ESP+4] <- ContextFrame
    //MOV EBX,DWORD PTR SS:[ESP] <- pExcptRec
#ifndef _WIN64
    __asm
    {
        MOV EAX, [ESP + 4]
        MOV ECX, [ESP]
        PUSH EAX
        PUSH ECX
        CALL HandleKiUserExceptionDispatcher
        jmp HookDllData.dKiUserExceptionDispatcher
    }
#endif

    //return HookDllData.dKiUserExceptionDispatcher(pExcptRec, ContextFrame);
}

static DWORD_PTR KiUserExceptionDispatcherAddress = 0;

NTSTATUS NTAPI HookedNtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert) //restore DRx Registers
{
    DWORD_PTR retAddress = (DWORD_PTR)_ReturnAddress();
    if (!KiUserExceptionDispatcherAddress)
    {
        ANSI_STRING KiUserExceptionDispatcherName = RTL_CONSTANT_ANSI_STRING("KiUserExceptionDispatcher");
        LdrGetProcedureAddress(HookDllData.hNtdll, &KiUserExceptionDispatcherName, 0, (PVOID*)&KiUserExceptionDispatcherAddress);
    }

    if (ThreadContext)
    {
        //char text[100];
        //wsprintfA(text, "HookedNtContinue return %X", _ReturnAddress());
        //MessageBoxA(0, text, "debug", 0);

        if (retAddress >= KiUserExceptionDispatcherAddress && retAddress < (KiUserExceptionDispatcherAddress + 0x100))
        {
            int index = ThreadDebugContextFindExistingSlotIndex();
            if (index != -1)
            {
                ThreadContext->Dr0 = ArrayDebugRegister[index].Dr0;
                ThreadContext->Dr1 = ArrayDebugRegister[index].Dr1;
                ThreadContext->Dr2 = ArrayDebugRegister[index].Dr2;
                ThreadContext->Dr3 = ArrayDebugRegister[index].Dr3;
                ThreadContext->Dr6 = ArrayDebugRegister[index].Dr6;
                ThreadContext->Dr7 = ArrayDebugRegister[index].Dr7;
                ThreadDebugContextRemoveEntry(index);
            }

        }
    }

    return HookDllData.dNtContinue(ThreadContext, RaiseAlert);
}

#ifndef _WIN64
PVOID NTAPI HandleNativeCallInternal(DWORD eaxValue, DWORD ecxValue)
{
    for (int i = 0; i < _countof(HookDllData.HookNative); i++)
    {
        if (HookDllData.HookNative[i].eaxValue == eaxValue)
        {
            if (HookDllData.HookNative[i].ecxValue)
            {
                if (HookDllData.HookNative[i].ecxValue == ecxValue)
                {
                    return HookDllData.HookNative[i].hookedFunction;
                }
            }
            else
            {
                return HookDllData.HookNative[i].hookedFunction;
            }
        }
    }

    return 0;
}
#endif

void NAKED NTAPI HookedNativeCallInternal()
{
#ifndef _WIN64
    __asm
    {
        PUSHAD
        PUSH ECX
        PUSH EAX
        CALL HandleNativeCallInternal
        cmp eax, 0
        je NoHook
        POPAD
        ADD ESP,4
        PUSH ECX
        PUSH EAX
        CALL HandleNativeCallInternal
        jmp eax
        NoHook:
        POPAD
        jmp HookDllData.NativeCallContinue
    }
#endif
}

NTSTATUS NTAPI HookedNtClose(HANDLE Handle)
{
    OBJECT_HANDLE_FLAG_INFORMATION flags;
    flags.ProtectFromClose = 0;
    flags.Inherit = 0;
    if (NtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), 0) >= 0)
    {
        if (flags.ProtectFromClose)
        {
            return STATUS_HANDLE_NOT_CLOSABLE;
        }

        return HookDllData.dNtClose(Handle);
    }
    else
    {
        return STATUS_INVALID_HANDLE;
    }
}

//////////////////////////////////////////////////////////////
////////////////////// TIME FUNCTIONS ////////////////////////
//////////////////////////////////////////////////////////////

static DWORD OneTickCount = 0;

DWORD WINAPI HookedGetTickCount(void)
{
    if (!OneTickCount)
    {
        OneTickCount = HookDllData.dGetTickCount();
    }
    else
    {
        OneTickCount++;
    }
    return OneTickCount;
}

ULONGLONG WINAPI HookedGetTickCount64(void) //yes we can use DWORD
{
	if (!OneTickCount)
	{
		if (HookDllData.dGetTickCount)
		{
			OneTickCount = HookDllData.dGetTickCount();
		}
		else
		{
			OneTickCount = RtlGetTickCount();
		}
	}
	else
	{
		OneTickCount++;
	}
	return OneTickCount;
}

static SYSTEMTIME OneLocalTime = {0};
static SYSTEMTIME OneSystemTime = {0};

// GetSystemTime and GetLocalTime are reimplemented here because the KernelBase functions use
// RIP-relative addressing which breaks hooking. https://github.com/x64dbg/ScyllaHide/issues/31
static void WINAPI RealGetSystemTime(PSYSTEMTIME lpSystemTime)
{
	TIME_FIELDS TimeFields;
	RtlTimeToTimeFields((PLARGE_INTEGER)&SharedUserData->SystemTime, &TimeFields);

	lpSystemTime->wYear = TimeFields.Year;
	lpSystemTime->wMonth = TimeFields.Month;
	lpSystemTime->wDay = TimeFields.Day;
	lpSystemTime->wHour = TimeFields.Hour;
	lpSystemTime->wMinute = TimeFields.Minute;
	lpSystemTime->wSecond = TimeFields.Second;
	lpSystemTime->wMilliseconds = TimeFields.Milliseconds;
	lpSystemTime->wDayOfWeek = TimeFields.Weekday;
}

static void WINAPI RealGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	TIME_FIELDS TimeFields;
	LARGE_INTEGER SystemTime = *(PLARGE_INTEGER)&SharedUserData->SystemTime;
	LARGE_INTEGER TimeZoneBias = *(PLARGE_INTEGER)&SharedUserData->TimeZoneBias;

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

void WINAPI HookedGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	if (!OneLocalTime.wYear)
	{
		RealGetLocalTime(&OneLocalTime);

		if (HookDllData.dGetSystemTime)
		{
			RealGetSystemTime(&OneSystemTime);
		}
	}
	else
	{
		IncreaseSystemTime(&OneLocalTime);

		if (HookDllData.dGetSystemTime)
		{
			IncreaseSystemTime(&OneSystemTime);
		}
	}

	if (lpSystemTime)
	{
		memcpy(lpSystemTime, &OneLocalTime, sizeof(SYSTEMTIME));
	}
}

void WINAPI HookedGetSystemTime(LPSYSTEMTIME lpSystemTime)
{
	if (!OneSystemTime.wYear)
	{
		RealGetSystemTime(&OneSystemTime);

		if (HookDllData.dGetLocalTime)
		{
			RealGetLocalTime(&OneLocalTime);
		}
	}
	else
	{
		IncreaseSystemTime(&OneSystemTime);

		if (HookDllData.dGetLocalTime)
		{
			IncreaseSystemTime(&OneLocalTime);
		}
	}

	if (lpSystemTime)
	{
		memcpy(lpSystemTime, &OneSystemTime, sizeof(SYSTEMTIME));
	}
}

static LARGE_INTEGER OneNativeSysTime = {0};

NTSTATUS WINAPI HookedNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
	if (!OneNativeSysTime.QuadPart)
	{
		HookDllData.dNtQuerySystemTime(&OneNativeSysTime);
	}
	else
	{
		OneNativeSysTime.QuadPart++;
	}

	NTSTATUS ntStat = HookDllData.dNtQuerySystemTime(SystemTime);

	if (ntStat == STATUS_SUCCESS)
	{
		if (SystemTime)
		{
			SystemTime->QuadPart = OneNativeSysTime.QuadPart;
		}
	}

	return ntStat;
}

static LARGE_INTEGER OnePerformanceCounter = {0};
static LARGE_INTEGER OnePerformanceFrequency = {0};

NTSTATUS NTAPI HookedNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency)
{
	if (!OnePerformanceCounter.QuadPart)
	{
		HookDllData.dNtQueryPerformanceCounter(&OnePerformanceCounter, &OnePerformanceFrequency);
	}
	else
	{
		OnePerformanceCounter.QuadPart++;
	}

	NTSTATUS ntStat = HookDllData.dNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);

	if (ntStat == STATUS_SUCCESS)
	{
		if (PerformanceFrequency) //OPTIONAL
		{
			PerformanceFrequency->QuadPart = OnePerformanceFrequency.QuadPart;
		}

		if (PerformanceCounter)
		{
			PerformanceCounter->QuadPart = OnePerformanceCounter.QuadPart;
		}
	}

	return ntStat;
}

//////////////////////////////////////////////////////////////
////////////////////// TIME FUNCTIONS ////////////////////////
//////////////////////////////////////////////////////////////


static BOOL isBlocked = FALSE;

BOOL WINAPI HookedBlockInput(BOOL fBlockIt)
{
    if (isBlocked == FALSE && fBlockIt != FALSE)
    {
        isBlocked = TRUE;
        return TRUE;
    }
    else if (isBlocked != FALSE && fBlockIt == FALSE)
    {
        isBlocked = FALSE;
        return TRUE;
    }

    return FALSE;
}

NTSTATUS NTAPI HookedNtUserBlockInput(BOOL fBlockIt)
{
    return (NTSTATUS)HookedBlockInput(fBlockIt);
}

//GetLastError() function might not change if a  debugger is present (it has never been the case that it is always set to zero).
DWORD WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString) //Worst anti-debug ever
{
    if (RtlNtMajorVersion() >= 6) // Vista or later
        return 0;

    NtCurrentTeb()->LastErrorValue = NtCurrentTeb()->LastErrorValue + 1; //change last error
    return 1; //WinXP EAX -> 1
}

HWND NTAPI HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
    HWND resultHwnd = HookDllData.dNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
    if (resultHwnd)
    {
        if (IsWindowClassNameBad(lpszClass) || IsWindowNameBad(lpszWindow))
        {
            return 0;
        }

		if (HookDllData.EnableProtectProcessId == TRUE)
		{
			DWORD dwProcessId;
			if (HookDllData.dNtUserQueryWindow)
			{
				dwProcessId = HandleToULong(HookDllData.dNtUserQueryWindow(resultHwnd, WindowProcess));
			}
			else
			{
				dwProcessId = HandleToULong(HookDllData.NtUserQueryWindow(resultHwnd, WindowProcess));
			}

			if (dwProcessId == HookDllData.dwProtectedProcessId)
			{
				return 0;
			}
		}
    }
    return resultHwnd;
}

NTSTATUS NTAPI HookedNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State)
{
    return HasDebugPrivileges(NtCurrentProcess) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

void FilterHwndList(HWND * phwndFirst, PUINT pcHwndNeeded)
{
    if (!HookDllData.EnableProtectProcessId)
        return;

    for (UINT i = 0; i < *pcHwndNeeded; i++)
    {
        if (phwndFirst[i] != nullptr)
        {
            //GetWindowThreadProcessId(phwndFirst[i], &dwProcessId);
            ULONG dwProcessId = HookDllData.dNtUserQueryWindow != nullptr
                ? HandleToULong(HookDllData.dNtUserQueryWindow(phwndFirst[i], WindowProcess))
                : HandleToULong(HookDllData.NtUserQueryWindow(phwndFirst[i], WindowProcess));

            if (dwProcessId == HookDllData.dwProtectedProcessId)
            {
                if (i == 0)
                {
                    // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                    for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                    {
                        dwProcessId = HookDllData.dNtUserQueryWindow != nullptr
                            ? HandleToULong(HookDllData.dNtUserQueryWindow(phwndFirst[j], WindowProcess))
                            : HandleToULong(HookDllData.NtUserQueryWindow(phwndFirst[j], WindowProcess));
                        if (dwProcessId != HookDllData.dwProtectedProcessId)
                        {
                            phwndFirst[i] = phwndFirst[j];
                            break;
                        }
                    }
                }
                else
                {
                    phwndFirst[i] = phwndFirst[i - 1]; //just override with previous
                }
            }
        }
    }
}

NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK hdesk, HWND hwndNext, BOOL fEnumChildren, DWORD idThread, UINT cHwndMax, HWND *phwndFirst, PUINT pcHwndNeeded)
{
    NTSTATUS ntStat = HookDllData.dNtUserBuildHwndList(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    if (NT_SUCCESS(ntStat) && pcHwndNeeded != 0 && phwndFirst != 0)
    {
        FilterHwndList(phwndFirst, pcHwndNeeded);
    }

    return ntStat;
}

HANDLE NTAPI HookedNtUserQueryWindow(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
	HANDLE hHandle = HookDllData.dNtUserQueryWindow(hwnd, WindowInfo);

	if (hHandle)
	{
		if(HookDllData.EnableProtectProcessId == TRUE)
		{
			if (hHandle == ULongToHandle(HookDllData.dwProtectedProcessId))
			{
				return (HANDLE)((DWORD_PTR)hHandle + 1);
			}
		}
	}

	return hHandle;
}

//WIN XP: CreateThread -> CreateRemoteThread -> NtCreateThread
NTSTATUS NTAPI HookedNtCreateThread(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PCLIENT_ID ClientId,PCONTEXT ThreadContext,PINITIAL_TEB InitialTeb,BOOLEAN CreateSuspended)
{
    if (ProcessHandle == NtCurrentProcess)
    {
        return STATUS_INSUFFICIENT_RESOURCES;//STATUS_INVALID_PARAMETER STATUS_INVALID_HANDLE STATUS_INSUFFICIENT_RESOURCES
    }
    return HookDllData.dNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,ThreadContext, InitialTeb,CreateSuspended);
}

//WIN 7: CreateThread -> CreateRemoteThreadEx -> NtCreateThreadEx
NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PUSER_THREAD_START_ROUTINE StartRoutine,PVOID Argument,ULONG CreateFlags,ULONG_PTR ZeroBits,SIZE_T StackSize,SIZE_T MaximumStackSize,PPS_ATTRIBUTE_LIST AttributeList)
{
    if (HookDllData.EnableNtCreateThreadExHook == TRUE) //prevent hide from debugger
    {
        if (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
        {
            CreateFlags ^= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        }
    }

    if (HookDllData.EnablePreventThreadCreation == TRUE)
    {
        if (ProcessHandle == NtCurrentProcess)
        {
            return STATUS_INSUFFICIENT_RESOURCES;//STATUS_INVALID_PARAMETER STATUS_INVALID_HANDLE STATUS_INSUFFICIENT_RESOURCES
        }
    }

    return HookDllData.dNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize,AttributeList);
}

void FilterHandleInfo(PSYSTEM_HANDLE_INFORMATION pHandleInfo, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = pHandleInfo->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        // TODO: protect processes by name too
        if ((HookDllData.EnableProtectProcessId == TRUE && (ULONG)(pHandleInfo->Handles[i].UniqueProcessId == HookDllData.dwProtectedProcessId)) &&
            IsObjectTypeBad(pHandleInfo->Handles[i].ObjectTypeIndex))
        {
            pHandleInfo->NumberOfHandles--;
            *pReturnLengthAdjust += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                pHandleInfo->Handles[j] = pHandleInfo->Handles[j + 1];
                RtlZeroMemory(&pHandleInfo->Handles[j + 1], sizeof(pHandleInfo->Handles[j + 1]));
            }
            i--;
        }
    }
}

void FilterHandleInfoEx(PSYSTEM_HANDLE_INFORMATION_EX pHandleInfoEx, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = (ULONG)pHandleInfoEx->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        // TODO: protect processes by name too
        if ((HookDllData.EnableProtectProcessId == TRUE && (ULONG)(pHandleInfoEx->Handles[i].UniqueProcessId == HookDllData.dwProtectedProcessId)) &&
            IsObjectTypeBad(pHandleInfoEx->Handles[i].ObjectTypeIndex))
        {
            pHandleInfoEx->NumberOfHandles--;
            *pReturnLengthAdjust += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                pHandleInfoEx->Handles[j] = pHandleInfoEx->Handles[j + 1];
                RtlZeroMemory(&pHandleInfoEx->Handles[j + 1], sizeof(pHandleInfoEx->Handles[j + 1]));
            }
            i--;
        }
    }
}

void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes)
{
    POBJECT_TYPE_INFORMATION pObject = pObjectTypes->TypeInformation;
    for (ULONG i = 0; i < pObjectTypes->NumberOfTypes; i++)
    {
        FilterObject(pObject, true);

        pObject = (POBJECT_TYPE_INFORMATION)(((PCHAR)(pObject + 1) + ALIGN_UP(pObject->TypeName.MaximumLength, ULONG_PTR)));
    }
}

void FilterObject(POBJECT_TYPE_INFORMATION pObject, bool zeroTotal)
{
    UNICODE_STRING debugObjectName = RTL_CONSTANT_STRING(L"DebugObject");
    if (RtlEqualUnicodeString(&debugObjectName, &pObject->TypeName, FALSE))
    {
        // Subtract just one from both counts for our debugger, unless the query was a generic one for all object types
        pObject->TotalNumberOfObjects = zeroTotal || pObject->TotalNumberOfObjects == 0 ? 0 : pObject->TotalNumberOfObjects - 1;
        pObject->TotalNumberOfHandles = zeroTotal || pObject->TotalNumberOfHandles == 0 ? 0 : pObject->TotalNumberOfHandles - 1;
    }
}

void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    while (true)
    {
        if (pInfo->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
        {
            pInfo->InheritedFromUniqueProcessId = ULongToHandle(GetExplorerProcessId());
            break;
        }

        if (pInfo->NextEntryOffset == 0)
            break;

        pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
    }
}

void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

    while (TRUE)
    {
        if (IsProcessNameBad(&pInfo->ImageName) || ((HookDllData.EnableProtectProcessId == TRUE) && (HandleToULong(pInfo->UniqueProcessId) == HookDllData.dwProtectedProcessId)))
        {
            if (pInfo->ImageName.Buffer)
                ZeroMemory(pInfo->ImageName.Buffer, pInfo->ImageName.Length);

            if (pInfo->NextEntryOffset == 0) //last element
            {
                pPrev->NextEntryOffset = 0;
            }
            else
            {
                pPrev->NextEntryOffset += pInfo->NextEntryOffset;
            }
        }
        else
        {
            pPrev = pInfo;
        }

        if (pInfo->NextEntryOffset == 0)
        {
            break;
        }
        else
        {
            pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
        }
    }
}

NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
	DWORD dwProcessId = GetProcessIdByThreadHandle(ThreadHandle);
	if (dwProcessId != HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess)) //malware starts the thread of another process
	{
		DumpMalware(dwProcessId);
		TerminateProcessByProcessId(dwProcessId); //terminate it
		DbgPrint("Malware called ResumeThread");
		DbgBreakPoint();
		return STATUS_SUCCESS;
	}
	else
	{
		return HookDllData.dNtResumeThread(ThreadHandle, PreviousSuspendCount);
	}
}
