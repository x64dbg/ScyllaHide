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

// https://forum.tuts4you.com/topic/40011-debugme-vmprotect-312-build-886-anti-debug-method-improved/#comment-192824
// https://github.com/x64dbg/ScyllaHide/issues/47
// https://github.com/mrexodia/TitanHide/issues/27
#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ReturnLength != nullptr) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ReturnLength != nullptr) \
        (*ReturnLength) = TempReturnLength

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
            if (SystemInformationClass == SystemKernelDebuggerInformation)
            {
                BACKUP_RETURNLENGTH();

                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemHandleInformation)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterHandleInfo((PSYSTEM_HANDLE_INFORMATION)SystemInformation, &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
				    TempReturnLength -= ReturnLengthAdjust;
                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemExtendedHandleInformation)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterHandleInfoEx((PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation, &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
                    TempReturnLength -= ReturnLengthAdjust;
                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemProcessInformation ||
                    SystemInformationClass == SystemSessionProcessInformation ||
                    SystemInformationClass == SystemExtendedProcessInformation)
            {
                BACKUP_RETURNLENGTH();

                PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
                if (SystemInformationClass == SystemSessionProcessInformation)
                    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;

                FilterProcess(ProcessInfo);
                FakeCurrentParentProcessId(ProcessInfo);

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemCodeIntegrityInformation)
            {
                BACKUP_RETURNLENGTH();

                ((PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation)->CodeIntegrityOptions = CODEINTEGRITY_OPTION_ENABLED;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
            {
                BACKUP_RETURNLENGTH();

                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemKernelDebuggerFlags)
            {
                BACKUP_RETURNLENGTH();

                *(PUCHAR)SystemInformation = 0;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemCodeIntegrityUnlockInformation)
            {
                BACKUP_RETURNLENGTH();

                // The size of the buffer for this class changed from 4 to 36, but the output should still be all zeroes
                RtlZeroMemory(SystemInformation, SystemInformationLength);

                RESTORE_RETURNLENGTH();
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

// Instrumentation callback

static LONG volatile InstrumentationCallbackHookInstalled = 0;
static LONG volatile RecurseGuard = 0;

extern "C"
ULONG_PTR
NTAPI
InstrumentationCallback(
    _In_ ULONG_PTR ReturnAddress, // ECX/R10
    _Inout_ ULONG_PTR ReturnVal // EAX/RAX
    )
{
    if (InterlockedOr(&RecurseGuard, 0x1) == 0x1)
        return ReturnVal;

    const PVOID ImageBase = NtCurrentPeb()->ImageBaseAddress;
    const PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBase);
    if (NtHeaders != nullptr && ReturnAddress >= (ULONG_PTR)ImageBase &&
        ReturnAddress < (ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage)
    {
        // Syscall return address within the exe file
        ReturnVal = STATUS_PORT_NOT_SET;
    }

    InterlockedAnd(&RecurseGuard, 0);

    return ReturnVal;
}

NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    if (InterlockedOr(&InstrumentationCallbackHookInstalled, 0x1) == 0)
    {
        InstallInstrumentationCallbackHook(NtCurrentProcess, FALSE);
    }

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
            if (ProcessInformationClass == ProcessDebugFlags)
            {
                BACKUP_RETURNLENGTH();

                *((ULONG *)ProcessInformation) = ((ValueProcessDebugFlags & PROCESS_NO_DEBUG_INHERIT) != 0) ? 0 : PROCESS_DEBUG_INHERIT;

                RESTORE_RETURNLENGTH();
            }
            else if (ProcessInformationClass == ProcessDebugObjectHandle)
            {
                BACKUP_RETURNLENGTH();

                if (HookDllData.dNtClose)
                    HookDllData.dNtClose(*(PHANDLE)ProcessInformation);
                else
                    NtClose(*(PHANDLE)ProcessInformation);

                *((HANDLE *)ProcessInformation) = nullptr;

                RESTORE_RETURNLENGTH(); // Trigger any possible exceptions caused by messing with the output buffer before changing the final return status

                ntStat = STATUS_PORT_NOT_SET;
            }
            else if (ProcessInformationClass == ProcessDebugPort)
            {
                BACKUP_RETURNLENGTH();

                *((HANDLE *)ProcessInformation) = nullptr;

                RESTORE_RETURNLENGTH();
            }
            else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
            {
                BACKUP_RETURNLENGTH();

                ((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = ULongToHandle(GetExplorerProcessId());

                RESTORE_RETURNLENGTH();
            }
            else if (ProcessInformationClass == ProcessBreakOnTermination)
            {
                BACKUP_RETURNLENGTH();

                *((ULONG *)ProcessInformation) = ValueProcessBreakOnTermination;

                RESTORE_RETURNLENGTH();
            }
			else if (ProcessInformationClass == ProcessHandleTracing)
			{
                BACKUP_RETURNLENGTH();
                RESTORE_RETURNLENGTH(); // Trigger any possible exceptions caused by messing with the output buffer before changing the final return status

                ntStat = IsProcessHandleTracingEnabled ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
			}
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
        if (ObjectInformationClass == ObjectTypesInformation)
        {
            BACKUP_RETURNLENGTH();

            FilterObjects((POBJECT_TYPES_INFORMATION)ObjectInformation);

            RESTORE_RETURNLENGTH();
        }
        else if (ObjectInformationClass == ObjectTypeInformation)
        {
            BACKUP_RETURNLENGTH();

            FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation, false);

            RESTORE_RETURNLENGTH();
        }
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
    BOOLEAN DebugRegistersRequested = FALSE;
    if (ThreadHandle == NtCurrentThread ||
		HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
            DebugRegistersRequested = ThreadContext->ContextFlags != ContextBackup;
        }
    }

    NTSTATUS ntStat = HookDllData.dNtGetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
        if (DebugRegistersRequested)
        {
            ThreadContext->Dr0 = 0;
            ThreadContext->Dr1 = 0;
            ThreadContext->Dr2 = 0;
            ThreadContext->Dr3 = 0;
            ThreadContext->Dr6 = 0;
            ThreadContext->Dr7 = 0;
#ifdef _WIN64
            ThreadContext->LastBranchToRip = 0;
            ThreadContext->LastBranchFromRip = 0;
            ThreadContext->LastExceptionToRip = 0;
            ThreadContext->LastExceptionFromRip = 0;
#endif
        }
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
        UNICODE_STRING NtdllName = RTL_CONSTANT_STRING(L"ntdll.dll");
        PVOID Ntdll;
        if (NT_SUCCESS(LdrGetDllHandle(nullptr, nullptr, &NtdllName, &Ntdll)))
        {
            ANSI_STRING KiUserExceptionDispatcherName = RTL_CONSTANT_ANSI_STRING("KiUserExceptionDispatcher");
            LdrGetProcedureAddress(Ntdll, &KiUserExceptionDispatcherName, 0, (PVOID*)&KiUserExceptionDispatcherAddress);
        }
    }

    if (ThreadContext != nullptr &&
        retAddress >= KiUserExceptionDispatcherAddress && retAddress < (KiUserExceptionDispatcherAddress + 0x100))
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

    return HookDllData.dNtContinue(ThreadContext, RaiseAlert);
}

#ifndef _WIN64
PVOID NTAPI HandleNativeCallInternal(DWORD eaxValue, DWORD ecxValue)
{
    for (ULONG i = 0; i < _countof(HookDllData.HookNative); i++)
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
    NTSTATUS Status;
    if (HookDllData.dNtQueryObject != nullptr)
        Status = HookDllData.dNtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), nullptr);
    else
        Status = NtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), nullptr);

    if (NT_SUCCESS(Status))
    {
        if (flags.ProtectFromClose)
        {
            return STATUS_HANDLE_NOT_CLOSABLE;
        }

        return HookDllData.dNtClose(Handle);
    }

    return STATUS_INVALID_HANDLE;
}

NTSTATUS NTAPI HookedNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
	if (Options & DUPLICATE_CLOSE_SOURCE)
	{
		// If a process is being debugged and duplicates a handle with DUPLICATE_CLOSE_SOURCE, *and* the handle has the ProtectFromClose bit set, a STATUS_HANDLE_NOT_CLOSABLE exception will occur.
		// This is actually the exact same exception we already check for in NtClose, but the difference is that this NtClose call happens inside the kernel which we obviously can't hook.
		// When a process is not being debugged, NtDuplicateObject will simply return success without closing the source. This is because ObDuplicateObject ignores NtClose return values
		OBJECT_HANDLE_FLAG_INFORMATION HandleFlags;
		NTSTATUS Status;
		if (HookDllData.dNtQueryObject != nullptr)
			Status = HookDllData.dNtQueryObject(SourceHandle, ObjectHandleFlagInformation, &HandleFlags, sizeof(HandleFlags), nullptr);
		else
			Status = NtQueryObject(SourceHandle, ObjectHandleFlagInformation, &HandleFlags, sizeof(HandleFlags), nullptr);

		if (NT_SUCCESS(Status) && HandleFlags.ProtectFromClose)
		{
			// Prevent the exception
			Options &= ~DUPLICATE_CLOSE_SOURCE;
		}
	}

	return HookDllData.dNtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
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

BOOL NTAPI HookedNtUserBlockInput(BOOL fBlockIt)
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

void FilterHwndList(HWND * phwndFirst, PULONG pcHwndNeeded)
{
    for (UINT i = 0; i < *pcHwndNeeded; i++)
    {
        if (phwndFirst[i] != nullptr && IsWindowBad(phwndFirst[i]))
        {
            if (i == 0)
            {
                // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                {
                    if (phwndFirst[j] != nullptr && !IsWindowBad(phwndFirst[j]))
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

NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
    NTSTATUS ntStat = HookDllData.dNtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}

NTSTATUS NTAPI HookedNtUserBuildHwndList_Eight(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
    NTSTATUS ntStat = ((t_NtUserBuildHwndList_Eight)HookDllData.dNtUserBuildHwndList)(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}

HANDLE NTAPI HookedNtUserQueryWindow(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
	if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hwnd))
	{
		if (WindowInfo == WindowProcess)
			return NtCurrentTeb()->ClientId.UniqueProcess;
		if (WindowInfo == WindowThread)
			return NtCurrentTeb()->ClientId.UniqueThread;
	}
	return HookDllData.dNtUserQueryWindow(hwnd, WindowInfo);
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
