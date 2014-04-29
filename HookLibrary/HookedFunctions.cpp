#include "HookMain.h"
#include "HookedFunctions.h"
#include "HookHelper.h"
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

extern HOOK_DLL_EXCHANGE DllExchange;

void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo);
void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo);
void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes);
void FilterObject(POBJECT_TYPE_INFORMATION pObject);
void FilterHwndList(HWND * phwndFirst, PUINT pcHwndNeeded);

SAVE_DEBUG_REGISTERS ArrayDebugRegister[100] = { 0 }; //Max 100 threads

extern DWORD dwExplorerPid;
extern WCHAR ExplorerProcessName[13];

NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    if (ThreadInformationClass == ThreadHideFromDebugger && ThreadInformation == 0 && ThreadInformationLength == 0)
    {
        if (ThreadHandle == NtCurrentThread || GetCurrentProcessId() == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
        {
            return STATUS_SUCCESS;
        }
    }
    return DllExchange.dNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    if (SystemInformationClass == SystemKernelDebuggerInformation || SystemInformationClass == SystemProcessInformation)
    {
        NTSTATUS ntStat = DllExchange.dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        if (NT_SUCCESS(ntStat) && SystemInformation != 0 && SystemInformationLength != 0)
        {
            if (SystemInformationClass == SystemKernelDebuggerInformation)
            {
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
            }
            else if (SystemInformationClass == SystemProcessInformation)
            {
                FilterProcess((PSYSTEM_PROCESS_INFORMATION)SystemInformation);
                FakeCurrentParentProcessId((PSYSTEM_PROCESS_INFORMATION)SystemInformation);
            }
        }

        return ntStat;
    }
    return DllExchange.dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

static ULONG ValueProcessBreakOnTermination = FALSE;
static bool IsProcessHandleTracingEnabled = false;
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)


NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    if (ProcessHandle == NtCurrentProcess || GetCurrentProcessId() == GetProcessIdByProcessHandle(ProcessHandle))
    {
        NTSTATUS ntStat = DllExchange.dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

        if (NT_SUCCESS(ntStat) && ProcessInformation != 0 && ProcessInformationLength != 0)
        {
            if (ProcessInformationClass == ProcessDebugFlags)
            {
                *((ULONG *)ProcessInformation) = 1;
            }
            else if (ProcessInformationClass == ProcessDebugObjectHandle)
            {
                *((HANDLE *)ProcessInformation) = 0;
                return STATUS_PORT_NOT_SET;
            }
            else if (ProcessInformationClass == ProcessDebugPort)
            {
                *((HANDLE *)ProcessInformation) = 0;
            }
            else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
            {
                ((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = (HANDLE)GetExplorerProcessId();
            }
            else if (ProcessInformationClass == ProcessBreakOnTermination)
            {
                *((ULONG *)ProcessInformation) = ValueProcessBreakOnTermination;
            }
			else if (ProcessInformationClass == ProcessHandleTracing)
			{
				if (IsProcessHandleTracingEnabled)
				{
					return STATUS_SUCCESS;
				}
				else
				{
					return STATUS_INVALID_PARAMETER;
				}
			}
        }

        return ntStat;
    }
    return DllExchange.dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
    if (ProcessHandle == NtCurrentProcess || GetCurrentProcessId() == GetProcessIdByProcessHandle(ProcessHandle))
    {
        if (ProcessInformationClass == ProcessBreakOnTermination && ProcessInformation != 0 && sizeof(ULONG) == ProcessInformationLength)
        {
            ValueProcessBreakOnTermination = *((ULONG *)ProcessInformation);
            return STATUS_SUCCESS;
        }

		//PROCESS_HANDLE_TRACING_ENABLE -> ULONG, PROCESS_HANDLE_TRACING_ENABLE_EX -> ULONG,ULONG
		if (ProcessInformationClass == ProcessHandleTracing && ProcessInformation != 0)
		{
			if (ProcessInformationLength != sizeof(ULONG) && ProcessInformationLength != (sizeof(ULONG)*2))
			{
				return STATUS_INFO_LENGTH_MISMATCH;
			}

			IsProcessHandleTracingEnabled = true;
			return STATUS_SUCCESS;
		}
    }
    return DllExchange.dNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS NTAPI HookedNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
    NTSTATUS ntStat = DllExchange.dNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    if (NT_SUCCESS(ntStat) && ObjectInformation)
    {
        if (ObjectInformationClass == ObjectTypesInformation)
        {
            FilterObjects((POBJECT_TYPES_INFORMATION)ObjectInformation);
        }
        else if (ObjectInformationClass == ObjectTypeInformation)
        {
            FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation);
        }
    }

    return ntStat;
}

NTSTATUS NTAPI HookedNtYieldExecution()
{
    DllExchange.dNtYieldExecution();
    return STATUS_ACCESS_DENIED; //better than STATUS_SUCCESS or STATUS_NO_YIELD_PERFORMED
}

NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    DWORD ContextBackup = 0;
    if (ThreadHandle == NtCurrentThread || GetCurrentProcessId() == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        }
    }

    NTSTATUS ntStat = DllExchange.dNtGetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
    }
    return ntStat;
}

NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    DWORD ContextBackup = 0;
    if (ThreadHandle == NtCurrentThread || GetCurrentProcessId() == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        }
    }

    NTSTATUS ntStat = DllExchange.dNtSetContextThread(ThreadHandle, ThreadContext);

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
        jmp DllExchange.dKiUserExceptionDispatcher
    }
#endif

    //return DllExchange.dKiUserExceptionDispatcher(pExcptRec, ContextFrame);
}

static DWORD_PTR KiUserExceptionDispatcherAddress = 0;

NTSTATUS NTAPI HookedNtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert) //restore DRx Registers
{
    DWORD_PTR retAddress = (DWORD_PTR)_ReturnAddress();
    if (!KiUserExceptionDispatcherAddress)
    {
        KiUserExceptionDispatcherAddress = (DWORD_PTR)GetProcAddress(DllExchange.hNtdll, "KiUserExceptionDispatcher");
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

    return DllExchange.dNtContinue(ThreadContext, RaiseAlert);
}

#ifndef _WIN64
PVOID NTAPI HandleNativeCallInternal(DWORD eaxValue, DWORD ecxValue)
{
    for (int i = 0; i < _countof(DllExchange.HookNative); i++)
    {
        if (DllExchange.HookNative[i].eaxValue == eaxValue)
        {
            if (DllExchange.HookNative[i].ecxValue)
            {
                if (DllExchange.HookNative[i].ecxValue == ecxValue)
                {
                    return DllExchange.HookNative[i].hookedFunction;
                }
            }
            else
            {
                return DllExchange.HookNative[i].hookedFunction;
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
        jmp DllExchange.NativeCallContinue
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

        return DllExchange.dNtClose(Handle);
    }
    else
    {
        return STATUS_INVALID_HANDLE;
    }
}

static DWORD OneTickCount = 0;

DWORD WINAPI HookedGetTickCount(void)
{
    if (!OneTickCount)
    {
        OneTickCount = DllExchange.dGetTickCount();
    }
    else
    {
        OneTickCount++;
    }
    return OneTickCount;
}

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

//GetLastError() function might not change if a  debugger is present (it has never been the case that it is always set to zero).
DWORD WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString) //Worst anti-debug ever
{
    if (IsAtleastVista())
    {
        return 0;
    }
    else
    {
        SetLastError(GetLastError() + 1); //change last error
        return 1; //WinXP EAX -> 1
    }
}

HWND NTAPI HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
    HWND resultHwnd = DllExchange.dNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
    if (resultHwnd)
    {
        if (IsWindowClassBad(lpszClass) || IsWindowNameBad(lpszWindow))
        {
            return 0;
        }

		if (DllExchange.EnableProtectProcessId == TRUE)
		{
			DWORD dwProcessId;
			if (DllExchange.dNtUserQueryWindow)
			{
				dwProcessId = (DWORD)DllExchange.dNtUserQueryWindow(resultHwnd, WindowProcess);
			}
			else
			{
				dwProcessId = (DWORD)DllExchange.NtUserQueryWindow(resultHwnd, WindowProcess);
			}

			if (dwProcessId == DllExchange.dwProtectedProcessId)
			{
				return 0;
			}
		}
    }
    return resultHwnd;
}

NTSTATUS NTAPI HookedNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State)
{
    return STATUS_ACCESS_DENIED;
}

void FilterHwndList(HWND * phwndFirst, PUINT pcHwndNeeded)
{
    DWORD dwProcessId = 0;

    if (DllExchange.EnableProtectProcessId == TRUE)
    {
        for (UINT i = 0; i < *pcHwndNeeded; i++)
        {
            if (phwndFirst[i] != 0)
            {
                //GetWindowThreadProcessId(phwndFirst[i], &dwProcessId);
				if (DllExchange.dNtUserQueryWindow)
				{
					dwProcessId = (DWORD)DllExchange.dNtUserQueryWindow(phwndFirst[i], WindowProcess);
				}
				else
				{
					dwProcessId = (DWORD)DllExchange.NtUserQueryWindow(phwndFirst[i], WindowProcess);
				}
                if (dwProcessId == DllExchange.dwProtectedProcessId)
                {
                    if (i == 0)
                    {
                        phwndFirst[i] = phwndFirst[i + 1];
                    }
                    else
                    {
                        phwndFirst[i] = phwndFirst[i - 1]; //just override with previous
                    }
                }
            }
        }
    }

}

NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK hdesk, HWND hwndNext, BOOL fEnumChildren, DWORD idThread, UINT cHwndMax, HWND *phwndFirst, PUINT pcHwndNeeded)
{
    NTSTATUS ntStat = DllExchange.dNtUserBuildHwndList(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

    if (NT_SUCCESS(ntStat) && pcHwndNeeded != 0 && phwndFirst != 0)
    {
        FilterHwndList(phwndFirst, pcHwndNeeded);
    }

    return ntStat;
}

HANDLE NTAPI HookedNtUserQueryWindow(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
	HANDLE hHandle = DllExchange.dNtUserQueryWindow(hwnd, WindowInfo);

	if (hHandle)
	{
		if(DllExchange.EnableProtectProcessId == TRUE)
		{
			if (hHandle == (HANDLE)DllExchange.dwProtectedProcessId)
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
    return DllExchange.dNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,ThreadContext, InitialTeb,CreateSuspended);
}

//WIN 7: CreateThread -> CreateRemoteThreadEx -> NtCreateThreadEx
NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PVOID StartRoutine,PVOID Argument,ULONG CreateFlags,ULONG_PTR ZeroBits,SIZE_T StackSize,SIZE_T MaximumStackSize,PPS_ATTRIBUTE_LIST AttributeList)
{
    if (DllExchange.EnableNtCreateThreadExHook == TRUE) //prevent hide from debugger
    {
        if (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
        {
            CreateFlags ^= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        }
    }

    if (DllExchange.EnablePreventThreadCreation == TRUE)
    {
        if (ProcessHandle == NtCurrentProcess)
        {
            return STATUS_INSUFFICIENT_RESOURCES;//STATUS_INVALID_PARAMETER STATUS_INVALID_HANDLE STATUS_INSUFFICIENT_RESOURCES
        }
    }

    return DllExchange.dNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize,AttributeList);
}

void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes)
{
    POBJECT_TYPE_INFORMATION pObject = pObjectTypes->TypeInformation;
    for (ULONG i = 0; i < pObjectTypes->NumberOfTypes; i++)
    {
        FilterObject(pObject);

        pObject = (POBJECT_TYPE_INFORMATION)(((PCHAR)(pObject + 1) + ALIGN_UP(pObject->TypeName.MaximumLength, ULONG_PTR)));
    }
}

void FilterObject(POBJECT_TYPE_INFORMATION pObject)
{
    const WCHAR strDebugObject[] = L"DebugObject";

	if (pObject->TypeName.Length == 0 || pObject->TypeName.Buffer == 0)
	{
		return;
	}

    if (pObject->TypeName.Length == (sizeof(strDebugObject)-sizeof(WCHAR)))
    {
        if (!memcmp(strDebugObject, pObject->TypeName.Buffer, pObject->TypeName.Length))
        {
            pObject->TotalNumberOfObjects = 0;
            pObject->TotalNumberOfHandles = 0;
        }
    }

}


void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    if (!dwExplorerPid)
    {
        const USHORT explorerNameLength = (USHORT)_wcslen(ExplorerProcessName);
        PSYSTEM_PROCESS_INFORMATION pTemp = pInfo;
        while (TRUE)
        {
            if (pTemp->ImageName.Buffer && pTemp->ImageName.Length)
            {
                if (pTemp->ImageName.Length == explorerNameLength)
                {
                    if (!_wcsnicmp(pTemp->ImageName.Buffer, ExplorerProcessName, pTemp->ImageName.Length))
                    {
                        dwExplorerPid = (DWORD)pTemp->UniqueProcessId;
                        break;
                    }
                }
            }

            if (pTemp->NextEntryOffset == 0)
            {
                break;
            }
            else
            {
                pTemp = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pTemp + pTemp->NextEntryOffset);
            }
        }
    }

    if (dwExplorerPid)
    {
        while (TRUE)
        {
            if (pInfo->UniqueProcessId == (HANDLE)GetCurrentProcessId())
            {
                pInfo->InheritedFromUniqueProcessId = (HANDLE)dwExplorerPid;
                break;
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
}

void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

    while (TRUE)
    {
        if (IsProcessBad(&pInfo->ImageName) || ((DllExchange.EnableProtectProcessId == TRUE) && (pInfo->UniqueProcessId == (HANDLE)DllExchange.dwProtectedProcessId)))
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
