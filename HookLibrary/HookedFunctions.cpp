#include "ntdll.h"
#include "HookedFunctions.h"
#include "HookHelper.h"


t_NtSetInformationThread dNtSetInformationThread = 0;
t_NtQuerySystemInformation dNtQuerySystemInformation = 0;
t_NtSetInformationProcess dNtSetInformationProcess = 0;
t_NtQueryInformationProcess dNtQueryInformationProcess = 0;
t_NtQueryObject dNtQueryObject = 0;
t_NtYieldExecution dNtYieldExecution = 0;
t_NtGetContextThread dNtGetContextThread = 0;
t_NtSetContextThread dNtSetContextThread = 0;
t_KiUserExceptionDispatcher dKiUserExceptionDispatcher = 0;
t_NtContinue dNtContinue = 0;
t_NtClose dNtClose = 0;

t_GetTickCount dGetTickCount = 0;
t_BlockInput dBlockInput = 0;

t_NtUserFindWindowEx dNtUserFindWindowEx = 0;


//t_OutputDebugStringA dOutputDebugStringA = 0;

void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo);
void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes);
void FilterObject(POBJECT_TYPE_INFORMATION pObject);

NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    if (ThreadInformationClass == ThreadHideFromDebugger && ThreadInformation == 0 && ThreadInformationLength == 0)
    {
        if (ThreadHandle == NtCurrentThread || GetCurrentProcessId() == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
        {
            return STATUS_SUCCESS;
        }
    }
    return dNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    if (SystemInformationClass == SystemKernelDebuggerInformation || SystemInformationClass == SystemProcessInformation)
    {
        NTSTATUS ntStat = dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        if (NT_SUCCESS(ntStat))
        {
            if (SystemInformationClass == SystemKernelDebuggerInformation)
            {
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
            }
            else if (SystemInformationClass == SystemProcessInformation)
            {
                FilterProcess((PSYSTEM_PROCESS_INFORMATION)SystemInformation);
            }
        }

        return ntStat;
    }
    return dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

static ULONG ValueProcessBreakOnTermination = FALSE;

NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    if (ProcessHandle == NtCurrentProcess || GetCurrentProcessId() == GetProcessIdByProcessHandle(ProcessHandle))
    {
        NTSTATUS ntStat = dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

        if (NT_SUCCESS(ntStat))
        {
            if (ProcessInformationClass == ProcessDebugFlags)
            {
                *((ULONG *)ProcessInformation) = 1;
            }
            else if (ProcessInformationClass == ProcessDebugObjectHandle)
            {
                *((HANDLE *)ProcessInformation) = 0;
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
        }

        return ntStat;
    }
    return dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
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
	}
	return dNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS NTAPI HookedNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
    NTSTATUS ntStat = dNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

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
    dNtYieldExecution();
    return STATUS_SUCCESS;
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

    NTSTATUS ntStat = dNtGetContextThread(ThreadHandle, ThreadContext);

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

    NTSTATUS ntStat = dNtSetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
    }

    return ntStat;
}

VOID NTAPI HookedKiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame)
{
    return dKiUserExceptionDispatcher(pExcptRec, ContextFrame);
}

NTSTATUS NTAPI HookedNtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert)
{
    if(ThreadContext) {
        ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    }

    return dNtContinue(ThreadContext, RaiseAlert);
}

NTSTATUS NTAPI HookedNtClose(HANDLE Handle)
{
#define STATUS_HANDLE_NOT_CLOSABLE       ((NTSTATUS)0xC0000235L)

	OBJECT_HANDLE_FLAG_INFORMATION flags;
	flags.ProtectFromClose = 0;
	flags.Inherit = 0;
	if (NtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), 0) >= 0)
	{
		if (flags.ProtectFromClose)
		{
			return STATUS_HANDLE_NOT_CLOSABLE;
		}

		return dNtClose(Handle);
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
        OneTickCount = dGetTickCount();
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
	return dNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
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

    if (pObject->TypeName.Length == (sizeof(strDebugObject)-sizeof(WCHAR)))
    {
        if (!memcmp(strDebugObject, pObject->TypeName.Buffer, pObject->TypeName.Length))
        {
            pObject->TotalNumberOfObjects = 0;
            pObject->TotalNumberOfHandles = 0;
        }
    }

}

void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

    while (TRUE)
    {
        if (IsProcessBad(pInfo->ImageName.Buffer, pInfo->ImageName.Length))
        {
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