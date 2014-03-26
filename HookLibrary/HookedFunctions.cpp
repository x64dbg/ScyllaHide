#include "ntdll.h"
#include "HookedFunctions.h"
#include "HookHelper.h"


t_NtSetInformationThread dNtSetInformationThread = 0;
t_NtQuerySystemInformation dNtQuerySystemInformation = 0;
t_NtQueryInformationProcess dNtQueryInformationProcess = 0;


NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
	if (ThreadInformationClass == ThreadHideFromDebugger && ThreadInformation == 0 && ThreadInformationLength == 0 && IsValidThreadHandle(ThreadHandle))
	{
		return STATUS_SUCCESS;
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
				PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
				PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

				while (TRUE)
				{
					if (IsProcessBad(pInfo->ImageName.Buffer, pInfo->ImageName.Length))
					{
						ZeroMemory(pInfo->ImageName.Buffer, pInfo->ImageName.Length);

						if (pInfo->NextEntryOffset == 0) //last element
						{
							pPrev->NextEntryOffset = 0;
							break;
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
		}
		else
		{
			return ntStat;
		}
	}
	return dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

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
				return ntStat;
			}
			else if (ProcessInformationClass == ProcessDebugObjectHandle)
			{
				*((HANDLE *)ProcessInformation) = 0;
				return ntStat;
			}
			else if (ProcessInformationClass == ProcessDebugPort)
			{
				*((HANDLE *)ProcessInformation) = 0;
				return ntStat;
			}
			else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
			{
				((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = (HANDLE)GetExplorerProcessId();
				return ntStat;
			}
		}
		else
		{
			return ntStat;
		}
	}
	return dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}