#include "CustomExceptionHandler.h"
#include <Scylla/Logger.h>
#include <Scylla/Settings.h>

#include "Injector.h"
#include "..\InjectorCLI\RemoteHook.h"


t_WaitForDebugEvent dWaitForDebugEvent = 0;
t_ContinueDebugEvent dContinueDebugEvent = 0;

typedef bool (__cdecl * t_IsAddressBreakpoint)(DWORD_PTR address);

extern scl::Settings g_settings;
extern scl::Logger g_log;

char OutputDebugStringBuffer[500] = {0};

t_IsAddressBreakpoint _IsAddressBreakpoint = 0;

void handleOutputDebugString( LPDEBUG_EVENT lpDebugEvent )
{
	if (lpDebugEvent->u.DebugString.nDebugStringLength > 0 && lpDebugEvent->u.DebugString.lpDebugStringData != 0)
	{
		HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, lpDebugEvent->dwProcessId);

		if (hProcess)
		{
			if (lpDebugEvent->u.DebugString.nDebugStringLength < sizeof(OutputDebugStringBuffer))
			{
				ZeroMemory(OutputDebugStringBuffer, sizeof(OutputDebugStringBuffer));
				if (ReadProcessMemory(hProcess, lpDebugEvent->u.DebugString.lpDebugStringData, OutputDebugStringBuffer, lpDebugEvent->u.DebugString.nDebugStringLength, NULL))
				{
					g_log.LogInfo(L"[ScyllaHide] Debug String: %S", OutputDebugStringBuffer);
				}
			}
			else
			{
                g_log.LogInfo(L"[ScyllaHide] Debug String is too long: %d", lpDebugEvent->u.DebugString.nDebugStringLength);
			}
			CloseHandle(hProcess);
		}
	}
	else
	{
        g_log.LogInfo(L"[ScyllaHide] Detected possible Anti-Debug method - OUTPUT_DEBUG_STRING");
	}
}

void handleRipEvent( LPDEBUG_EVENT lpDebugEvent )
{
	if (lpDebugEvent->u.RipInfo.dwError == 0)
	{
        g_log.LogInfo(L"[ScyllaHide] Detected possible Anti-Debug method - RIP Exception");
		return;
	}

	if (lpDebugEvent->u.RipInfo.dwType == 0)
	{
        g_log.LogInfo(L"[ScyllaHide] RIP Exception: Error 0x%X Type NONE", lpDebugEvent->u.RipInfo.dwError);
	}
	else if (lpDebugEvent->u.RipInfo.dwType == SLE_ERROR)
	{
        g_log.LogInfo(L"[ScyllaHide] RIP Exception: Error 0x%X Type SLE_ERROR", lpDebugEvent->u.RipInfo.dwError);
	}
	else if (lpDebugEvent->u.RipInfo.dwType == SLE_MINORERROR)
	{
        g_log.LogInfo(L"[ScyllaHide] RIP Exception: Error 0x%X Type SLE_MINORERROR", lpDebugEvent->u.RipInfo.dwError);
	}
	else if (lpDebugEvent->u.RipInfo.dwType == SLE_WARNING)
	{
        g_log.LogInfo(L"[ScyllaHide] RIP Exception: Error 0x%X Type SLE_WARNING", lpDebugEvent->u.RipInfo.dwError);
	}

}

DWORD_PTR hNtdll = 0;
DWORD_PTR hKernel = 0;

bool IsNotInsideKernelOrNtdll( DWORD dwProcessId, DWORD_PTR address )
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);

	DWORD imageSizeNtdll = pNt->OptionalHeader.SizeOfImage;

	pDos = (PIMAGE_DOS_HEADER)hKernel;
	pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);

	DWORD imageSizeKernel = pNt->OptionalHeader.SizeOfImage;

	if (address > hNtdll && address < (hNtdll + imageSizeNtdll))
	{
		return false;
	}
	else if (address > hKernel && address < (hKernel + imageSizeKernel))
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool AnalyzeDebugStructure( LPDEBUG_EVENT lpDebugEvent )
{
    if (g_settings.opts().handleExceptionPrint != 0 && lpDebugEvent->dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT)
	{
		handleOutputDebugString(lpDebugEvent);
		return true;
	}
    else if (g_settings.opts().handleExceptionRip != 0 && lpDebugEvent->dwDebugEventCode == RIP_EVENT)
	{
		handleRipEvent(lpDebugEvent);
		return true;
	}
	else if (lpDebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
        if (g_settings.opts().handleExceptionIllegalInstruction != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
		{
            g_log.LogInfo(L"[ScyllaHide] Illegal Instruction %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
        else if (g_settings.opts().handleExceptionInvalidLockSequence != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_INVALID_LOCK_SEQUENCE)
		{
            g_log.LogInfo(L"[ScyllaHide] Invalid Lock Sequence %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
        else if (g_settings.opts().handleExceptionNoncontinuableException != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_NONCONTINUABLE_EXCEPTION)
		{
            g_log.LogInfo(L"[ScyllaHide] Non-continuable Exception %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
        else if (g_settings.opts().handleExceptionAssertionFailure != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_ASSERTION_FAILURE)
		{
            g_log.LogInfo(L"[ScyllaHide] Assertion Failure %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
        else if (g_settings.opts().handleExceptionBreakpoint != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT)
		{
			if (_IsAddressBreakpoint((DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress) == false)
			{
				//system breakpoint?
				if (IsNotInsideKernelOrNtdll(lpDebugEvent->dwProcessId, (DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress))
				{
                    g_log.LogInfo(L"[ScyllaHide] Breakpoint %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
					return true;
				}
			}
		}
        else if (g_settings.opts().handleExceptionWx86Breakpoint != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT)
		{
			if (_IsAddressBreakpoint((DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress) == false)
			{
				//system breakpoint?
				if (IsNotInsideKernelOrNtdll(lpDebugEvent->dwProcessId, (DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress))
				{
                    g_log.LogInfo(L"[ScyllaHide] Wx86 Breakpoint %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
					return true;
				}
			}
		}
        else if (g_settings.opts().handleExceptionGuardPageViolation != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
            g_log.LogInfo(L"[ScyllaHide] Guard Page Violation %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
	}

	return false;
}

BOOL WINAPI HookedWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
	BOOL retV = dWaitForDebugEvent(lpDebugEvent, dwMilliseconds);

	if (retV)
	{
		while(1)
		{
			if (AnalyzeDebugStructure(lpDebugEvent))
			{
				ContinueDebugEvent(lpDebugEvent->dwProcessId, lpDebugEvent->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);

				retV = dWaitForDebugEvent(lpDebugEvent, dwMilliseconds);
				if (!retV)
				{
					break;
				}
			}
			else
			{
				break;
			}
		}
	}

	return retV;
}

BOOL WINAPI HookedContinueDebugEvent(DWORD dwProcessId,DWORD dwThreadId,DWORD dwContinueStatus)
{
	BOOL retV = dContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus);
	return retV;
}


void HookDebugLoop()
{
	hNtdll = (DWORD_PTR)GetModuleHandleW(L"ntdll.dll");
	hKernel = (DWORD_PTR)GetModuleHandleW(L"kernel32.dll");

	BYTE * WaitForIt = (BYTE *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "WaitForDebugEvent");
	BYTE * ContinueIt = (BYTE *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ContinueDebugEvent");

	if (*WaitForIt == 0xE9 || *WaitForIt == 0x68) //JMP, PUSH
	{
		MessageBoxW(0, L"kernel32.dll - WaitForDebugEvent is hooked already!", L"Error", MB_ICONERROR);
	}
	else if (*ContinueIt == 0xE9 || *ContinueIt == 0x68) //JMP, PUSH
	{
		MessageBoxW(0, L"kernel32.dll - ContinueDebugEvent is hooked already!", L"Error", MB_ICONERROR);
	}
	else
	{
		dWaitForDebugEvent = (t_WaitForDebugEvent)DetourCreate(WaitForIt,HookedWaitForDebugEvent, true);
		//dContinueDebugEvent = (t_ContinueDebugEvent)DetourCreate(ContinueIt,HookedContinueDebugEvent, true);
	}
}
