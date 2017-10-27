#include "OllyExceptionHandler.h"
#include <Scylla/Logger.h>
#include <Scylla/Settings.h>

#include "Injector.h"
#include "..\InjectorCLI\RemoteHook.h"


t_WaitForDebugEvent dWaitForDebugEvent = nullptr;

#ifdef OLLY1
typedef bool (__cdecl * t_IsAddressBreakpoint)(DWORD_PTR address);
t_IsAddressBreakpoint _IsAddressBreakpoint = nullptr;
#endif

extern scl::Settings g_settings;
extern scl::Logger g_log;

char OutputDebugStringBuffer[500] = {0};

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
					g_log.LogInfo(L"Debug String: %S", OutputDebugStringBuffer);
				}
			}
			else
			{
                g_log.LogInfo(L"Debug String is too long: %d", lpDebugEvent->u.DebugString.nDebugStringLength);
			}
			CloseHandle(hProcess);
		}
	}
	else
	{
        g_log.LogInfo(L"Detected possible Anti-Debug method - OUTPUT_DEBUG_STRING");
	}
}

void handleRipEvent( LPDEBUG_EVENT lpDebugEvent )
{
	if (lpDebugEvent->u.RipInfo.dwError == 0)
	{
        g_log.LogInfo(L"Detected possible Anti-Debug method - RIP Exception");
		return;
	}

	if (lpDebugEvent->u.RipInfo.dwType == 0)
	{
        g_log.LogInfo(L"RIP Exception: Error 0x%X Type NONE", lpDebugEvent->u.RipInfo.dwError);
	}
	else if (lpDebugEvent->u.RipInfo.dwType == SLE_ERROR)
	{
        g_log.LogInfo(L"RIP Exception: Error 0x%X Type SLE_ERROR", lpDebugEvent->u.RipInfo.dwError);
	}
	else if (lpDebugEvent->u.RipInfo.dwType == SLE_MINORERROR)
	{
        g_log.LogInfo(L"RIP Exception: Error 0x%X Type SLE_MINORERROR", lpDebugEvent->u.RipInfo.dwError);
	}
	else if (lpDebugEvent->u.RipInfo.dwType == SLE_WARNING)
	{
        g_log.LogInfo(L"RIP Exception: Error 0x%X Type SLE_WARNING", lpDebugEvent->u.RipInfo.dwError);
	}

}

DWORD_PTR hNtdll = 0;
DWORD_PTR hKernel = 0;

bool IsInsideKernelOrNtdll( DWORD_PTR address )
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);

	DWORD imageSizeNtdll = pNt->OptionalHeader.SizeOfImage;

	pDos = (PIMAGE_DOS_HEADER)hKernel;
	pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);

	DWORD imageSizeKernel = pNt->OptionalHeader.SizeOfImage;

	return (address > hNtdll && address < (hNtdll + imageSizeNtdll)) ||
			(address > hKernel && address < (hKernel + imageSizeKernel));
}

bool AnalyzeDebugStructure( LPDEBUG_EVENT lpDebugEvent )
{
    if (g_settings.opts().handleExceptionPrint != 0 && lpDebugEvent->dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT)
	{
		handleOutputDebugString(lpDebugEvent);
		return true;
	}

    if (g_settings.opts().handleExceptionRip != 0 && lpDebugEvent->dwDebugEventCode == RIP_EVENT)
	{
		handleRipEvent(lpDebugEvent);
		return true;
	}

    if (lpDebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
        if (g_settings.opts().handleExceptionIllegalInstruction != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
		{
            g_log.LogInfo(L"Illegal Instruction %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
        if (g_settings.opts().handleExceptionInvalidLockSequence != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_INVALID_LOCK_SEQUENCE)
		{
            g_log.LogInfo(L"Invalid Lock Sequence %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
        if (g_settings.opts().handleExceptionNoncontinuableException != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_NONCONTINUABLE_EXCEPTION)
		{
            g_log.LogInfo(L"Non-continuable Exception %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
        if (g_settings.opts().handleExceptionAssertionFailure != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_ASSERTION_FAILURE)
		{
            g_log.LogInfo(L"Assertion Failure %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
			return true;
		}
#ifdef OLLY1 // This may or may not be needed for Olly v2, but we don't have IsAddressBreakPoint() there
        if (g_settings.opts().handleExceptionBreakpoint != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT)
		{
			if (_IsAddressBreakpoint((DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress) == false)
			{
				//system breakpoint?
				if (!IsInsideKernelOrNtdll((DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress))
				{
                    g_log.LogInfo(L"Breakpoint %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
					return true;
				}
			}
		}
        else if (g_settings.opts().handleExceptionWx86Breakpoint != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT)
		{
			if (_IsAddressBreakpoint((DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress) == false)
			{
				//system breakpoint?
				if (!IsInsideKernelOrNtdll((DWORD_PTR)lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress))
				{
                    g_log.LogInfo(L"Wx86 Breakpoint %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
					return true;
				}
			}
		}
#endif
        else if (g_settings.opts().handleExceptionGuardPageViolation != 0 && lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		{
            g_log.LogInfo(L"Guard Page Violation %p", lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
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

void HookDebugLoop()
{
	hNtdll = (DWORD_PTR)GetModuleHandleW(L"ntdll.dll");
	hKernel = (DWORD_PTR)GetModuleHandleW(L"kernel32.dll");

	BYTE * WaitForIt = (BYTE *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "WaitForDebugEvent");

	if (*WaitForIt == 0xE9 || *WaitForIt == 0x68) //JMP, PUSH
	{
		MessageBoxW(0, L"kernel32.dll - WaitForDebugEvent is hooked already!", L"Error", MB_ICONERROR);
	}
	else
	{
		dWaitForDebugEvent = (t_WaitForDebugEvent)DetourCreate(WaitForIt,HookedWaitForDebugEvent, true);
	}
}
