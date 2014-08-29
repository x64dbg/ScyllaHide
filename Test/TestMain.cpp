#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <commdlg.h>
#include <time.h> 
#include <Psapi.h>

#include "..\ntdll\ntdll.h"
#include <string>

#pragma comment(lib,"Winmm.lib")
#pragma comment(lib,"psapi.lib")

#pragma comment(linker, "/ENTRY:WinMain")

void ShowMessageBox(const char * format, ...);
void Test_NtSetInformationThread();
void Test_RtlProcessFlsData();
void SuccessMethod();
void Test_OutputDebugString();
void Test_NtQueryObject1();
void Test_NtQueryObject2();
DWORD GetProcessIdByThreadHandle(HANDLE hThread);
void Test_NtQueryInformationProcess();
void Test_FindWindow();
void Test_NtSetDebugFilterState();
void Test_NtGetContextThread();
void Test_PEB();
void Test_StartUpInfo();
void Test_Time();
void Test_HandleTracing();
void Test_DebugPrivileges();
bool IsSysWow64();
void Test_RunpeUnpacker();
void Test_AntiAttach();

BYTE memory[0x3000] = { 0 };


int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	//ShowMessageBox("%d\n", sizeof(UNICODE_STRING));

	Test_AntiAttach();;

	//Test_RunpeUnpacker();
	//Test_DebugPrivileges();
	//Test_HandleTracing();
	//Test_Time();
	//Test_StartUpInfo();
	//Test_PEB();
	//Test_NtGetContextThread();
	//Test_NtSetDebugFilterState();
	//Test_FindWindow();
	//Test_NtSetInformationThread();
	//Test_RtlProcessFlsData();
	//Test_OutputDebugString();
	//Test_NtQueryInformationProcess();
	//Test_NtQueryObject2();
	//Test_NtQueryObject1();
	ExitProcess(0);
	return 0;
}

void ShowMessageBox(const char * format, ...)
{
	char text[2000];
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfA(text, format, va_alist);

	MessageBoxA(0, text, "Text", 0);
}

void Test_AntiAttach()
{
	BYTE NopDbgBreakPoint[] = {0xC3};
	BYTE BytesExit32[] = {0xB8 ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF ,0xE0};
	BYTE BytesExit64[] = {0x48,0xB8  ,0xFF ,0xFF ,0xFF ,0xFF ,0xFF,0xFF ,0xFF ,0xFF ,0xFF ,0xE0};

	BYTE * pFuncDbgBreakPoint = (BYTE*)DbgBreakPoint;
	BYTE * pFuncDbgBreakUiRemoteBreakin = (BYTE*)DbgUiRemoteBreakin;
	BYTE * pFuncNtContinue = (BYTE*)NtContinue;
	
#ifdef _WIN64
	DWORD_PTR * pAddr = (DWORD_PTR *)&BytesExit64[2];
	int byteSize = sizeof(BytesExit64);
	BYTE * patch = BytesExit64;
#else
	DWORD_PTR * pAddr = (DWORD_PTR *)&BytesExit32[1];
	int byteSize = sizeof(BytesExit32);
	BYTE * patch = BytesExit32;
#endif
	*pAddr = (DWORD_PTR)ExitProcess;

	WriteProcessMemory(GetCurrentProcess(), pFuncDbgBreakPoint, NopDbgBreakPoint, sizeof(NopDbgBreakPoint), 0);

	MessageBoxA(0, "DbgBreakPoint patched, attach now", "Attach", MB_OK);

	WriteProcessMemory(GetCurrentProcess(), pFuncDbgBreakUiRemoteBreakin, patch, byteSize, 0);

	MessageBoxA(0, "DbgUiRemoteBreakin patched, attach now", "Attach", MB_OK);

	WriteProcessMemory(GetCurrentProcess(), pFuncNtContinue, patch, byteSize, 0);

	MessageBoxA(0, "NtContinue patched, attach now", "Attach", MB_OK);
	
	MessageBoxA(0, "Am I still running? Cool", "Attach", MB_OK);
}

void Test_RunpeUnpacker()
{
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	WCHAR path[] = L"InjectorCLIx86.exe";

	CreateProcessW(0,path,0,0,0,CREATE_SUSPENDED,0,0,&si, &pi);
	ResumeThread(pi.hThread);
}

#define PROCESS_HANDLE_TRACING_MAX_STACKS 16

typedef struct _PROCESS_HANDLE_TRACING_ENTRY
{
	HANDLE Handle;
	CLIENT_ID ClientId;
	ULONG Type;
	PVOID Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} PROCESS_HANDLE_TRACING_ENTRY, *PPROCESS_HANDLE_TRACING_ENTRY;

typedef struct _PROCESS_HANDLE_TRACING_QUERY {
	HANDLE Handle;
	ULONG  TotalTraces;
	PROCESS_HANDLE_TRACING_ENTRY HandleTrace[1];
} PROCESS_HANDLE_TRACING_QUERY, *PPROCESS_HANDLE_TRACING_QUERY;

typedef struct _CLIENT_ID64
{
	ULONGLONG UniqueProcess;
	ULONGLONG UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

typedef struct _PROCESS_HANDLE_TRACING_ENTRY64
{
	ULONGLONG Handle;
	CLIENT_ID64 ClientId;
	ULONG Type;
	ULONGLONG Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} PROCESS_HANDLE_TRACING_ENTRY64, *PPROCESS_HANDLE_TRACING_ENTRY64;

typedef struct _PROCESS_HANDLE_TRACING_QUERY64 {
	ULONGLONG Handle;
	ULONG  TotalTraces;
	PROCESS_HANDLE_TRACING_ENTRY64 HandleTrace[1];
} PROCESS_HANDLE_TRACING_QUERY64, *PPROCESS_HANDLE_TRACING_QUERY64;

typedef struct _PROCESS_HANDLE_TRACING_ENABLE {
	ULONG Flags;
} PROCESS_HANDLE_TRACING_ENABLE, *PPROCESS_HANDLE_TRACING_ENABLE;


LONG NTAPI HandleTracingExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (STATUS_INVALID_HANDLE == ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
#ifndef _WIN64
		ShowMessageBox("ExceptionCode %X ExceptionAddress %p EIP %p", ExceptionInfo->ExceptionRecord->ExceptionCode,ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Eip);
#else
		ShowMessageBox("ExceptionCode %X ExceptionAddress %p RIP %p", ExceptionInfo->ExceptionRecord->ExceptionCode,ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord->Rip);
#endif
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

}
void Test_HandleTracing()
{
	NTSTATUS ntStat;
	PROCESS_HANDLE_TRACING_ENABLE tracing = {0};
	PPROCESS_HANDLE_TRACING_QUERY query = (PPROCESS_HANDLE_TRACING_QUERY)memory;
	PPROCESS_HANDLE_TRACING_QUERY64 query64 = (PPROCESS_HANDLE_TRACING_QUERY64)memory;
	ULONG length = 0;

	AddVectoredExceptionHandler(1, HandleTracingExceptionHandler);

	ntStat = NtSetInformationProcess(NtCurrentProcess, ProcessHandleTracing, &tracing, sizeof(PROCESS_HANDLE_TRACING_ENABLE));

	HANDLE handleToTrace = (HANDLE)0xBAD;
	NtClose(handleToTrace);
	query->Handle = (HANDLE)handleToTrace;

	ntStat = NtQueryInformationProcess(NtCurrentProcess, ProcessHandleTracing, query, sizeof(memory), &length);

	if (ntStat == STATUS_INFO_LENGTH_MISMATCH)
	{
		//ShowMessageBox("NtQueryInformationProcess STATUS_INFO_LENGTH_MISMATCH %d %d",sizeof(PROCESS_HANDLE_TRACING_QUERY),length );
		//ntStat = NtQueryInformationProcess(NtCurrentProcess, ProcessHandleTracing, query, sizeof(memory), &length);
		//goto again;
		ShowMessageBox("NtQueryInformationProcess STATUS_INFO_LENGTH_MISMATCH");
	}
	else if (ntStat == STATUS_SUCCESS)
	{
		if (!IsSysWow64())
		{
			ShowMessageBox("Handle %X TotalTraces %d", query->Handle, query->TotalTraces);
		}
		else
		{
			ShowMessageBox("Handle %I64X TotalTraces %d", query64->Handle, query64->TotalTraces);
		}
		
	
		for (int j = 0; j < 2; j++)
		{
			if (!IsSysWow64())
			{
				ShowMessageBox("Type %d Handle %p UniqueProcess %p UniqueThread %p", 
					query->HandleTrace[j].Type, 
					query->HandleTrace[j].Handle, 
					query->HandleTrace[j].ClientId.UniqueProcess,
					query->HandleTrace[j].ClientId.UniqueThread);
			}
			else
			{
				ShowMessageBox("Type %d Handle %I64X UniqueProcess %I64X UniqueThread %I64X", 
					query64->HandleTrace[j].Type, 
					query64->HandleTrace[j].Handle, 
					query64->HandleTrace[j].ClientId.UniqueProcess,
					query64->HandleTrace[j].ClientId.UniqueThread);
			}

			for (int i = 0; i < PROCESS_HANDLE_TRACING_MAX_STACKS; i++)
			{
				if (!IsSysWow64())
				{
					if (query->HandleTrace[j].Stacks[i]) ShowMessageBox("Stack %d -> %p", i, query->HandleTrace[j].Stacks[i]);
				}
				else
				{
					if (query64->HandleTrace[j].Stacks[i]) ShowMessageBox("Stack %d -> %I64X", i, query64->HandleTrace[j].Stacks[i]);
				}
				
			}
		}
	}
	else
	{
		ShowMessageBox("NtQueryInformationProcess error %X", ntStat);
	}

}

void Test_DebugPrivileges()
{
	ULONG flags = 0;
	NTSTATUS ntStat;

	ntStat = NtQuerySystemInformation(SystemFlagsInformation, &ntStat, sizeof(ULONG), NULL);
	ntStat = NtSetSystemInformation(SystemFlagsInformation, &ntStat, sizeof(ULONG));

	if (ntStat >= 0)
	{
		ShowMessageBox("Debug Privileges enabled!");
	}
	else if (ntStat == STATUS_ACCESS_DENIED)
	{
		ShowMessageBox("Debug Privileges disabled!");
	}
	else
	{
		ShowMessageBox("Test_DebugPrivileges -> Something wrong %X!",ntStat);
	}

}

void Test_Time()
{
	SYSTEMTIME systime;
	SYSTEMTIME localtime;
	LARGE_INTEGER sysTimeNative;
	LARGE_INTEGER perform;
	LARGE_INTEGER frequen;

	LARGE_INTEGER performnative;
	LARGE_INTEGER frequennative;

	NTSTATUS ntstat = 0;

	ntstat = NtQuerySystemTime(&sysTimeNative);
	ntstat = NtQuerySystemTime(0);
	
	GetSystemTime(&systime);
	GetLocalTime(&localtime);

	QueryPerformanceCounter(&perform);
	QueryPerformanceFrequency(&frequen);

	ntstat = NtQueryPerformanceCounter(&performnative, &frequennative);
	ntstat = NtQueryPerformanceCounter(0, &frequennative);
	ntstat = NtQueryPerformanceCounter(&performnative, 0);
	ntstat = NtQueryPerformanceCounter(0, 0);

	DWORD tick = GetTickCount();
	ULONGLONG tick64 = GetTickCount64();
	DWORD time1 = timeGetTime();
}

void Test_StartUpInfo()
{
	STARTUPINFOA infoA = {0};
	STARTUPINFOW infoW = {0};

	GetStartupInfoW(&infoW);
	GetStartupInfoA(&infoA);

	ShowMessageBox("STARTUPINFOA\r\nOffset %X -> %X\r\nOffset %X -> %X\r\nOffset %X -> %X", offsetof(STARTUPINFOA, dwX),infoA.dwX,offsetof(STARTUPINFOA, dwY),infoA.dwY,offsetof(STARTUPINFOA, dwFillAttribute),infoA.dwFillAttribute);
	ShowMessageBox("STARTUPINFOW\r\nOffset %X -> %X\r\nOffset %X -> %X\r\nOffset %X -> %X", offsetof(STARTUPINFOW, dwX),infoW.dwX,offsetof(STARTUPINFOW, dwY),infoW.dwY,offsetof(STARTUPINFOW, dwFillAttribute),infoW.dwFillAttribute);
}

void Test_PEB()
{
	BYTE BeingDebugged = 0;
	DWORD NtGlobalFlags = 0;
	DWORD_PTR processHeap = 0;
	DWORD ForceFlags = 0;
	DWORD Flags = 0;
	DWORD protectedHeap = 0;

	DWORD_PTR pPeb = 0;
#ifdef _WIN64
#define PEB_BeingDebugged 0x2
#define PEB_NtGlobalFlags 0xBC
#define PEB_ProcessHeap 0x30
	pPeb = (DWORD_PTR)__readgsqword(12 * sizeof(DWORD_PTR));
#else
#define PEB_BeingDebugged 0x2
#define PEB_NtGlobalFlags 0x68
#define PEB_ProcessHeap 0x18
	pPeb = (DWORD_PTR)__readfsdword(12 * sizeof(DWORD_PTR));
#endif

	BeingDebugged = *((BYTE *)(pPeb + PEB_BeingDebugged));
	NtGlobalFlags = *((DWORD *)(pPeb + PEB_NtGlobalFlags));
	processHeap = *((DWORD_PTR *)(pPeb + PEB_ProcessHeap));

	DWORD dwVersion = GetVersion();
	DWORD dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	DWORD dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	int FlagsOffset = 0x0C;
	int ForceFlagsOffset = 0x10;

#ifdef _WIN64
	if (dwMajorVersion >= 6)
	{
		FlagsOffset = 0x70;
		ForceFlagsOffset = 0x74;	
	}
	else
	{
		FlagsOffset = 0x14;
		ForceFlagsOffset = 0x18;
	}
#else

	if (dwMajorVersion >= 6)
	{
		FlagsOffset = 0x40;
		ForceFlagsOffset = 0x44;
	}
	else
	{
		FlagsOffset = 0x0C;
		ForceFlagsOffset = 0x10;
	}
#endif

	ForceFlags = *((DWORD *)(processHeap + ForceFlagsOffset));
	Flags = *((DWORD *)(processHeap + FlagsOffset));

	ShowMessageBox("BeingDebugged %u == 1?\r\nNtGlobalFlags 0x%X == 0x70?\r\n\r\nProcessHeap %p\r\n\r\nForceFlags != 0? %X Flags %X != 2?",BeingDebugged,NtGlobalFlags, processHeap,ForceFlags,Flags);

}
void Test_NtGetContextThread()
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	NtGetContextThread(NtCurrentThread, &ctx);

	ShowMessageBox("NtGetContextThread flags %X Drx %X %X %X %X %X %X",ctx.ContextFlags, ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3, ctx.Dr6, ctx.Dr7);
}

void Test_NtSetDebugFilterState()
{
	NTSTATUS ntstat = NtSetDebugFilterState(0, 0, TRUE);

	ShowMessageBox("NtSetDebugFilterState return status %X", ntstat);
}
void Test_FindWindow()
{
	HANDLE hOlly = FindWindowW(L"OLLYDBG", NULL);
	if (hOlly)
	{
		ShowMessageBox("FindWindow hOlly");
	}

	hOlly = FindWindowExW(0,0,L"OLLYDBG", 0);
	if (hOlly)
	{
		ShowMessageBox("FindWindowEx hOlly");
	}

	hOlly = FindWindowW(L"OLLYDBGss", 0);
	if (hOlly)
	{
		ShowMessageBox("This should not be possible");
	}
	else
	{
		ShowMessageBox("FindWindowW Not found last error %d", GetLastError());
	}

	hOlly = FindWindowExW(0, 0, L"OLLYDBGss", 0);
	if (hOlly)
	{
		ShowMessageBox("This should not be possible");
	}
	else
	{
		ShowMessageBox("FindWindowExW Not found last error %d", GetLastError());
	}
}

void Test_NtQueryInformationProcess()
{
	HANDLE port = 0;
	ULONG flags = 0;
	NTSTATUS ntstat = NtQueryInformationProcess(NtCurrentProcess, ProcessDebugPort, &port, sizeof(HANDLE), 0);

	ShowMessageBox("ProcessDebugPort %p, %X", port, ntstat);

	ntstat = NtQueryInformationProcess(NtCurrentProcess, ProcessDebugObjectHandle, &port, sizeof(HANDLE), 0);

	ShowMessageBox("ProcessDebugObjectHandle %p, %X", port, ntstat);
}

void Test_OutputDebugString()
{
	typedef DWORD(WINAPI * t_OutputDebugStringA)(LPCSTR lpOutputString); //Kernel32.dll
	typedef DWORD(WINAPI * t_OutputDebugStringW)(LPCWSTR lpOutputString); //Kernel32.dll

	t_OutputDebugStringA _OutputDebugStringA = (t_OutputDebugStringA)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OutputDebugStringA");
	t_OutputDebugStringW _OutputDebugStringW = (t_OutputDebugStringW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OutputDebugStringW");


	ShowMessageBox("OutputDebugStringA return value %X\n", _OutputDebugStringA("test"));
	ShowMessageBox("Last error %X\n", GetLastError());

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



void Test_NtQueryObject2()
{
	HANDLE debugObject;
	OBJECT_ATTRIBUTES oa;
	//	OBJECT_BASIC_INFORMATION obBasic;
	POBJECT_NAME_INFORMATION obName = (POBJECT_NAME_INFORMATION)memory;
	POBJECT_TYPE_INFORMATION objectType = (POBJECT_TYPE_INFORMATION)memory;
	InitializeObjectAttributes(&oa,0,0,0,0);

	if (NT_SUCCESS(NtCreateDebugObject(&debugObject, DEBUG_ALL_ACCESS, &oa, DEBUG_KILL_ON_CLOSE)))
	{
		NTSTATUS ntStat = NtQueryObject(debugObject, ObjectTypeInformation, objectType, sizeof(memory), 0);
		if (NT_SUCCESS(ntStat))
		{
			ShowMessageBox("DebugObject TotalNumberOfHandles %08X\r\nTotalNumberOfObjects %08X\r\n", objectType->TotalNumberOfHandles, objectType->TotalNumberOfObjects);
		}
		NtClose(debugObject);
	}
}

void Test_NtQueryObject1()
{
	const wchar_t DebugObject[] = L"DebugObject";
	const int DebugObjectLength = sizeof(DebugObject)-sizeof(wchar_t);

	ULONG ret;
	POBJECT_TYPES_INFORMATION pObjTypes = (POBJECT_TYPES_INFORMATION)VirtualAlloc(0,0x3000, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	NTSTATUS ntStat = NtQueryObject(0, ObjectTypesInformation, pObjTypes, 0x3000, &ret);

	if (ntStat >= 0)
	{
		POBJECT_TYPE_INFORMATION pOb = pObjTypes->TypeInformation;
		for (ULONG i = 0; i < pObjTypes->NumberOfTypes; i++)
		{
			if (pOb->TypeName.Length == DebugObjectLength && !memcmp(pOb->TypeName.Buffer, DebugObject, DebugObjectLength))
			{
				ShowMessageBox("DebugObject TotalNumberOfHandles %08X\r\nTotalNumberOfObjects %08X\r\n", pOb->TotalNumberOfHandles,pOb->TotalNumberOfObjects);
				break;
			}
			pOb = (POBJECT_TYPE_INFORMATION)(((PCHAR)(pOb + 1) + ALIGN_UP(pOb->TypeName.MaximumLength, ULONG_PTR)));
		}
	}

}

FLS_CALLBACK_INFO info = { 0 };

void Test_RtlProcessFlsData()
{
	info.unk1 = (LPVOID)(GetTickCount() + 1); //Random value
	info.address = SuccessMethod;
	info.unk4 = (LPVOID)1;
	PRTL_UNKNOWN_FLS_DATA pData = (PRTL_UNKNOWN_FLS_DATA)&info.unk2;

	DWORD_PTR pPeb = 0;
#ifdef _WIN64
#define PEB_FLS_CALLBACK_OFFSET 0x0320
#define PEB_FLS_HIGHINDEX_OFFSET 0x0350
	pPeb = (DWORD_PTR)__readgsqword(12 * sizeof(DWORD_PTR));
#else
#define PEB_FLS_CALLBACK_OFFSET 0x020C
#define PEB_FLS_HIGHINDEX_OFFSET 0x022C
	pPeb = (DWORD_PTR)__readfsdword(12 * sizeof(DWORD_PTR));
#endif

	ULONG * FlsHighIndex = (ULONG *)(pPeb + PEB_FLS_HIGHINDEX_OFFSET);
	DWORD_PTR * FlsCallback = (DWORD_PTR *)(pPeb + PEB_FLS_CALLBACK_OFFSET);
	*FlsCallback = (DWORD_PTR)&info;
	*FlsHighIndex = *FlsHighIndex + 1;

	RtlProcessFlsData(pData);
}

void SuccessMethod()
{
	ShowMessageBox("Target runs, nice!");
}

void Test_NtSetInformationThread()
{
	NTSTATUS ntStat;
	BOOLEAN check = FALSE;

	ntStat = NtSetInformationThread(NtCurrentThread, ThreadHideFromDebugger, &check, sizeof(ULONG));

	if (ntStat >= 0) //it must fail
	{
		ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
	}

	ntStat = NtSetInformationThread(NtCurrentThread, ThreadHideFromDebugger, 0, 0);

	if (ntStat >= 0)
	{
		ntStat = NtQueryInformationThread(NtCurrentThread, ThreadHideFromDebugger, &check, sizeof(BOOLEAN), 0);
		if (ntStat >= 0)
		{
			if (!check)
			{
				ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
			}
			else
			{
				ShowMessageBox("Everything ok!\n");
			}
		}
		else
		{
			ShowMessageBox("NtQueryInformationThread ThreadHideFromDebugger failed %X!\n", ntStat);
		}
	}
	else
	{
		ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
	}
}

bool IsSysWow64()
{
#ifndef _WIN64
	return ((DWORD)__readfsdword(0xC0) != 0);

#else
	return false;
#endif
}
