#include "Injector.h"
#include "plugin.h"
#include "..\InjectorCLI\RemoteHook.h"
#include "..\InjectorCLI\RemotePebHider.h"
#include "..\InjectorCLI\\ApplyHooking.h"

extern struct HideOptions pHideOptions;

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };

static LPVOID remoteImageBase = 0;

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
t_LogWrapper LogWrap = 0;


void StartFixBeingDebugged(DWORD targetPid, bool setToNull)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
    if (hProcess)
    {
        FixPebBeingDebugged(hProcess, setToNull);
        CloseHandle(hProcess);
    }
}

bool StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    DllExchangeLoader.dwProtectedProcessId = GetCurrentProcessId(); //for olly plugins
    DllExchangeLoader.EnableProtectProcessId = TRUE;

    DWORD enableFlags = 0x0;
    if(pHideOptions.PEBBeingDebugged) enableFlags |= PEB_PATCH_BeingDebugged;
    if(pHideOptions.PEBHeapFlags) enableFlags |= PEB_PATCH_HeapFlags;
    if(pHideOptions.PEBNtGlobalFlag) enableFlags |= PEB_PATCH_NtGlobalFlag;
    if(pHideOptions.PEBStartupInfo) enableFlags |= PEB_PATCH_StartUpInfo;

    ApplyPEBPatch(&DllExchangeLoader, hProcess, enableFlags);

    return ApplyHook(&DllExchangeLoader, hProcess, dllMemory, imageBase);
}

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess)
{
    DWORD initDllFuncAddressRva = GetDllFunctionAddressRVA(dllMemory, "InitDll");
    DWORD exchangeDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "DllExchange");

    if (newProcess == false)
    {
        Message(0, L"[ScyllaHide] Apply hooks again");
        StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase);
        WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0);
    }
    else
    {
        RestoreHooks(&DllExchangeLoader, hProcess);

        remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
        if (remoteImageBase)
        {
            FillExchangeStruct(hProcess, &DllExchangeLoader);


            StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase);

            if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0))
            {
                Message(0, L"[ScyllaHide] Injection successful, Imagebase %p", remoteImageBase);
            }
            else
            {
                Message(0, L"[ScyllaHide] Failed to write exchange struct");
            }
        }
        else
        {
            Message(0, L"[ScyllaHide] Failed to map image!");
        }
    }
}

void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
    if (hProcess)
    {
        BYTE * dllMemory = ReadFileToMemory(dllPath);
        if (dllMemory)
        {
            startInjectionProcess(hProcess, dllMemory, newProcess);
            free(dllMemory);
        }
        else
        {
            Error(L"[ScyllaHide] Cannot find %s", dllPath);
        }
        CloseHandle(hProcess);
    }
    else
    {
        Error(L"[ScyllaHide] Cannot open process handle %d", targetPid);
    }
}

LPVOID NormalDllInjection( HANDLE hProcess, const WCHAR * dllPath )
{
	SIZE_T memorySize = (wcslen(dllPath) + 1) * sizeof(WCHAR);

	LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, memorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	DWORD hModule = 0;

	if (!remoteMemory)
	{
		LogWrap(L"[ScyllaHide] DLL INJECTION: VirtualAllocEx failed!");
		return 0;
	}

	if (WriteProcessMemory(hProcess, remoteMemory, dllPath, memorySize, 0))
	{
		HANDLE hThread = CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)LoadLibraryW,remoteMemory,CREATE_SUSPENDED, 0);
		if (hThread)
		{
			SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
			NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);
			ResumeThread(hThread);

			WaitForSingleObject(hThread, INFINITE);

			GetExitCodeThread(hThread, &hModule);

			CloseHandle(hThread);
		}
		else
		{
			LogWrap(L"[ScyllaHide] DLL INJECTION: Failed to start thread!");
		}
	}
	else
	{
		LogWrap(L"[ScyllaHide] DLL INJECTION: Failed WriteProcessMemory!");
	}

	VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

	return (LPVOID)hModule;
}

LPVOID StealthDllInjection( HANDLE hProcess, const WCHAR * dllPath )
{
	LPVOID remoteImageBaseOfInjectedDll = 0;

	BYTE * dllMemory = ReadFileToMemory(dllPath);
	if (dllMemory)
	{
		remoteImageBaseOfInjectedDll = MapModuleToProcess(hProcess, dllMemory);
		if(remoteImageBaseOfInjectedDll)
		{
			PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dllMemory;
			PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);

			DWORD_PTR dllMain = pNt->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteImageBaseOfInjectedDll;

			HANDLE hThread = CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)dllMain,remoteImageBaseOfInjectedDll,CREATE_SUSPENDED, 0);
			if (hThread)
			{
				SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
				NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);
				ResumeThread(hThread);

				WaitForSingleObject(hThread, INFINITE);

				CloseHandle(hThread);
			}
			else
			{
				LogWrap(L"[ScyllaHide] DLL INJECTION: Failed to start thread!");
			}
		}
		else
		{
			LogWrap(L"[ScyllaHide] DLL INJECTION: Failed to map image of %s!", dllPath);
		}
		free(dllMemory);
	}

	return remoteImageBaseOfInjectedDll;
}

void injectDll(DWORD targetPid, const WCHAR * dllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
	if (hProcess)
	{
		LPVOID remoteImage = 0;

		if (pHideOptions.DLLStealth)
		{
			LogWrap(L"[ScyllaHide] Starting Stealth DLL Injection!");
			remoteImage = StealthDllInjection(hProcess, dllPath);
		}
		else if (pHideOptions.DLLNormal)
		{
			LogWrap(L"[ScyllaHide] Starting Normal DLL Injection!");
			remoteImage = NormalDllInjection(hProcess, dllPath);
			if (remoteImage)
			{
				LogWrap(L"[ScyllaHide] Injection of %s successful, Imagebase %p", dllPath, remoteImage);
				if (pHideOptions.DLLUnload)
				{
					LogWrap(L"[ScyllaHide] Unloading Imagebase %p", remoteImage);
					CloseHandle(CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)FreeLibrary,remoteImage, 0, 0));
				}
			}
		}
		else
		{
			LogWrap(L"[ScyllaHide] DLL INJECTION: No injection type selected!");
		}

		CloseHandle(hProcess);
	}
	else
	{
		LogWrap(L"[ScyllaHide] DLL INJECTION: Cannot open process handle %d", targetPid);
	}
}

BYTE * ReadFileToMemory(const WCHAR * targetFilePath)
{
    HANDLE hFile;
    DWORD dwBytesRead;
    DWORD FileSize;
    BYTE* FilePtr = 0;

    hFile = CreateFileW(targetFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        FileSize = GetFileSize(hFile, NULL);
        if (FileSize > 0)
        {
            FilePtr = (BYTE*)calloc(FileSize + 1, 1);
            if (FilePtr)
            {
                if (!ReadFile(hFile, (LPVOID)FilePtr, FileSize, &dwBytesRead, NULL))
                {
                    free(FilePtr);
                    FilePtr = 0;
                }

            }
        }
        CloseHandle(hFile);
    }

    return FilePtr;
}

void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data)
{
    HMODULE localKernel = GetModuleHandleW(L"kernel32.dll");
    HMODULE localKernelbase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");

    data->hNtdll = GetModuleBaseRemote(hProcess, L"ntdll.dll");
    data->hkernel32 = GetModuleBaseRemote(hProcess, L"kernel32.dll");
    data->hkernelBase = GetModuleBaseRemote(hProcess, L"kernelbase.dll");
    data->hUser32 = GetModuleBaseRemote(hProcess, L"user32.dll");

    data->EnablePebBeingDebugged = pHideOptions.PEBBeingDebugged;
    data->EnablePebHeapFlags = pHideOptions.PEBHeapFlags;
    data->EnablePebNtGlobalFlag = pHideOptions.PEBNtGlobalFlag;
    data->EnablePebStartupInfo = pHideOptions.PEBStartupInfo;
    data->EnableBlockInputHook = pHideOptions.BlockInput;
    data->EnableGetTickCountHook = pHideOptions.GetTickCount;
    data->EnableOutputDebugStringHook = pHideOptions.OutputDebugStringA;
    data->EnableNtSetInformationThreadHook = pHideOptions.NtSetInformationThread;
    data->EnableNtQueryInformationProcessHook = pHideOptions.NtQueryInformationProcess;
    data->EnableNtQuerySystemInformationHook = pHideOptions.NtQuerySystemInformation;
    data->EnableNtQueryObjectHook = pHideOptions.NtQueryObject;
    data->EnableNtYieldExecutionHook = pHideOptions.NtYieldExecution;
    data->EnableNtCloseHook = pHideOptions.NtClose;
    data->EnableNtCreateThreadExHook = pHideOptions.NtCreateThreadEx;
    data->EnablePreventThreadCreation = pHideOptions.preventThreadCreation;

    data->EnableNtGetContextThreadHook = pHideOptions.NtGetContextThread;
    data->EnableNtSetContextThreadHook = pHideOptions.NtSetContextThread;
    data->EnableNtContinueHook = pHideOptions.NtContinue;
    data->EnableKiUserExceptionDispatcherHook = pHideOptions.KiUserExceptionDispatcher;

    data->EnableNtUserFindWindowExHook = pHideOptions.NtUserFindWindowEx;
    data->EnableNtUserBuildHwndListHook = pHideOptions.NtUserBuildHwndList;
    data->EnableNtUserQueryWindowHook = pHideOptions.NtUserQueryWindow;
    data->EnableNtSetDebugFilterStateHook = pHideOptions.NtSetDebugFilterState;

    data->isKernel32Hooked = FALSE;
    data->isNtdllHooked = FALSE;
    data->isUser32Hooked = FALSE;
}

