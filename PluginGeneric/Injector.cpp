#include "Injector.h"
#include "..\InjectorCLI\RemoteHook.h"
#include "..\InjectorCLI\RemotePebHider.h"
#include "..\InjectorCLI\\ApplyHooking.h"
#include <Psapi.h>

extern struct HideOptions pHideOptions;

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };

static LPVOID remoteImageBase = 0;

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
t_LogWrapper LogWrap = 0;
t_LogWrapper LogErrorWrap = 0;

//anti-attach vars
DWORD ExitThread_addr;
BYTE* DbgUiIssueRemoteBreakin_addr;
DWORD jmpback;
DWORD DbgUiRemoteBreakin_addr;
BYTE* RemoteBreakinPatch;
BYTE code[8];
HANDLE hDebuggee;

#ifndef _WIN64
void __declspec(naked) handleAntiAttach()
{
    _asm {
        push ebp //stolen bytes
        mov ebp,esp //stolen bytes
        pushad
        mov eax,dword ptr[ebp+0x8]
        mov hDebuggee,eax
    }

    //write our RemoteBreakIn patch to target memory
    RemoteBreakinPatch = (BYTE*) VirtualAllocEx(hDebuggee, 0, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hDebuggee, (LPVOID)RemoteBreakinPatch, code, sizeof(code), NULL);

    //find push ntdll.DbgUiRemoteBreakin and patch our patch function addr there
    while(*(DWORD*)DbgUiIssueRemoteBreakin_addr != DbgUiRemoteBreakin_addr) {
        DbgUiIssueRemoteBreakin_addr++;
    }
    WriteProcessMemory(GetCurrentProcess(), DbgUiIssueRemoteBreakin_addr, &RemoteBreakinPatch, 4, NULL);

    _asm {
        popad
        mov eax, jmpback
        jmp eax
    }
}
#endif

void InstallAntiAttachHook()
{
#ifndef _WIN64
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);

    DbgUiIssueRemoteBreakin_addr = (BYTE*) GetProcAddress(GetModuleHandleA("ntdll.dll"),"DbgUiIssueRemoteBreakin");
    DbgUiRemoteBreakin_addr = (DWORD) GetProcAddress(GetModuleHandleA("ntdll.dll"),"DbgUiRemoteBreakin");
    ExitThread_addr = (DWORD) GetProcAddress(GetModuleHandleA("kernel32.dll"),"ExitThread");
    jmpback = (DWORD)DbgUiIssueRemoteBreakin_addr;
    jmpback += 5;

    BYTE jmp[1] = {0xE9};
    WriteProcessMemory(hOlly, DbgUiIssueRemoteBreakin_addr, &jmp, sizeof(jmp), NULL);
    DWORD patch = (DWORD)handleAntiAttach;
    patch -= (DWORD)DbgUiIssueRemoteBreakin_addr;
    patch -= 5;
    WriteProcessMemory(hOlly, DbgUiIssueRemoteBreakin_addr+1, &patch, 4, NULL);

    //init our remote breakin patch
    BYTE* p = &code[0];
    *p=0xCC;  //int3
    p++;
    *p=0x68;  //push
    p++;
    *(DWORD*)(p) = ExitThread_addr;
    p+=4;
    *p=0xC3; //retn
#endif
}


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
        LogWrap(L"[ScyllaHide] Apply hooks again");
        if (StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase))
        {
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0);
        }
    }
    else
    {
        if (pHideOptions.removeDebugPrivileges)
        {
            RemoveDebugPrivileges(hProcess);
        }

        RestoreHooks(&DllExchangeLoader, hProcess);

        remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
        if (remoteImageBase)
        {
            FillExchangeStruct(hProcess, &DllExchangeLoader);


            StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase);

            if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0))
            {
                LogWrap(L"[ScyllaHide] Hook Injection successful, Imagebase %p", remoteImageBase);
            }
            else
            {
                LogWrap(L"[ScyllaHide] Failed to write exchange struct");
            }
        }
        else
        {
            LogWrap(L"[ScyllaHide] Failed to map image!");
        }
    }
}

void checkStructAlignment()
{
    char text[600] = {0};

#ifdef _WIN64
    if (sizeof(HOOK_DLL_EXCHANGE) != HOOK_DLL_EXCHANGE_SIZE_64)
    {
        wsprintfA(text,"Warning wrong struct size %d != %d\n", sizeof(HOOK_DLL_EXCHANGE), HOOK_DLL_EXCHANGE_SIZE_64);
        MessageBoxA(0, text, "Error", 0);
    }
#else
    if (sizeof(HOOK_DLL_EXCHANGE) != HOOK_DLL_EXCHANGE_SIZE_32)
    {
        wsprintfA(text, "Warning wrong struct size %d != %d\n", sizeof(HOOK_DLL_EXCHANGE), HOOK_DLL_EXCHANGE_SIZE_32);
        MessageBoxA(0, text, "Error", 0);
    }
#endif
}

void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess)
{
    checkStructAlignment();

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
            LogErrorWrap(L"[ScyllaHide] Cannot find %s", dllPath);
        }
        CloseHandle(hProcess);
    }
    else
    {
        LogErrorWrap(L"[ScyllaHide] Cannot open process handle %d", targetPid);
    }
}

void DoThreadMagic( HANDLE hThread )
{
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
    NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);
    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);
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
            DoThreadMagic(hThread);

            GetExitCodeThread(hThread, &hModule);

            if (!hModule)
            {
                LogWrap(L"[ScyllaHide] DLL INJECTION: Failed load library!");
            }

            CloseHandle(hThread);
        }
        else
        {
            LogWrap(L"[ScyllaHide] DLL INJECTION: Failed to start thread %d!", GetLastError());
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

            if (pNt->OptionalHeader.AddressOfEntryPoint)
            {
                DWORD_PTR dllMain = pNt->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteImageBaseOfInjectedDll;

                HANDLE hThread = CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)dllMain,remoteImageBaseOfInjectedDll,CREATE_SUSPENDED, 0);
                if (hThread)
                {
                    DoThreadMagic(hThread);

                    CloseHandle(hThread);
                }
                else
                {
                    LogWrap(L"[ScyllaHide] DLL INJECTION: Failed to start thread %d!", GetLastError());
                }
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
        }
        else
        {
            LogWrap(L"[ScyllaHide] DLL INJECTION: No injection type selected!");
        }

        if (remoteImage)
        {
            LogWrap(L"[ScyllaHide] DLL INJECTION: Injection of %s successful, Imagebase %p", dllPath, remoteImage);

            if (pHideOptions.DLLUnload)
            {
                LogWrap(L"[ScyllaHide] DLL INJECTION: Unloading Imagebase %p", remoteImage);

                if (pHideOptions.DLLNormal)
                {
                    HANDLE hThread = CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)FreeLibrary,remoteImage, CREATE_SUSPENDED, 0);
                    if (hThread)
                    {
                        DoThreadMagic(hThread);
                        CloseHandle(hThread);
                        LogWrap(L"[ScyllaHide] DLL INJECTION: Unloading Imagebase %p successful", remoteImage);
                    }
                    else
                    {
                        LogWrap(L"[ScyllaHide] DLL INJECTION: Unloading Imagebase %p FAILED", remoteImage);
                    }
                }
                else if (pHideOptions.DLLStealth)
                {
                    VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
                    LogWrap(L"[ScyllaHide] DLL INJECTION: Unloading Imagebase %p successful", remoteImage);
                }
            }
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

    hFile = CreateFileW(targetFilePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
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
    data->EnableOutputDebugStringHook = pHideOptions.OutputDebugStringA;
    data->EnableNtSetInformationThreadHook = pHideOptions.NtSetInformationThread;
    data->EnableNtQueryInformationProcessHook = pHideOptions.NtQueryInformationProcess;
    data->EnableNtQuerySystemInformationHook = pHideOptions.NtQuerySystemInformation;
    data->EnableNtQueryObjectHook = pHideOptions.NtQueryObject;
    data->EnableNtYieldExecutionHook = pHideOptions.NtYieldExecution;
    data->EnableNtCloseHook = pHideOptions.NtClose;
    data->EnableNtCreateThreadExHook = pHideOptions.NtCreateThreadEx;
    data->EnablePreventThreadCreation = pHideOptions.preventThreadCreation;
    data->EnableNtUserFindWindowExHook = pHideOptions.NtUserFindWindowEx;
    data->EnableNtUserBuildHwndListHook = pHideOptions.NtUserBuildHwndList;
    data->EnableNtUserQueryWindowHook = pHideOptions.NtUserQueryWindow;
    data->EnableNtSetDebugFilterStateHook = pHideOptions.NtSetDebugFilterState;
    data->EnableGetTickCountHook = pHideOptions.GetTickCount;
    data->EnableGetTickCount64Hook = pHideOptions.GetTickCount64;
    data->EnableGetLocalTimeHook = pHideOptions.GetLocalTime;
    data->EnableGetSystemTimeHook = pHideOptions.GetSystemTime;
    data->EnableNtQuerySystemTimeHook = pHideOptions.NtQuerySystemTime;
    data->EnableNtQueryPerformanceCounterHook = pHideOptions.NtQueryPerformanceCounter;
    data->EnableNtSetInformationProcessHook = pHideOptions.NtSetInformationProcess;

    data->EnableNtGetContextThreadHook = pHideOptions.NtGetContextThread;
    data->EnableNtSetContextThreadHook = pHideOptions.NtSetContextThread;
    data->EnableNtContinueHook = pHideOptions.NtContinue | pHideOptions.killAntiAttach;
    data->EnableKiUserExceptionDispatcherHook = pHideOptions.KiUserExceptionDispatcher;
    data->EnableMalwareRunPeUnpacker = pHideOptions.malwareRunpeUnpacker;

    data->isKernel32Hooked = FALSE;
    data->isNtdllHooked = FALSE;
    data->isUser32Hooked = FALSE;
}

typedef void (WINAPI *tGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
typedef BOOL (WINAPI * tIsWow64Process)(HANDLE hProcess,PBOOL Wow64Process);

tGetNativeSystemInfo _GetNativeSystemInfo = 0;
tIsWow64Process fnIsWow64Process = 0;

bool isWindows64()
{
    SYSTEM_INFO si = {0};

    if (!_GetNativeSystemInfo)
    {
        _GetNativeSystemInfo = (tGetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetNativeSystemInfo");
    }

    if (_GetNativeSystemInfo)
    {
        _GetNativeSystemInfo(&si);
    }
    else
    {
        GetSystemInfo(&si);
    }

    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}

bool IsProcessWOW64(HANDLE hProcess)
{
    BOOL bIsWow64 = FALSE;
    if (!fnIsWow64Process)
    {
        fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    }


    if (fnIsWow64Process)
    {
        fnIsWow64Process(hProcess, &bIsWow64);
    }

    return (bIsWow64 != FALSE);
}

bool RemoveDebugPrivileges(HANDLE hProcess)
{
    TOKEN_PRIVILEGES Debug_Privileges;

    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
    {
        HANDLE hToken = 0;
        if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            Debug_Privileges.Privileges[0].Attributes = 0;
            Debug_Privileges.PrivilegeCount = 1;

            AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL);
            CloseHandle(hToken);
            return true;
        }
    }

    return false;
}

#define DbgBreakPoint_FUNC_SIZE 2
#ifdef _WIN64
#define DbgUiRemoteBreakin_FUNC_SIZE 0x42
#define NtContinue_FUNC_SIZE 11
#else
#define DbgUiRemoteBreakin_FUNC_SIZE 0x54
#define NtContinue_FUNC_SIZE 0x18
#endif

typedef struct _PATCH_FUNC {
	PCHAR funcName;
	PVOID funcAddr;
	SIZE_T funcSize;
} PATCH_FUNC;


PATCH_FUNC patchFunctions[] = {
	{
		"DbgBreakPoint", 0, DbgBreakPoint_FUNC_SIZE
	},
	{
		"DbgUiRemoteBreakin",0,DbgUiRemoteBreakin_FUNC_SIZE
	},
	{
		"NtContinue", 0, NtContinue_FUNC_SIZE
	}
};

bool ApplyAntiAntiAttach(DWORD targetPid)
{
	bool resu = false;

	WCHAR modName[MAX_PATH] = {0};
	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);

	if (!hProcess)
		return resu;

	HMODULE hMod = GetModuleHandleW(L"ntdll.dll");

	for (int i = 0; i < _countof(patchFunctions); i++)
	{
		patchFunctions[i].funcAddr = GetProcAddress(hMod, patchFunctions[i].funcName);
	}

	//has remote ntdll same image base? if not -> crap
	if (GetModuleBaseNameW(hProcess, hMod, modName, _countof(modName)))
	{
		if (wcsstr(modName, L"ntdll") || wcsstr(modName, L"NTDLL"))
		{
			for (int i = 0; i < _countof(patchFunctions); i++)
			{
				if (WriteProcessMemory(hProcess, patchFunctions[i].funcAddr, patchFunctions[i].funcAddr, patchFunctions[i].funcSize, 0))
				{
					resu = true;
				}
				else
				{
					resu = false;
					break;
				}
			}
		}
		else
		{
			MessageBoxA(0, "Remote NTDLL does not have the same image base, please contact ScyllaHide developers!", "Error", MB_ICONERROR);
		}
	}

	CloseHandle(hProcess);

	return resu;
}
