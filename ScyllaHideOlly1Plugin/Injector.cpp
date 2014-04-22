#include "Injector.h"
#include "ollyplugindefinitions.h"
#include "..\InjectorCLI\RemoteHook.h"
#include "..\InjectorCLI\RemotePebHider.h"
#include "..\InjectorCLI\\ApplyHooking.h"

extern struct HideOptions pHideOptions;


HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };


static LPVOID remoteImageBase = 0;


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
        _Message(0, "[ScyllaHide] Apply hooks again");
        if (StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase))
        {
            WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0);
        }
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
                //DWORD exitCode = StartDllInitFunction(hProcess, ((DWORD_PTR)initDllFuncAddressRva + (DWORD_PTR)remoteImageBase), remoteImageBase);

                //bool suc = StartSystemBreakpointInjection(dwThreadid, hProcess, ((DWORD_PTR)initDllFuncAddressRva + (DWORD_PTR)remoteImageBase), remoteImageBase);
                //if (suc)
                //{
                _Message(0, "[ScyllaHide] Injection successful, Imagebase %p", remoteImageBase);
                //}
                //else
                //{
                //    _Message(0, "[ScyllaHide] Injection failed Imagebase %p\n", remoteImageBase);
                //}
            }
            else
            {
                _Message(0, "[ScyllaHide] Failed to write exchange struct");
            }
        }
        else
        {
            _Message(0, "[ScyllaHide] Failed to map image!");
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
            _Error("[ScyllaHide] Cannot find %S", dllPath);
        }
        CloseHandle(hProcess);
    }
    else
    {
        _Error("[ScyllaHide] Cannot open process handle %d", targetPid);
    }
}

void injectDll(DWORD targetPid, const WCHAR * dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
    if (hProcess)
    {
        BYTE * dllMemory = ReadFileToMemory(dllPath);
        if (dllMemory)
        {
            LPVOID remoteImageBaseOfInjectedDll = 0;
            remoteImageBaseOfInjectedDll = MapModuleToProcess(hProcess, dllMemory);
            if(remoteImageBaseOfInjectedDll) {
                _Message(0, "[ScyllaHide] Injection of %S successful, Imagebase %p", dllPath, remoteImageBaseOfInjectedDll);
            }
            else
            {
                _Message(0, "[ScyllaHide] Failed to map image of %S!", dllPath);
            }
            free(dllMemory);
        }
        CloseHandle(hProcess);
    }
    else
    {
        _Error("[ScyllaHide] Cannot open process handle %d", targetPid);
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
    data->EnableNtCloseHook = pHideOptions.NtClose;

    data->isKernel32Hooked = FALSE;
    data->isNtdllHooked = FALSE;
    data->isUser32Hooked = FALSE;

}
