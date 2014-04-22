#include "Injector.h"
#include "..\InjectorCLI\RemoteHook.h"
#include "..\InjectorCLI\RemotePebHider.h"
#include "..\InjectorCLI\\ApplyHooking.h"

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };



bool StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    DllExchangeLoader.dwProtectedProcessId = 0; //for olly plugins
    DllExchangeLoader.EnableProtectProcessId = FALSE;

    DWORD enableEverything = PEB_PATCH_BeingDebugged|PEB_PATCH_HeapFlags|PEB_PATCH_NtGlobalFlag|PEB_PATCH_StartUpInfo;

    ApplyPEBPatch(&DllExchangeLoader, hProcess,enableEverything);

    return ApplyHook(&DllExchangeLoader, hProcess, dllMemory, imageBase);
}

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory)
{
    LPVOID remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
    if (remoteImageBase)
    {
        FillExchangeStruct(hProcess, &DllExchangeLoader);
        DWORD initDllFuncAddressRva = GetDllFunctionAddressRVA(dllMemory, "InitDll");
        DWORD exchangeDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "DllExchange");

        StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase);

        if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0))
        {
            //DWORD exitCode = StartDllInitFunction(hProcess, ((DWORD_PTR)initDllFuncAddressRva + (DWORD_PTR)remoteImageBase), remoteImageBase);

            //bool suc = StartSystemBreakpointInjection(dwThreadid, hProcess, ((DWORD_PTR)initDllFuncAddressRva + (DWORD_PTR)remoteImageBase), remoteImageBase);
            //if (suc)
            //{
            //_Message(0, "[ScyllaHide] Injection successful, Imagebase %p\n", remoteImageBase);
            //}
            //else
            //{
            //    _Message(0, "[ScyllaHide] Injection failed Imagebase %p\n", remoteImageBase);
            //}
        }
        else
        {
            //_Message(0, "[ScyllaHide] Failed to write exchange struct\n");
        }
    }
}

void startInjection(DWORD targetPid, const WCHAR * dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
    if (hProcess)
    {
        BYTE * dllMemory = ReadFileToMemory(dllPath);
        if (dllMemory)
        {
            startInjectionProcess(hProcess, dllMemory);
            free(dllMemory);
        }
        else
        {
            //_Error("[ScyllaHide] Cannot find %S", dllPath);
        }
        CloseHandle(hProcess);
    }
    else
    {
        //_Error("[ScyllaHide] Cannot open process handle %d\n", targetPid);
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

    data->EnablePebBeingDebugged = TRUE;
    data->EnablePebHeapFlags = TRUE;
    data->EnablePebNtGlobalFlag = TRUE;
    data->EnablePebStartupInfo = TRUE;
    data->EnableBlockInputHook = TRUE;
    data->EnableGetTickCountHook = TRUE;
    data->EnableKiUserExceptionDispatcherHook = TRUE;
    data->EnableNtCloseHook = TRUE;
    data->EnableNtContinueHook = TRUE;
    data->EnableNtGetContextThreadHook = TRUE;
    data->EnableNtQueryInformationProcessHook = TRUE;
    data->EnableNtQueryObjectHook = TRUE;
    data->EnableNtQuerySystemInformationHook = TRUE;
    data->EnableNtSetContextThreadHook = TRUE;
    data->EnableNtSetDebugFilterStateHook = TRUE;
    data->EnableNtSetInformationThreadHook = TRUE;
    data->EnableNtUserBuildHwndListHook = TRUE;
    data->EnableNtUserFindWindowExHook = TRUE;
    data->EnableNtUserQueryWindowHook = TRUE;
    data->EnableNtYieldExecutionHook = TRUE;
    data->EnableOutputDebugStringHook = TRUE;
    data->EnableProtectProcessId = TRUE;

    data->isKernel32Hooked = FALSE;
    data->isNtdllHooked = FALSE;
    data->isUser32Hooked = FALSE;
}
