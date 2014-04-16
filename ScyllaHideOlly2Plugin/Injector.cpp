#include "Injector.h"
#include "plugin.h"
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
        DllExchangeLoader.EnablePebHiding = pHideOptions.PEB;

        FixPebBeingDebugged(hProcess, setToNull);
        CloseHandle(hProcess);
    }
}

bool StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    DllExchangeLoader.dwProtectedProcessId = GetCurrentProcessId(); //for olly plugins
    DllExchangeLoader.EnableProtectProcessId = TRUE;

    DWORD enableEverything = PEB_PATCH_BeingDebugged|PEB_PATCH_HeapFlags|PEB_PATCH_NtGlobalFlag|PEB_PATCH_StartUpInfo;
    ApplyPEBPatch(&DllExchangeLoader, hProcess, enableEverything);

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
        remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
        if (remoteImageBase)
        {
            FillExchangeStruct(hProcess, &DllExchangeLoader);


            StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase);

            if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0))
            {
                //DWORD exitCode = StartDllInitFunction(hProcess, ((DWORD_PTR)initDllFuncAddressRva + (DWORD_PTR)remoteImageBase), remoteImageBase);

                //if (exitCode == HOOK_ERROR_SUCCESS)
                //{
                Message(0, L"[ScyllaHide] Injection successful, Imagebase %p", remoteImageBase);
                //}
                //else
                //{
                //    Message(0, L"[ScyllaHide] Injection failed, exit code %d Imagebase %p\n", exitCode, remoteImageBase);
                //}
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

    data->EnablePebHiding = pHideOptions.PEB;
    data->EnableBlockInputHook = pHideOptions.BlockInput;
    data->EnableGetTickCountHook = pHideOptions.GetTickCount;
    data->EnableOutputDebugStringHook = pHideOptions.OutputDebugStringA;
    data->EnableNtSetInformationThreadHook = pHideOptions.NtSetInformationThread;
    data->EnableNtQueryInformationProcessHook = pHideOptions.NtQueryInformationProcess;
    data->EnableNtQuerySystemInformationHook = pHideOptions.NtQuerySystemInformation;
    data->EnableNtQueryObjectHook = pHideOptions.NtQueryObject;
    data->EnableNtYieldExecutionHook = pHideOptions.NtYieldExecution;
    data->EnableNtCloseHook = pHideOptions.NtClose;

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

