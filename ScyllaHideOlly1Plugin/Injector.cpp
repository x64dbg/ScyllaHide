#include "Injector.h"

extern struct HideOptions pHideOptions;

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory)
{
    LPVOID remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
    if (remoteImageBase)
    {
        FillExchangeStruct(hProcess, &DllExchangeLoader);
        DWORD initDllFuncAddressRva = GetDllFunctionAddressRVA(dllMemory, "InitDll");
        DWORD exchangeDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "DllExchange");

        if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0))
        {
            DWORD exitCode = StartDllInitFunction(hProcess, ((DWORD_PTR)initDllFuncAddressRva + (DWORD_PTR)remoteImageBase), remoteImageBase);

            if (exitCode == HOOK_ERROR_SUCCESS)
            {
                _Message(0, "[ScyllaHide] Injection successful, Imagebase %p\n", remoteImageBase);
            }
            else
            {
                _Message(0, "[ScyllaHide] Injection failed, exit code %d Imagebase %p\n", exitCode, remoteImageBase);
            }
        }
        else
        {
            _Message(0, "[ScyllaHide] Failed to write exchange struct\n");
        }
    }
}

void startInjection(DWORD targetPid, const WCHAR * dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
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
            _Error("[ScyllaHide] Cannot find HookLibrary.dll");
        }
        CloseHandle(hProcess);
    }
    else
    {
        _Error("[ScyllaHide] Cannot open process handle %d\n", targetPid);
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
    HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");

    data->hNtdll = GetModuleBaseRemote(hProcess, L"ntdll.dll");
    data->hkernel32 = GetModuleBaseRemote(hProcess, L"kernel32.dll");
    data->hkernelBase = GetModuleBaseRemote(hProcess, L"kernelbase.dll");
    data->hUser32 = GetModuleBaseRemote(hProcess, L"user32.dll");

    data->fLoadLibraryA = (t_LoadLibraryA)((DWORD_PTR)GetProcAddress(localKernel, "LoadLibraryA") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
    data->fGetModuleHandleA = (t_GetModuleHandleA)((DWORD_PTR)GetProcAddress(localKernel, "GetModuleHandleA") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
    data->fGetProcAddress = (t_GetProcAddress)((DWORD_PTR)GetProcAddress(localKernel, "GetProcAddress") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);

    data->EnablePebHiding = (BOOLEAN)pHideOptions.PEB;
    data->EnableBlockInputHook = pHideOptions.BlockInput;
    data->EnableGetTickCountHook = pHideOptions.GetTickCount;
    data->EnableOutputDebugStringHook = pHideOptions.OutputDebugStringA;

    data->EnableNtSetInformationThreadHook = pHideOptions.NtSetInformationThread;
    data->EnableNtQueryInformationProcessHook = pHideOptions.NtQueryInformationProcess;
    data->EnableNtQuerySystemInformationHook = pHideOptions.NtQuerySystemInformation;
    data->EnableNtQueryObjectHook = pHideOptions.NtQueryObject;
    data->EnableNtYieldExecutionHook = pHideOptions.NtYieldExecution;

    data->EnableNtGetContextThreadHook = pHideOptions.ProtectDrx;
    data->EnableNtSetContextThreadHook = pHideOptions.ProtectDrx;
    data->EnableNtContinueHook = pHideOptions.ProtectDrx;
}

DWORD SetDebugPrivileges()
{
    DWORD err = 0;
    TOKEN_PRIVILEGES Debug_Privileges;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid)) return GetLastError();

    HANDLE hToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        err = GetLastError();
        if (hToken) CloseHandle(hToken);
        return err;
    }

    Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Debug_Privileges.PrivilegeCount = 1;

    if (!AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, NULL, NULL))
    {
        err = GetLastError();
        if (hToken) CloseHandle(hToken);
    }

    return err;
}
