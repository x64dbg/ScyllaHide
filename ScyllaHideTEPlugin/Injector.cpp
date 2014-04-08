#include "Injector.h"
#include "..\InjectorCLI\RemoteHook.h"
#include "..\InjectorCLI\RemotePebHider.h"

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };

#define HOOK(name) DllExchangeLoader.d##name = (t_##name)DetourCreateRemote(hProcess,_##name, Hooked##name, true)
#define HOOK_NOTRAMP(name) DetourCreateRemote(hProcess,_##name, Hooked##name, false)

void StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    HMODULE hKernelbase = GetModuleHandleW(L"kernelbase.dll");

    HMODULE hUser = GetModuleHandleW(L"user32.dll");
    HMODULE hUserRemote = GetModuleBaseRemote(hProcess, L"user32.dll");

    DllExchangeLoader.hDllImage = (HMODULE)imageBase;
    void * HookedNtSetInformationThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetInformationThread") + imageBase);
    void * HookedNtQuerySystemInformation = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQuerySystemInformation") + imageBase);
    void * HookedNtQueryInformationProcess = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQueryInformationProcess") + imageBase);
    void * HookedNtSetInformationProcess = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetInformationProcess") + imageBase);
    void * HookedNtQueryObject = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQueryObject") + imageBase);
    void * HookedNtYieldExecution = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtYieldExecution") + imageBase);
    void * HookedNtGetContextThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtGetContextThread") + imageBase);
    void * HookedNtSetContextThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetContextThread") + imageBase);
    void * HookedKiUserExceptionDispatcher = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedKiUserExceptionDispatcher") + imageBase);
    void * HookedNtContinue = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtContinue") + imageBase);
    void * HookedNtClose = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtClose") + imageBase);

    void * HookedOutputDebugStringA = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedOutputDebugStringA") + imageBase);
    void * HookedGetTickCount = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedGetTickCount") + imageBase);
    void * HookedBlockInput = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedBlockInput") + imageBase);
    void * HookedNtUserFindWindowEx = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserFindWindowEx") + imageBase);
    void * HookedNtUserBuildHwndList = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserBuildHwndList") + imageBase);
    void * HookedNtSetDebugFilterState = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetDebugFilterState") + imageBase);

    t_NtSetInformationThread _NtSetInformationThread = (t_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
    t_NtQuerySystemInformation _NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    t_NtQueryInformationProcess _NtQueryInformationProcess = (t_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    t_NtSetInformationProcess _NtSetInformationProcess = (t_NtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    t_NtQueryObject _NtQueryObject = (t_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    t_NtYieldExecution _NtYieldExecution = (t_NtYieldExecution)GetProcAddress(hNtdll, "NtYieldExecution");
    t_NtGetContextThread _NtGetContextThread = (t_NtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
    t_NtSetContextThread _NtSetContextThread = (t_NtSetContextThread)GetProcAddress(hNtdll, "NtSetContextThread");
    t_KiUserExceptionDispatcher _KiUserExceptionDispatcher = (t_KiUserExceptionDispatcher)GetProcAddress(hNtdll, "KiUserExceptionDispatcher");
    t_NtContinue _NtContinue = (t_NtContinue)GetProcAddress(hNtdll, "NtContinue");
    t_NtClose _NtClose = (t_NtClose)GetProcAddress(hNtdll, "NtClose");
    t_NtSetDebugFilterState _NtSetDebugFilterState = (t_NtSetDebugFilterState)GetProcAddress(hNtdll, "NtSetDebugFilterState");

    t_OutputDebugStringA _OutputDebugStringA;
    t_GetTickCount _GetTickCount;
    if (hKernelbase)
    {
        _GetTickCount = (t_GetTickCount)GetProcAddress(hKernelbase, "GetTickCount");
        _OutputDebugStringA = (t_OutputDebugStringA)GetProcAddress(hKernelbase, "OutputDebugStringA");
    }
    else
    {
        _GetTickCount = (t_GetTickCount)GetProcAddress(hKernel, "GetTickCount");
        _OutputDebugStringA = (t_OutputDebugStringA)GetProcAddress(hKernel, "OutputDebugStringA");
    }

    if (hUser && hUserRemote)
    {
        t_NtUserBuildHwndList _NtUserBuildHwndList = 0;
        t_NtUserFindWindowEx _NtUserFindWindowEx = 0;
        t_NtUserQueryWindow _NtUserQueryWindow = 0;

        if (DllExchangeLoader.NtUserQueryWindowRVA)
        {
            _NtUserQueryWindow = (t_NtUserQueryWindow)((DWORD_PTR)hUserRemote + DllExchangeLoader.NtUserQueryWindowRVA);
            DllExchangeLoader.NtUserQueryWindow = _NtUserQueryWindow;
        }
        if (DllExchangeLoader.NtUserBuildHwndListRVA)
        {
            _NtUserBuildHwndList = (t_NtUserBuildHwndList)((DWORD_PTR)hUserRemote + DllExchangeLoader.NtUserBuildHwndListRVA);
        }
        if (DllExchangeLoader.NtUserFindWindowExRVA)
        {
            _NtUserFindWindowEx = (t_NtUserFindWindowEx)((DWORD_PTR)hUserRemote + DllExchangeLoader.NtUserFindWindowExRVA);
        }
        t_BlockInput _BlockInput = (t_BlockInput)GetProcAddress(hUser, "BlockInput");

        if (DllExchangeLoader.EnableBlockInputHook == TRUE) HOOK(BlockInput);
        if (DllExchangeLoader.EnableNtUserFindWindowExHook == TRUE && _NtUserFindWindowEx != 0) HOOK(NtUserFindWindowEx);
        if (DllExchangeLoader.EnableNtUserBuildHwndListHook == TRUE && _NtUserBuildHwndList != 0) HOOK(NtUserBuildHwndList);
    }

    if (DllExchangeLoader.EnablePebHiding == TRUE) FixPebInProcess(hProcess);

    if (DllExchangeLoader.EnableNtSetInformationThreadHook == TRUE) HOOK(NtSetInformationThread);
    if (DllExchangeLoader.EnableNtQuerySystemInformationHook == TRUE) HOOK(NtQuerySystemInformation);
    if (DllExchangeLoader.EnableNtQueryInformationProcessHook == TRUE)
    {
        HOOK(NtQueryInformationProcess);
        HOOK(NtSetInformationProcess);
    }
    if (DllExchangeLoader.EnableNtQueryObjectHook == TRUE) HOOK(NtQueryObject);
    if (DllExchangeLoader.EnableNtYieldExecutionHook == TRUE) HOOK(NtYieldExecution);
    if (DllExchangeLoader.EnableNtGetContextThreadHook == TRUE) HOOK(NtGetContextThread);
    if (DllExchangeLoader.EnableNtSetContextThreadHook == TRUE) HOOK(NtSetContextThread);
    if (DllExchangeLoader.EnableKiUserExceptionDispatcherHook == TRUE) HOOK(KiUserExceptionDispatcher);
    if (DllExchangeLoader.EnableNtContinueHook == TRUE) HOOK(NtContinue);
    if (DllExchangeLoader.EnableNtCloseHook == TRUE) HOOK(NtClose);
    if (DllExchangeLoader.EnableGetTickCountHook == TRUE) HOOK(GetTickCount);
    if (DllExchangeLoader.EnableOutputDebugStringHook == TRUE) HOOK_NOTRAMP(OutputDebugStringA);
    if (DllExchangeLoader.EnableNtSetDebugFilterStateHook == TRUE) HOOK_NOTRAMP(NtSetDebugFilterState);
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
    data->EnablePebHiding = TRUE;
    data->EnableProtectProcessId = TRUE;
}
