#include <Scylla/OsInfo.h>

#include "ApplyHooking.h"
#include "DynamicMapping.h"
#include "RemotePebHider.h"
#include "RemoteHook.h"
#include "Logger.h"

#define HOOK(name) dllexchange->d##name = (t_##name)DetourCreateRemote(hProcess,_##name, Hooked##name, true, &dllexchange->##name##BackupSize)
#define HOOK_NATIVE(name) dllexchange->d##name = (t_##name)DetourCreateRemoteNative(hProcess,_##name, Hooked##name, true, &dllexchange->##name##BackupSize)
#define HOOK_NATIVE_NOTRAMP(name) DetourCreateRemoteNative(hProcess,_##name, Hooked##name, false, &dllexchange->##name##BackupSize)
#define FREE_HOOK(name) FreeMemory(hProcess, dllexchange->d##name); dllexchange->d##name = 0
#define RESTORE_JMP(name) RestoreJumper(hProcess,_##name, dllexchange->d##name, dllexchange->##name##BackupSize)


void * HookedNativeCallInternal = 0;
void * NativeCallContinue = 0;
int countNativeHooks = 0;
HOOK_NATIVE_CALL32 * HookNative = 0;
bool onceNativeCallContinue = false;


#ifndef _WIN64
extern BYTE KiSystemCallBackup[20];
extern BYTE sysWowSpecialJmp[7];
extern DWORD KiSystemCallAddress;
extern DWORD sysWowSpecialJmpAddress;
#endif

HMODULE hKernel = 0;
HMODULE hKernelbase = 0;
HMODULE hNtdll = 0;
HMODULE hUser = 0;
HMODULE hUserRemote = 0;
HMODULE hWin32u = 0;

t_KiUserExceptionDispatcher _KiUserExceptionDispatcher = 0;
t_OutputDebugStringA _OutputDebugStringA = 0;
t_GetTickCount _GetTickCount = 0;
t_GetTickCount64 _GetTickCount64 = 0;
t_GetLocalTime _GetLocalTime = 0;
t_GetSystemTime _GetSystemTime = 0;

t_NtUserBlockInput _NtUserBlockInput = 0;
t_NtUserBuildHwndList _NtUserBuildHwndList = 0;
t_NtUserFindWindowEx _NtUserFindWindowEx = 0;
t_NtUserQueryWindow _NtUserQueryWindow = 0;
t_BlockInput _BlockInput = 0;

t_NtSetInformationThread _NtSetInformationThread = 0;
t_NtQuerySystemInformation _NtQuerySystemInformation = 0;
t_NtQueryInformationProcess _NtQueryInformationProcess = 0;
t_NtSetInformationProcess _NtSetInformationProcess = 0;
t_NtQueryObject _NtQueryObject = 0;
t_NtYieldExecution _NtYieldExecution = 0;
t_NtGetContextThread _NtGetContextThread = 0;
t_NtSetContextThread _NtSetContextThread = 0;
t_NtContinue _NtContinue = 0;
t_NtClose _NtClose = 0;
t_NtSetDebugFilterState _NtSetDebugFilterState = 0;
t_NtCreateThread _NtCreateThread = 0;
t_NtCreateThreadEx _NtCreateThreadEx = 0;
t_NtQuerySystemTime _NtQuerySystemTime = 0;
t_NtQueryPerformanceCounter _NtQueryPerformanceCounter = 0;
t_NtResumeThread _NtResumeThread = 0;

void ApplyNtdllHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hNtdll = GetModuleHandleW(L"ntdll.dll");

#ifndef _WIN64
    countNativeHooks = 0;
    onceNativeCallContinue = false;
    HookNative = dllexchange->HookNative;
#endif

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
    void * HookedNtSetDebugFilterState = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetDebugFilterState") + imageBase);
    void * HookedNtCreateThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtCreateThread") + imageBase);
    void * HookedNtCreateThreadEx = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtCreateThreadEx") + imageBase);
    void * HookedNtQuerySystemTime = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQuerySystemTime") + imageBase);
    void * HookedNtQueryPerformanceCounter = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQueryPerformanceCounter") + imageBase);
    void * HookedNtResumeThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtResumeThread") + imageBase);

    HookedNativeCallInternal = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNativeCallInternal") + imageBase);

    _NtSetInformationThread = (t_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
    _NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    _NtQueryInformationProcess = (t_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    _NtSetInformationProcess = (t_NtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    _NtQueryObject = (t_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    _NtYieldExecution = (t_NtYieldExecution)GetProcAddress(hNtdll, "NtYieldExecution");
    _NtGetContextThread = (t_NtGetContextThread)GetProcAddress(hNtdll, "NtGetContextThread");
    _NtSetContextThread = (t_NtSetContextThread)GetProcAddress(hNtdll, "NtSetContextThread");
    _KiUserExceptionDispatcher = (t_KiUserExceptionDispatcher)GetProcAddress(hNtdll, "KiUserExceptionDispatcher");
    _NtContinue = (t_NtContinue)GetProcAddress(hNtdll, "NtContinue");
    _NtClose = (t_NtClose)GetProcAddress(hNtdll, "NtClose");
    _NtSetDebugFilterState = (t_NtSetDebugFilterState)GetProcAddress(hNtdll, "NtSetDebugFilterState");
    _NtCreateThread = (t_NtCreateThread)GetProcAddress(hNtdll, "NtCreateThread");
    _NtCreateThreadEx = (t_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    _NtQuerySystemTime = (t_NtQuerySystemTime)GetProcAddress(hNtdll, "NtQuerySystemTime");
    _NtQueryPerformanceCounter = (t_NtQueryPerformanceCounter)GetProcAddress(hNtdll, "NtQueryPerformanceCounter");
    _NtResumeThread = (t_NtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");

    LogDebug("ApplyNtdllHook -> _NtSetInformationThread %p _NtQuerySystemInformation %p _NtQueryInformationProcess %p _NtSetInformationProcess %p _NtQueryObject %p",
        _NtSetInformationThread,
        _NtQuerySystemInformation,
        _NtQueryInformationProcess,
        _NtSetInformationProcess,
        _NtQueryObject);
    LogDebug("ApplyNtdllHook -> _NtYieldExecution %p _NtGetContextThread %p _NtSetContextThread %p _KiUserExceptionDispatcher %p _NtContinue %p",
        _NtYieldExecution,
        _NtGetContextThread,
        _NtSetContextThread,
        _KiUserExceptionDispatcher,
        _NtContinue);
    LogDebug("ApplyNtdllHook -> _NtClose %p _NtSetDebugFilterState %p _NtCreateThread %p _NtCreateThreadEx %p _NtQuerySystemTime %p _NtQueryPerformanceCounter %p _NtResumeThread %p",
        _NtClose,
        _NtSetDebugFilterState,
        _NtCreateThread,
        _NtCreateThreadEx,
        _NtQuerySystemTime,
        _NtQueryPerformanceCounter,
        _NtResumeThread);

    if (dllexchange->EnableNtSetInformationThreadHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtSetInformationThread");
        HOOK_NATIVE(NtSetInformationThread);
    }
    if (dllexchange->EnableNtQuerySystemInformationHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtQuerySystemInformation");
        HOOK_NATIVE(NtQuerySystemInformation);
    }
    if (dllexchange->EnableNtQueryInformationProcessHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtQueryInformationProcess");
        HOOK_NATIVE(NtQueryInformationProcess);
    }
    if (dllexchange->EnableNtSetInformationProcessHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtSetInformationProcess");
        HOOK_NATIVE(NtSetInformationProcess);
    }

    if (dllexchange->EnableNtQueryObjectHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtQueryObject");
        HOOK_NATIVE(NtQueryObject);
    }
    if (dllexchange->EnableNtYieldExecutionHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtYieldExecution");
        HOOK_NATIVE(NtYieldExecution);
    }
    if (dllexchange->EnableNtGetContextThreadHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtGetContextThread");
        HOOK_NATIVE(NtGetContextThread);
    }
    if (dllexchange->EnableNtSetContextThreadHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtSetContextThread");
        HOOK_NATIVE(NtSetContextThread);
    }

    if (dllexchange->EnableNtCloseHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtClose");
        HOOK_NATIVE(NtClose);
    }
    if (dllexchange->EnablePreventThreadCreation == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtCreateThread");
        HOOK_NATIVE(NtCreateThread);
    }

    if (((dllexchange->EnablePreventThreadCreation == TRUE) || (dllexchange->EnableNtCreateThreadExHook == TRUE)) && _NtCreateThreadEx != 0)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtCreateThreadEx");
        HOOK_NATIVE(NtCreateThreadEx);
    }

    if (dllexchange->EnableNtSetDebugFilterStateHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtSetDebugFilterState");
        HOOK_NATIVE_NOTRAMP(NtSetDebugFilterState);
    }

#ifndef _WIN64
    if (dllexchange->EnableKiUserExceptionDispatcherHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking KiUserExceptionDispatcher");
        HOOK(KiUserExceptionDispatcher);
    }
    if (dllexchange->EnableNtContinueHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtContinue");
        HOOK_NATIVE(NtContinue);
    }
#endif

    if (dllexchange->EnableNtQuerySystemTimeHook == TRUE && _NtQuerySystemTime != 0)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtQuerySystemTime");
        HOOK_NATIVE(NtQuerySystemTime);
    }
    if (dllexchange->EnableNtQueryPerformanceCounterHook == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtQueryPerformanceCounter");
        HOOK_NATIVE(NtQueryPerformanceCounter);
    }

    if (dllexchange->EnableMalwareRunPeUnpacker == TRUE)
    {
        LogDebug("ApplyNtdllHook -> Hooking NtResumeThread for RUNPE UNPACKER");
        HOOK_NATIVE(NtResumeThread);
    }

    dllexchange->isNtdllHooked = TRUE;

#ifndef _WIN64
    dllexchange->NativeCallContinue = NativeCallContinue;
#endif
}

void ApplyKernel32Hook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hKernel = GetModuleHandleW(L"kernel32.dll");
    hKernelbase = GetModuleHandleW(L"kernelbase.dll");

    void * HookedOutputDebugStringA = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedOutputDebugStringA") + imageBase);
    void * HookedGetTickCount = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedGetTickCount") + imageBase);
    void * HookedGetTickCount64 = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedGetTickCount64") + imageBase);
    void * HookedGetLocalTime = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedGetLocalTime") + imageBase);
    void * HookedGetSystemTime = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedGetSystemTime") + imageBase);

    HMODULE hCurrent = hKernel;
    if (hKernelbase)
    {
        hCurrent = hKernelbase;
        LogDebug("ApplyKernel32Hook -> Using Kernelbase %p instead of kernel32 %p", hKernelbase, hKernel);
    }

    _GetTickCount = (t_GetTickCount)GetProcAddress(hCurrent, "GetTickCount");
    _GetTickCount64 = (t_GetTickCount64)GetProcAddress(hCurrent, "GetTickCount64");
    _GetLocalTime = (t_GetLocalTime)GetProcAddress(hCurrent, "GetLocalTime");
    _GetSystemTime = (t_GetSystemTime)GetProcAddress(hCurrent, "GetSystemTime");

    _OutputDebugStringA = (t_OutputDebugStringA)GetProcAddress(hCurrent, "OutputDebugStringA");

    LogDebug("ApplyKernel32Hook -> _GetTickCount %p _GetTickCount64 %p _GetLocalTime %p _GetSystemTime %p _OutputDebugStringA %p",
        _GetTickCount,
        _GetTickCount64,
        _GetLocalTime,
        _GetSystemTime,
        _OutputDebugStringA);

    if (dllexchange->EnableGetTickCountHook == TRUE)
    {
        LogDebug("ApplyKernel32Hook -> Hooking GetTickCount");
        HOOK(GetTickCount);
    }
    if (dllexchange->EnableGetTickCount64Hook == TRUE && _GetTickCount64 != 0)
    {
        LogDebug("ApplyKernel32Hook -> Hooking GetTickCount64");
        HOOK(GetTickCount64);
    }
    if (dllexchange->EnableGetLocalTimeHook == TRUE)
    {
        LogDebug("ApplyKernel32Hook -> Hooking GetLocalTime");
        HOOK(GetLocalTime);
    }
    if (dllexchange->EnableGetSystemTimeHook == TRUE)
    {
        LogDebug("ApplyKernel32Hook -> Hooking GetSystemTime");
        HOOK(GetSystemTime);
    }
    if (dllexchange->EnableOutputDebugStringHook == TRUE)
    {
        LogDebug("ApplyKernel32Hook -> Hooking OutputDebugStringA");
        HOOK(OutputDebugStringA);
    }
    dllexchange->isKernel32Hooked = TRUE;
}

void ApplyUser32Hook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hUser = GetModuleHandleW(L"user32.dll");
    hUserRemote = GetModuleBaseRemote(hProcess, L"user32.dll");

    if (!hUser || !hUserRemote)
    {
        LogDebug("ApplyUser32Hook -> dlls not loaded local %p remote %p", hUser, hUserRemote);
        return;
    }

    void * HookedBlockInput = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedBlockInput") + imageBase);
    void * HookedNtUserFindWindowEx = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserFindWindowEx") + imageBase);
    void * HookedNtUserBuildHwndList = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserBuildHwndList") + imageBase);
    void * HookedNtUserQueryWindow = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserQueryWindow") + imageBase);

    LogDebug("ApplyUser32Hook -> HookedBlockInput %p HookedNtUserFindWindowEx %p HookedNtUserBuildHwndList %p HookedNtUserQueryWindow %p",
        HookedBlockInput,
        HookedNtUserFindWindowEx,
        HookedNtUserBuildHwndList,
        HookedNtUserQueryWindow);

    if (dllexchange->NtUserBuildHwndListRVA && dllexchange->NtUserQueryWindowRVA)
    {
        _NtUserQueryWindow = (t_NtUserQueryWindow)((DWORD_PTR)hUserRemote + dllexchange->NtUserQueryWindowRVA);
        dllexchange->NtUserQueryWindow = _NtUserQueryWindow;
    }
    if (dllexchange->NtUserBuildHwndListRVA && dllexchange->NtUserQueryWindowRVA)
    {
        _NtUserBuildHwndList = (t_NtUserBuildHwndList)((DWORD_PTR)hUserRemote + dllexchange->NtUserBuildHwndListRVA);
    }
    if (dllexchange->NtUserFindWindowExRVA)
    {
        _NtUserFindWindowEx = (t_NtUserFindWindowEx)((DWORD_PTR)hUserRemote + dllexchange->NtUserFindWindowExRVA);
    }
    _BlockInput = (t_BlockInput)GetProcAddress(hUser, "BlockInput");

    LogDebug("ApplyUser32Hook -> _BlockInput %p _NtUserFindWindowEx %p _NtUserBuildHwndList %p _NtUserQueryWindow %p",
        _BlockInput,
        _NtUserFindWindowEx,
        _NtUserBuildHwndList,
        _NtUserQueryWindow);

    if (dllexchange->EnableBlockInputHook == TRUE)
    {
        LogDebug("ApplyUser32Hook -> Hooking BlockInput");
        HOOK_NATIVE(BlockInput);
    }
    if (dllexchange->EnableNtUserFindWindowExHook == TRUE && _NtUserFindWindowEx != 0)
    {
        LogDebug("ApplyUser32Hook -> Hooking NtUserFindWindowEx");
        HOOK_NATIVE(NtUserFindWindowEx);
    }
    if (dllexchange->EnableNtUserBuildHwndListHook == TRUE && _NtUserBuildHwndList != 0)
    {
        LogDebug("ApplyUser32Hook -> Hooking NtUserBuildHwndList");
        HOOK_NATIVE(NtUserBuildHwndList);
    }
    if (dllexchange->EnableNtUserQueryWindowHook == TRUE && _NtUserQueryWindow != 0)
    {
        LogDebug("ApplyUser32Hook -> Hooking NtUserQueryWindow");
        HOOK_NATIVE(NtUserQueryWindow);
    }

    dllexchange->isUser32Hooked = TRUE;
}

void ApplyWin32uHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hWin32u = GetModuleHandleW(L"win32u.dll");

    void * HookedNtUserBlockInput = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserBlockInput") + imageBase);
    void * HookedNtUserFindWindowEx = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserFindWindowEx") + imageBase);
    void * HookedNtUserBuildHwndList = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserBuildHwndList") + imageBase);
    void * HookedNtUserQueryWindow = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserQueryWindow") + imageBase);

    _NtUserBlockInput = (t_NtUserBlockInput)GetProcAddress(hWin32u, "NtUserBlockInput");
    _NtUserFindWindowEx = (t_NtUserFindWindowEx)GetProcAddress(hWin32u, "NtUserFindWindowEx");
    _NtUserBuildHwndList = (t_NtUserBuildHwndList)GetProcAddress(hWin32u, "NtUserBuildHwndList");
    _NtUserQueryWindow = (t_NtUserQueryWindow)GetProcAddress(hWin32u, "NtUserQueryWindow");

    LogDebug("ApplyWin32uHook -> _NtUserBlockInput %p _NtUserFindWindowEx %p _NtUserBuildHwndList %p _NtUserQueryWindow %p",
        _NtUserBlockInput,
        _NtUserFindWindowEx,
        _NtUserBuildHwndList,
        _NtUserQueryWindow);

    if (dllexchange->EnableBlockInputHook) {
        LogDebug("ApplyWin32uHook -> Hooking NtUserBlockInput");
        HOOK_NATIVE(NtUserBlockInput);
    }
    if (dllexchange->EnableNtUserFindWindowExHook) {
        LogDebug("ApplyWin32uHook -> Hooking NtUserFindWindowEx");
        HOOK_NATIVE(NtUserFindWindowEx);
    }
    if (dllexchange->EnableNtUserBuildHwndListHook) {
        LogDebug("ApplyWin32uHook -> Hooking NtUserBuildHwndList");
        HOOK_NATIVE(NtUserBuildHwndList);
    }
    if (dllexchange->EnableNtUserQueryWindowHook) {
        LogDebug("ApplyWin32uHook -> Hooking NtUserQueryWindow");
        HOOK_NATIVE(NtUserQueryWindow);
    }

    dllexchange->isWin32uHooked = TRUE;
}

bool ApplyPEBPatch(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, DWORD enableFlags)
{
    if (hProcess && dllexchange)
    {
        //DWORD enableEverything = PEB_PATCH_BeingDebugged|PEB_PATCH_HeapFlags|PEB_PATCH_NtGlobalFlag|PEB_PATCH_StartUpInfo;
        if (dllexchange->EnablePebBeingDebugged ||
            dllexchange->EnablePebHeapFlags ||
            dllexchange->EnablePebNtGlobalFlag ||
            dllexchange->EnablePebStartupInfo)
        {
            return FixPebInProcess(hProcess, enableFlags);
        }
        return true;
    }

    return false;
}

void RestoreMemory(HANDLE hProcess, DWORD_PTR address, void * buffer, int bufferSize)
{
    DWORD protect = 0;
    if (address && buffer && bufferSize)
    {
        if (VirtualProtectEx(hProcess, (void *)address, bufferSize, PAGE_EXECUTE_READWRITE, &protect))
        {
            WriteProcessMemory(hProcess, (void *)address, buffer, bufferSize, 0);

            VirtualProtectEx(hProcess, (void *)address, bufferSize, protect, &protect);
            FlushInstructionCache(hProcess, (void *)address, bufferSize);
        }
    }

}

void RestoreJumper(HANDLE hProcess, void* address, void * backupAddress, DWORD backupSize)
{
    if (address && backupAddress && backupSize)
    {
        void * backup = malloc(backupSize);
        if (backup)
        {
            if (ReadProcessMemory(hProcess, backupAddress, backup, backupSize, 0))
            {
                RestoreMemory(hProcess, (DWORD_PTR)address, backup, backupSize);
            }

            free(backup);
        }
    }
}

void FreeMemory(HANDLE hProcess, void * buffer)
{
    if (hProcess && buffer)
    {
        VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
    }
}

void RestoreNtdllHooks(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess)
{
#ifndef _WIN64
    if (scl::IsWow64Process(hProcess))
    {
        RestoreMemory(hProcess, sysWowSpecialJmpAddress, sysWowSpecialJmp, sizeof(sysWowSpecialJmp));
    }
    else
    {
        RestoreMemory(hProcess, KiSystemCallAddress, KiSystemCallBackup, sizeof(KiSystemCallBackup));
    }
#else
    RESTORE_JMP(NtClose);
    RESTORE_JMP(NtContinue);
    RESTORE_JMP(NtCreateThreadEx);
    RESTORE_JMP(NtCreateThread);
    RESTORE_JMP(NtSetContextThread);
    RESTORE_JMP(NtGetContextThread);
    RESTORE_JMP(NtYieldExecution);
    RESTORE_JMP(NtQueryObject);
    RESTORE_JMP(NtSetInformationProcess);
    RESTORE_JMP(NtQueryInformationProcess);
    RESTORE_JMP(NtQuerySystemInformation);
    RESTORE_JMP(NtSetInformationThread);
#endif

    FREE_HOOK(NtClose);
    FREE_HOOK(NtContinue);
    FREE_HOOK(NtCreateThreadEx);
    FREE_HOOK(NtCreateThread);
    FREE_HOOK(NtSetContextThread);
    FREE_HOOK(NtGetContextThread);
    FREE_HOOK(NtYieldExecution);
    FREE_HOOK(NtQueryObject);
    FREE_HOOK(NtSetInformationProcess);
    FREE_HOOK(NtQueryInformationProcess);
    FREE_HOOK(NtQuerySystemInformation);
    FREE_HOOK(NtSetInformationThread);


    RESTORE_JMP(KiUserExceptionDispatcher);
    FREE_HOOK(KiUserExceptionDispatcher);



    dllexchange->isNtdllHooked = FALSE;
}

void RestoreKernel32Hooks(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess)
{
    RESTORE_JMP(GetTickCount);
    FREE_HOOK(GetTickCount);

    RESTORE_JMP(OutputDebugStringA);
    FREE_HOOK(OutputDebugStringA);

    dllexchange->isKernel32Hooked = FALSE;
}

void RestoreUser32Hooks(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess)
{

#ifdef _WIN64
    RESTORE_JMP(BlockInput);
    RESTORE_JMP(NtUserFindWindowEx);
    RESTORE_JMP(NtUserBuildHwndList);
    RESTORE_JMP(NtUserQueryWindow);
#endif

    FREE_HOOK(BlockInput);
    FREE_HOOK(NtUserFindWindowEx);
    FREE_HOOK(NtUserBuildHwndList);
    FREE_HOOK(NtUserQueryWindow);

    dllexchange->isUser32Hooked = FALSE;
}

void RestoreWin32uHooks(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess)
{
#ifdef _WIN64
    RESTORE_JMP(NtUserBlockInput);
    RESTORE_JMP(NtUserFindWindowEx);
    RESTORE_JMP(NtUserBuildHwndList);
    RESTORE_JMP(NtUserQueryWindow);
#endif

    FREE_HOOK(NtUserBlockInput);
    FREE_HOOK(NtUserFindWindowEx);
    FREE_HOOK(NtUserBuildHwndList);
    FREE_HOOK(NtUserQueryWindow);

    dllexchange->isWin32uHooked = FALSE;
}

void RestoreHooks(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess)
{
    if (dllexchange->isNtdllHooked == TRUE)
    {
        RestoreNtdllHooks(dllexchange, hProcess);
    }

    if (dllexchange->isKernel32Hooked == TRUE)
    {
        RestoreKernel32Hooks(dllexchange, hProcess);
    }

    if (dllexchange->isUser32Hooked == TRUE)
    {
        RestoreUser32Hooks(dllexchange, hProcess);
    }
    if (dllexchange->isWin32uHooked == TRUE)
    {
        RestoreWin32uHooks(dllexchange, hProcess);
    }

    FreeMemory(hProcess, dllexchange->hDllImage);
    dllexchange->hDllImage = 0;
}

bool ApplyHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    bool retVal = false;
    dllexchange->hDllImage = (HMODULE)imageBase;

    if (dllexchange->isNtdllHooked == FALSE)
    {
        retVal = true;
        ApplyNtdllHook(dllexchange, hProcess, dllMemory, imageBase);
    }
    if (dllexchange->isKernel32Hooked == FALSE)
    {
        retVal = true;
        ApplyKernel32Hook(dllexchange, hProcess, dllMemory, imageBase);
    }
    if (!dllexchange->isUser32Hooked && !dllexchange->isWin32uHooked)
    {
        if (GetModuleHandleW(L"win32u.dll"))
        {
            ApplyWin32uHook(dllexchange, hProcess, dllMemory, imageBase);
        }
        else {
            ApplyUser32Hook(dllexchange, hProcess, dllMemory, imageBase);
        }
    }

    return retVal;
}
