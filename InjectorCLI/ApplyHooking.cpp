#include <Scylla/Logger.h>
#include <Scylla/OsInfo.h>
#include <Scylla/PebHider.h>

#include "ApplyHooking.h"
#include "DynamicMapping.h"
#include "RemoteHook.h"

#define HOOK(name) hdd->d##name = (t_##name)DetourCreateRemote(hProcess,_##name, Hooked##name, true, &hdd->##name##BackupSize)
#define HOOK_NATIVE(name) hdd->d##name = (t_##name)DetourCreateRemoteNative(hProcess,_##name, Hooked##name, true, &hdd->##name##BackupSize)
#define HOOK_NATIVE_NOTRAMP(name) DetourCreateRemoteNative(hProcess,_##name, Hooked##name, false, &hdd->##name##BackupSize)
#define FREE_HOOK(name) FreeMemory(hProcess, hdd->d##name); hdd->d##name = 0
#define RESTORE_JMP(name) RestoreJumper(hProcess,_##name, hdd->d##name, hdd->##name##BackupSize)

extern scl::Logger g_log;

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
t_NtDuplicateObject _NtDuplicateObject = 0;
t_NtSetDebugFilterState _NtSetDebugFilterState = 0;
t_NtCreateThread _NtCreateThread = 0;
t_NtCreateThreadEx _NtCreateThreadEx = 0;
t_NtQuerySystemTime _NtQuerySystemTime = 0;
t_NtQueryPerformanceCounter _NtQueryPerformanceCounter = 0;
t_NtResumeThread _NtResumeThread = 0;

void ApplyNtdllHook(HOOK_DLL_DATA * hdd, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hNtdll = GetModuleHandleW(L"ntdll.dll");

#ifndef _WIN64
    countNativeHooks = 0;
    onceNativeCallContinue = false;
    HookNative = hdd->HookNative;
#endif

    void * HookedNtSetInformationThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetInformationThread") + imageBase);
    void * HookedNtQuerySystemInformation = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQuerySystemInformation") + imageBase);
    void * HookedNtQueryInformationProcess = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQueryInformationProcess") + imageBase);
    void * HookedNtSetInformationProcess = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetInformationProcess") + imageBase);
    void * HookedNtQueryObject = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtQueryObject") + imageBase);
    void * HookedNtYieldExecution = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtYieldExecution") + imageBase);
    void * HookedNtGetContextThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtGetContextThread") + imageBase);
    void * HookedNtSetContextThread = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtSetContextThread") + imageBase);
#ifndef _WIN64
    void * HookedKiUserExceptionDispatcher = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedKiUserExceptionDispatcher") + imageBase);
    void * HookedNtContinue = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtContinue") + imageBase);
#endif
    void * HookedNtClose = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtClose") + imageBase);
    void * HookedNtDuplicateObject = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtDuplicateObject") + imageBase);
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
    _NtDuplicateObject = (t_NtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
    _NtSetDebugFilterState = (t_NtSetDebugFilterState)GetProcAddress(hNtdll, "NtSetDebugFilterState");
    _NtCreateThread = (t_NtCreateThread)GetProcAddress(hNtdll, "NtCreateThread");
    _NtCreateThreadEx = (t_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    _NtQuerySystemTime = (t_NtQuerySystemTime)GetProcAddress(hNtdll, "NtQuerySystemTime");
    _NtQueryPerformanceCounter = (t_NtQueryPerformanceCounter)GetProcAddress(hNtdll, "NtQueryPerformanceCounter");
    _NtResumeThread = (t_NtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");

    g_log.LogDebug(L"ApplyNtdllHook -> _NtSetInformationThread %p _NtQuerySystemInformation %p _NtQueryInformationProcess %p _NtSetInformationProcess %p _NtQueryObject %p",
        _NtSetInformationThread,
        _NtQuerySystemInformation,
        _NtQueryInformationProcess,
        _NtSetInformationProcess,
        _NtQueryObject);
    g_log.LogDebug(L"ApplyNtdllHook -> _NtYieldExecution %p _NtGetContextThread %p _NtSetContextThread %p _KiUserExceptionDispatcher %p _NtContinue %p",
        _NtYieldExecution,
        _NtGetContextThread,
        _NtSetContextThread,
        _KiUserExceptionDispatcher,
        _NtContinue);
    g_log.LogDebug(L"ApplyNtdllHook -> _NtClose %p _NtDuplicateObject %p _NtSetDebugFilterState %p _NtCreateThread %p _NtCreateThreadEx %p _NtQuerySystemTime %p _NtQueryPerformanceCounter %p _NtResumeThread %p",
        _NtClose,
        _NtDuplicateObject,
        _NtSetDebugFilterState,
        _NtCreateThread,
        _NtCreateThreadEx,
        _NtQuerySystemTime,
        _NtQueryPerformanceCounter,
        _NtResumeThread);

    if (hdd->EnableNtSetInformationThreadHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtSetInformationThread");
        HOOK_NATIVE(NtSetInformationThread);
    }
    if (hdd->EnableNtQuerySystemInformationHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtQuerySystemInformation");
        HOOK_NATIVE(NtQuerySystemInformation);
    }
    if (hdd->EnableNtQueryInformationProcessHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtQueryInformationProcess");
        HOOK_NATIVE(NtQueryInformationProcess);
    }
    if (hdd->EnableNtSetInformationProcessHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtSetInformationProcess");
        HOOK_NATIVE(NtSetInformationProcess);
    }

    if (hdd->EnableNtQueryObjectHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtQueryObject");
        HOOK_NATIVE(NtQueryObject);
    }
    if (hdd->EnableNtYieldExecutionHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtYieldExecution");
        HOOK_NATIVE(NtYieldExecution);
    }
    if (hdd->EnableNtGetContextThreadHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtGetContextThread");
        HOOK_NATIVE(NtGetContextThread);
    }
    if (hdd->EnableNtSetContextThreadHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtSetContextThread");
        HOOK_NATIVE(NtSetContextThread);
    }

    if (hdd->EnableNtCloseHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtClose");
        HOOK_NATIVE(NtClose);
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtDuplicateObject");
        HOOK_NATIVE(NtDuplicateObject);
    }
    if (hdd->EnablePreventThreadCreation == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtCreateThread");
        HOOK_NATIVE(NtCreateThread);
    }

    if (((hdd->EnablePreventThreadCreation == TRUE) || (hdd->EnableNtCreateThreadExHook == TRUE)) && _NtCreateThreadEx != 0)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtCreateThreadEx");
        HOOK_NATIVE(NtCreateThreadEx);
    }

    if (hdd->EnableNtSetDebugFilterStateHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtSetDebugFilterState");
        HOOK_NATIVE_NOTRAMP(NtSetDebugFilterState);
    }

#ifndef _WIN64
    if (hdd->EnableKiUserExceptionDispatcherHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking KiUserExceptionDispatcher");
        HOOK(KiUserExceptionDispatcher);
    }
    if (hdd->EnableNtContinueHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtContinue");
        HOOK_NATIVE(NtContinue);
    }
#endif

    if (hdd->EnableNtQuerySystemTimeHook == TRUE && _NtQuerySystemTime != 0)
    {
#ifdef _WIN64
        ULONG_PTR address = (ULONG_PTR)_NtQuerySystemTime;
        if (*(PUCHAR)address == 0xE9) // jmp rel32
        {
            g_log.LogDebug(L"ApplyNtdllHook -> Finding jmp to RtlQuerySystemTime at NtQuerySystemTime");
            LONG relativeOffset = *(PLONG)(address + 1);
            _NtQuerySystemTime = (t_NtQuerySystemTime)(address + relativeOffset + 5);
        }
#endif
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtQuerySystemTime at %p", _NtQuerySystemTime);
        HOOK_NATIVE(NtQuerySystemTime);
    }
    if (hdd->EnableNtQueryPerformanceCounterHook == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtQueryPerformanceCounter");
        HOOK_NATIVE(NtQueryPerformanceCounter);
    }

    if (hdd->EnableMalwareRunPeUnpacker == TRUE)
    {
        g_log.LogDebug(L"ApplyNtdllHook -> Hooking NtResumeThread for RUNPE UNPACKER");
        HOOK_NATIVE(NtResumeThread);
    }

    hdd->isNtdllHooked = TRUE;

#ifndef _WIN64
    hdd->NativeCallContinue = NativeCallContinue;
#endif
}

void ApplyKernel32Hook(HOOK_DLL_DATA * hdd, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
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
        g_log.LogDebug(L"ApplyKernel32Hook -> Using Kernelbase %p instead of kernel32 %p", hKernelbase, hKernel);
    }

    _GetTickCount = (t_GetTickCount)GetProcAddress(hCurrent, "GetTickCount");
    _GetTickCount64 = (t_GetTickCount64)GetProcAddress(hCurrent, "GetTickCount64");
    _GetLocalTime = (t_GetLocalTime)GetProcAddress(hCurrent, "GetLocalTime");
    _GetSystemTime = (t_GetSystemTime)GetProcAddress(hCurrent, "GetSystemTime");

    _OutputDebugStringA = (t_OutputDebugStringA)GetProcAddress(hCurrent, "OutputDebugStringA");

    g_log.LogDebug(L"ApplyKernel32Hook -> _GetTickCount %p _GetTickCount64 %p _GetLocalTime %p _GetSystemTime %p _OutputDebugStringA %p",
        _GetTickCount,
        _GetTickCount64,
        _GetLocalTime,
        _GetSystemTime,
        _OutputDebugStringA);

    if (hdd->EnableGetTickCountHook == TRUE)
    {
        g_log.LogDebug(L"ApplyKernel32Hook -> Hooking GetTickCount");
        HOOK(GetTickCount);
    }
    if (hdd->EnableGetTickCount64Hook == TRUE && _GetTickCount64 != 0)
    {
        g_log.LogDebug(L"ApplyKernel32Hook -> Hooking GetTickCount64");
        HOOK(GetTickCount64);
    }
    if (hdd->EnableGetLocalTimeHook == TRUE)
    {
        g_log.LogDebug(L"ApplyKernel32Hook -> Hooking GetLocalTime");
        HOOK(GetLocalTime);
    }
    if (hdd->EnableGetSystemTimeHook == TRUE)
    {
        g_log.LogDebug(L"ApplyKernel32Hook -> Hooking GetSystemTime");
        HOOK(GetSystemTime);
    }
    if (hdd->EnableOutputDebugStringHook == TRUE)
    {
        g_log.LogDebug(L"ApplyKernel32Hook -> Hooking OutputDebugStringA");
        HOOK(OutputDebugStringA);
    }
    hdd->isKernel32Hooked = TRUE;
}

void ApplyUser32Hook(HOOK_DLL_DATA * hdd, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hUser = GetModuleHandleW(L"user32.dll");
    hUserRemote = GetModuleBaseRemote(hProcess, L"user32.dll");

    if (!hUser || !hUserRemote)
    {
        g_log.LogDebug(L"ApplyUser32Hook -> dlls not loaded local %p remote %p", hUser, hUserRemote);
        return;
    }

    void * HookedBlockInput = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedBlockInput") + imageBase);
    void * HookedNtUserFindWindowEx = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserFindWindowEx") + imageBase);
    void * HookedNtUserBuildHwndList = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserBuildHwndList") + imageBase);
    void * HookedNtUserQueryWindow = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserQueryWindow") + imageBase);

    g_log.LogDebug(L"ApplyUser32Hook -> HookedBlockInput %p HookedNtUserFindWindowEx %p HookedNtUserBuildHwndList %p HookedNtUserQueryWindow %p",
        HookedBlockInput,
        HookedNtUserFindWindowEx,
        HookedNtUserBuildHwndList,
        HookedNtUserQueryWindow);

    if (hdd->NtUserBuildHwndListRVA && hdd->NtUserQueryWindowRVA)
    {
        _NtUserQueryWindow = (t_NtUserQueryWindow)((DWORD_PTR)hUserRemote + hdd->NtUserQueryWindowRVA);
        hdd->NtUserQueryWindow = _NtUserQueryWindow;
    }
    if (hdd->NtUserBuildHwndListRVA && hdd->NtUserQueryWindowRVA)
    {
        _NtUserBuildHwndList = (t_NtUserBuildHwndList)((DWORD_PTR)hUserRemote + hdd->NtUserBuildHwndListRVA);
    }
    if (hdd->NtUserFindWindowExRVA)
    {
        _NtUserFindWindowEx = (t_NtUserFindWindowEx)((DWORD_PTR)hUserRemote + hdd->NtUserFindWindowExRVA);
    }
    _BlockInput = (t_BlockInput)GetProcAddress(hUser, "BlockInput");

    g_log.LogDebug(L"ApplyUser32Hook -> _BlockInput %p _NtUserFindWindowEx %p _NtUserBuildHwndList %p _NtUserQueryWindow %p",
        _BlockInput,
        _NtUserFindWindowEx,
        _NtUserBuildHwndList,
        _NtUserQueryWindow);

    if (hdd->EnableBlockInputHook == TRUE)
    {
        g_log.LogDebug(L"ApplyUser32Hook -> Hooking BlockInput");
        HOOK_NATIVE(BlockInput);
    }
    if (hdd->EnableNtUserFindWindowExHook == TRUE && _NtUserFindWindowEx != 0)
    {
        g_log.LogDebug(L"ApplyUser32Hook -> Hooking NtUserFindWindowEx");
        HOOK_NATIVE(NtUserFindWindowEx);
    }
    if (hdd->EnableNtUserBuildHwndListHook == TRUE && _NtUserBuildHwndList != 0)
    {
        g_log.LogDebug(L"ApplyUser32Hook -> Hooking NtUserBuildHwndList");
        HOOK_NATIVE(NtUserBuildHwndList);
    }
    if (hdd->EnableNtUserQueryWindowHook == TRUE && _NtUserQueryWindow != 0)
    {
        g_log.LogDebug(L"ApplyUser32Hook -> Hooking NtUserQueryWindow");
        HOOK_NATIVE(NtUserQueryWindow);
    }

    hdd->isUser32Hooked = TRUE;
}

void ApplyWin32uHook(HOOK_DLL_DATA * hdd, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
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

    g_log.LogDebug(L"ApplyWin32uHook -> _NtUserBlockInput %p _NtUserFindWindowEx %p _NtUserBuildHwndList %p _NtUserQueryWindow %p",
        _NtUserBlockInput,
        _NtUserFindWindowEx,
        _NtUserBuildHwndList,
        _NtUserQueryWindow);

    if (hdd->EnableBlockInputHook) {
        g_log.LogDebug(L"ApplyWin32uHook -> Hooking NtUserBlockInput");
        HOOK_NATIVE(NtUserBlockInput);
    }
    if (hdd->EnableNtUserFindWindowExHook) {
        g_log.LogDebug(L"ApplyWin32uHook -> Hooking NtUserFindWindowEx");
        HOOK_NATIVE(NtUserFindWindowEx);
    }
    if (hdd->EnableNtUserBuildHwndListHook) {
        g_log.LogDebug(L"ApplyWin32uHook -> Hooking NtUserBuildHwndList");
        HOOK_NATIVE(NtUserBuildHwndList);
    }
    if (hdd->EnableNtUserQueryWindowHook) {
        g_log.LogDebug(L"ApplyWin32uHook -> Hooking NtUserQueryWindow");
        HOOK_NATIVE(NtUserQueryWindow);
    }

    hdd->isWin32uHooked = TRUE;
}

void ApplyPEBPatch(HANDLE hProcess, DWORD flags)
{
    auto peb = scl::GetPeb(hProcess);
    if (!peb) {
        g_log.LogError(L"Failed to read PEB from remote process");
    }
    else
    {
        if (flags & PEB_PATCH_BeingDebugged)
            peb->BeingDebugged = FALSE;
        if (flags & PEB_PATCH_NtGlobalFlag)
            peb->NtGlobalFlag &= ~0x70;

        if (flags & PEB_PATCH_ProcessParameters) {
            if (!scl::PebPatchProcessParameters(peb.get(), hProcess))
                g_log.LogError(L"Failed to patch PEB!ProcessParameters");
        }

        if (flags & PEB_PATCH_HeapFlags)
        {
            if (!scl::PebPatchHeapFlags(peb.get(), hProcess))
                g_log.LogError(L"Failed to patch flags in PEB!ProcessHeaps");
        }

        if (!scl::SetPeb(hProcess, peb.get()))
            g_log.LogError(L"Failed to write PEB to remote process");

    }

#ifndef _WIN64
    if (!scl::IsWow64Process(hProcess))
        return;

    auto peb64 = scl::Wow64GetPeb64(hProcess);
    if (!peb64) {
        g_log.LogError(L"Failed to read PEB64 from remote process");
    }
    else
    {
        if (flags & PEB_PATCH_BeingDebugged)
            peb64->BeingDebugged = FALSE;
        if (flags & PEB_PATCH_NtGlobalFlag)
            peb64->NtGlobalFlag &= ~0x70;

        if (flags & PEB_PATCH_ProcessParameters) {
            if (!scl::Wow64Peb64PatchProcessParameters(peb64.get(), hProcess))
                g_log.LogError(L"Failed to patch PEB64!ProcessParameters");
        }

        if (flags & PEB_PATCH_HeapFlags)
        {
            if (!scl::Wow64Peb64PatchHeapFlags(peb64.get(), hProcess))
                g_log.LogError(L"Failed to patch flags in PEB64!ProcessHeaps");
        }

        if (!scl::Wow64SetPeb64(hProcess, peb64.get()))
            g_log.LogError(L"Failed to write PEB64 to remote process");
    }
#endif
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

void RestoreNtdllHooks(HOOK_DLL_DATA * hdd, HANDLE hProcess)
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
    RESTORE_JMP(NtDuplicateObject);
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
    FREE_HOOK(NtDuplicateObject);
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



    hdd->isNtdllHooked = FALSE;
}

void RestoreKernel32Hooks(HOOK_DLL_DATA * hdd, HANDLE hProcess)
{
    RESTORE_JMP(GetTickCount);
    FREE_HOOK(GetTickCount);

    RESTORE_JMP(OutputDebugStringA);
    FREE_HOOK(OutputDebugStringA);

    hdd->isKernel32Hooked = FALSE;
}

void RestoreUser32Hooks(HOOK_DLL_DATA * hdd, HANDLE hProcess)
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

    hdd->isUser32Hooked = FALSE;
}

void RestoreWin32uHooks(HOOK_DLL_DATA * hdd, HANDLE hProcess)
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

    hdd->isWin32uHooked = FALSE;
}

void RestoreHooks(HOOK_DLL_DATA * hdd, HANDLE hProcess)
{
    if (hdd->isNtdllHooked == TRUE)
    {
        RestoreNtdllHooks(hdd, hProcess);
    }

    if (hdd->isKernel32Hooked == TRUE)
    {
        RestoreKernel32Hooks(hdd, hProcess);
    }

    if (hdd->isUser32Hooked == TRUE)
    {
        RestoreUser32Hooks(hdd, hProcess);
    }
    if (hdd->isWin32uHooked == TRUE)
    {
        RestoreWin32uHooks(hdd, hProcess);
    }

    FreeMemory(hProcess, hdd->hDllImage);
    hdd->hDllImage = 0;
}

bool ApplyHook(HOOK_DLL_DATA * hdd, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    bool retVal = false;
    hdd->hDllImage = (HMODULE)imageBase;

    if (hdd->isNtdllHooked == FALSE)
    {
        retVal = true;
        ApplyNtdllHook(hdd, hProcess, dllMemory, imageBase);
    }
    if (hdd->isKernel32Hooked == FALSE)
    {
        retVal = true;
        ApplyKernel32Hook(hdd, hProcess, dllMemory, imageBase);
    }
    if (!hdd->isUser32Hooked && !hdd->isWin32uHooked)
    {
        if (GetModuleHandleW(L"win32u.dll"))
        {
            ApplyWin32uHook(hdd, hProcess, dllMemory, imageBase);
        }
        else {
            ApplyUser32Hook(hdd, hProcess, dllMemory, imageBase);
        }
    }

    return retVal;
}
