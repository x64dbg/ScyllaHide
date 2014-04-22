#include "ApplyHooking.h"
#include "DynamicMapping.h"
#include "RemotePebHider.h"
#include "RemoteHook.h"

#define HOOK(name) dllexchange->d##name = (t_##name)DetourCreateRemote(hProcess,_##name, Hooked##name, true, &dllexchange->##name##BackupSize)
#define HOOK_NATIVE(name) dllexchange->d##name = (t_##name)DetourCreateRemoteNative(hProcess,_##name, Hooked##name, true, 0)
#define HOOK_NATIVE_NOTRAMP(name) DetourCreateRemoteNative(hProcess,_##name, Hooked##name, false, 0)
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

t_KiUserExceptionDispatcher _KiUserExceptionDispatcher = 0;
t_OutputDebugStringA _OutputDebugStringA = 0;
t_GetTickCount _GetTickCount = 0;

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

    if (dllexchange->EnableNtSetInformationThreadHook == TRUE) HOOK_NATIVE(NtSetInformationThread);
    if (dllexchange->EnableNtQuerySystemInformationHook == TRUE) HOOK_NATIVE(NtQuerySystemInformation);
    if (dllexchange->EnableNtQueryInformationProcessHook == TRUE)
    {
        HOOK_NATIVE(NtQueryInformationProcess);
        HOOK_NATIVE(NtSetInformationProcess);
    }
    if (dllexchange->EnableNtQueryObjectHook == TRUE) HOOK_NATIVE(NtQueryObject);
    if (dllexchange->EnableNtYieldExecutionHook == TRUE) HOOK_NATIVE(NtYieldExecution);
    if (dllexchange->EnableNtGetContextThreadHook == TRUE) HOOK_NATIVE(NtGetContextThread);
    if (dllexchange->EnableNtSetContextThreadHook == TRUE) HOOK_NATIVE(NtSetContextThread);

    if (dllexchange->EnableNtCloseHook == TRUE) HOOK_NATIVE(NtClose);
    if (dllexchange->EnablePreventThreadCreation == TRUE) HOOK_NATIVE(NtCreateThread);
    if (((dllexchange->EnablePreventThreadCreation == TRUE) || (dllexchange->EnableNtCreateThreadExHook == TRUE)) && _NtCreateThreadEx != 0) HOOK_NATIVE(NtCreateThreadEx);

    if (dllexchange->EnableNtSetDebugFilterStateHook == TRUE) HOOK_NATIVE_NOTRAMP(NtSetDebugFilterState);

#ifndef _WIN64
    if (dllexchange->EnableKiUserExceptionDispatcherHook == TRUE) HOOK(KiUserExceptionDispatcher);
    if (dllexchange->EnableNtContinueHook == TRUE) HOOK_NATIVE(NtContinue);
#endif

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
    if (dllexchange->EnableGetTickCountHook == TRUE) HOOK(GetTickCount);
    if (dllexchange->EnableOutputDebugStringHook == TRUE) HOOK(OutputDebugStringA);

    dllexchange->isKernel32Hooked = TRUE;
}

void ApplyUser32Hook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    hUser = GetModuleHandleW(L"user32.dll");
    hUserRemote = GetModuleBaseRemote(hProcess, L"user32.dll");

    if (hUser && hUserRemote)
    {
        void * HookedBlockInput = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedBlockInput") + imageBase);
        void * HookedNtUserFindWindowEx = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserFindWindowEx") + imageBase);
        void * HookedNtUserBuildHwndList = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserBuildHwndList") + imageBase);

        dllexchange->isUser32Hooked = TRUE;

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

        if (dllexchange->EnableBlockInputHook == TRUE) HOOK_NATIVE(BlockInput);
        if (dllexchange->EnableNtUserFindWindowExHook == TRUE && _NtUserFindWindowEx != 0) HOOK_NATIVE(NtUserFindWindowEx);
        if (dllexchange->EnableNtUserBuildHwndListHook == TRUE && _NtUserBuildHwndList != 0) HOOK_NATIVE(NtUserBuildHwndList);
    }
}

bool ApplyPEBPatch(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, DWORD enableFlags)
{
    if (hProcess && dllexchange)
    {
        //DWORD enableEverything = PEB_PATCH_BeingDebugged|PEB_PATCH_HeapFlags|PEB_PATCH_NtGlobalFlag|PEB_PATCH_StartUpInfo;
        if (dllexchange->EnablePebBeingDebugged ||
                dllexchange->EnablePebHeapFlags ||
                dllexchange->EnablePebNtGlobalFlag ||
                dllexchange->EnablePebStartupInfo) FixPebInProcess(hProcess, enableFlags);
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

void RestoreNtdllHooks( HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess )
{
#ifndef _WIN64
    if (IsSysWow64())
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

void RestoreKernel32Hooks( HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess )
{
    RESTORE_JMP(GetTickCount);
    FREE_HOOK(GetTickCount);

    RESTORE_JMP(OutputDebugStringA);
    FREE_HOOK(OutputDebugStringA);

    dllexchange->isKernel32Hooked = FALSE;
}

void RestoreUser32Hooks( HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess )
{

#ifdef _WIN64
    RESTORE_JMP(BlockInput);
    RESTORE_JMP(NtUserFindWindowEx);
    RESTORE_JMP(NtUserBuildHwndList);
#endif

    FREE_HOOK(BlockInput);
    FREE_HOOK(NtUserFindWindowEx);
    FREE_HOOK(NtUserBuildHwndList);

    dllexchange->isUser32Hooked = FALSE;
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
    if (dllexchange->isUser32Hooked == FALSE)
    {
        retVal = true;
        ApplyUser32Hook(dllexchange, hProcess, dllMemory, imageBase);
    }

    return retVal;
}