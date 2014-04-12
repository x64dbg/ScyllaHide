#include "ApplyHooking.h"
#include "DynamicMapping.h"
#include "RemotePebHider.h"
#include "RemoteHook.h"

#define HOOK(name) dllexchange->d##name = (t_##name)DetourCreateRemote(hProcess,_##name, Hooked##name, true)
#define HOOK_NATIVE(name) dllexchange->d##name = (t_##name)DetourCreateRemoteNative(hProcess,_##name, Hooked##name, true)
#define HOOK_NATIVE_NOTRAMP(name) DetourCreateRemoteNative(hProcess,_##name, Hooked##name, false)
#define HOOK_NOTRAMP(name) DetourCreateRemote(hProcess,_##name, Hooked##name, false)

void * HookedNativeCallInternal = 0;
void * NativeCallContinue = 0;
int countNativeHooks = 0;
HOOK_NATIVE_CALL32 * HookNative = 0;
bool onceNativeCallContinue = false;

void ApplyNtdllHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	
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

	HookedNativeCallInternal = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNativeCallInternal") + imageBase);

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
	HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
	HMODULE hKernelbase = GetModuleHandleW(L"kernelbase.dll");

	void * HookedOutputDebugStringA = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedOutputDebugStringA") + imageBase);
	void * HookedGetTickCount = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedGetTickCount") + imageBase);

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
	if (dllexchange->EnableGetTickCountHook == TRUE) HOOK(GetTickCount);
	if (dllexchange->EnableOutputDebugStringHook == TRUE) HOOK_NOTRAMP(OutputDebugStringA);

	dllexchange->isKernel32Hooked = TRUE;
}

void ApplyUser32Hook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
	HMODULE hUser = GetModuleHandleW(L"user32.dll");
	HMODULE hUserRemote = GetModuleBaseRemote(hProcess, L"user32.dll");

	if (hUser && hUserRemote)
	{
		void * HookedBlockInput = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedBlockInput") + imageBase);
		void * HookedNtUserFindWindowEx = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserFindWindowEx") + imageBase);
		void * HookedNtUserBuildHwndList = (void *)(GetDllFunctionAddressRVA(dllMemory, "HookedNtUserBuildHwndList") + imageBase);

		dllexchange->isUser32Hooked = TRUE;

		t_NtUserBuildHwndList _NtUserBuildHwndList = 0;
		t_NtUserFindWindowEx _NtUserFindWindowEx = 0;
		t_NtUserQueryWindow _NtUserQueryWindow = 0;

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
		t_BlockInput _BlockInput = (t_BlockInput)GetProcAddress(hUser, "BlockInput");

		if (dllexchange->EnableBlockInputHook == TRUE) HOOK(BlockInput);
		if (dllexchange->EnableNtUserFindWindowExHook == TRUE && _NtUserFindWindowEx != 0) HOOK(NtUserFindWindowEx);
		if (dllexchange->EnableNtUserBuildHwndListHook == TRUE && _NtUserBuildHwndList != 0) HOOK(NtUserBuildHwndList);
	}
}

bool ApplyHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
	bool retVal = false;
	dllexchange->hDllImage = (HMODULE)imageBase;

	if (dllexchange->EnablePebHiding == TRUE) FixPebInProcess(hProcess);

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