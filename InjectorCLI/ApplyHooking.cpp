#include "ApplyHooking.h"
#include "DynamicMapping.h"
#include "RemotePebHider.h"
#include "RemoteHook.h"

#define HOOK(name) dllexchange->d##name = (t_##name)DetourCreateRemote(hProcess,_##name, Hooked##name, true)
#define HOOK_NOTRAMP(name) DetourCreateRemote(hProcess,_##name, Hooked##name, false)

void ApplyNtdllHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

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


	if (dllexchange->EnableNtSetInformationThreadHook == TRUE) HOOK(NtSetInformationThread);
	if (dllexchange->EnableNtQuerySystemInformationHook == TRUE) HOOK(NtQuerySystemInformation);
	if (dllexchange->EnableNtQueryInformationProcessHook == TRUE)
	{
		HOOK(NtQueryInformationProcess);
		HOOK(NtSetInformationProcess);
	}
	if (dllexchange->EnableNtQueryObjectHook == TRUE) HOOK(NtQueryObject);
	if (dllexchange->EnableNtYieldExecutionHook == TRUE) HOOK(NtYieldExecution);
	if (dllexchange->EnableNtGetContextThreadHook == TRUE) HOOK(NtGetContextThread);
	if (dllexchange->EnableNtSetContextThreadHook == TRUE) HOOK(NtSetContextThread);

	if (dllexchange->EnableNtCloseHook == TRUE) HOOK(NtClose);
	if (dllexchange->EnableNtSetDebugFilterStateHook == TRUE) HOOK_NOTRAMP(NtSetDebugFilterState);

#ifndef _WIN64
	if (dllexchange->EnableKiUserExceptionDispatcherHook == TRUE) HOOK(KiUserExceptionDispatcher);
	if (dllexchange->EnableNtContinueHook == TRUE) HOOK(NtContinue);
#endif

	dllexchange->isNtdllHooked = TRUE;
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

void ApplyHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
	dllexchange->hDllImage = (HMODULE)imageBase;

	if (dllexchange->EnablePebHiding == TRUE) FixPebInProcess(hProcess);

	if (dllexchange->isNtdllHooked == FALSE)
	{
		ApplyNtdllHook(dllexchange, hProcess, dllMemory, imageBase);
	}
	if (dllexchange->isKernel32Hooked == FALSE)
	{
		ApplyKernel32Hook(dllexchange, hProcess, dllMemory, imageBase);
	}
	if (dllexchange->isUser32Hooked == FALSE)
	{
		ApplyUser32Hook(dllexchange, hProcess, dllMemory, imageBase);
	}
}