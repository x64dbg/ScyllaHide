#include "HookMain.h"
#include "Hook.h"
#include "ntdll.h"
#include "HookedFunctions.h"
#include "PebHider.h"

HOOK_DLL_EXCHANGE DllExchange = { 0 };

void StartHiding();

#pragma comment(linker, "/ENTRY:DllMain")


#define HOOK(name) d##name = (t_##name)DetourCreate(_##name, Hooked##name, true)
#define HOOK_NOTRAMP(name) DetourCreate(_##name, Hooked##name, false)

bool once = false;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}

//DWORD WINAPI InitDll(LPVOID notUsed)
DWORD InitDll()
{
    if (once == false)
    {
        once = true;
    }
    else
    {
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)DllExchange.hDllImage;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
    t_DllMain _DLLMain = (t_DllMain)((DWORD_PTR)DllExchange.hDllImage + pNtHeader->OptionalHeader.AddressOfEntryPoint);

    if (pDosHeader && pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && pNtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        //if (ResolveImports((PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)imageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), (DWORD_PTR)imageBase))
        //{
        //if (_DLLMain((HINSTANCE)DllExchange.hDllImage, DLL_PROCESS_ATTACH, 0))
        //{
        ZeroMemory(DllExchange.hDllImage, pNtHeader->OptionalHeader.SizeOfHeaders);
        //StartHiding();
        return HOOK_ERROR_SUCCESS;
        //}
        //else
        //{
        //	return HOOK_ERROR_DLLMAIN;
        //}
        //}
        //else
        //{
        //    return HOOK_ERROR_RESOLVE_IMPORT;
        //}
    }
    else
    {
        return HOOK_ERROR_PEHEADER;
    }
}

//void StartHiding()
//{
//    //MessageBoxA(0, "StartHiding", "StartHiding", 0);
//
//	t_NtSetInformationThread _NtSetInformationThread = (t_NtSetInformationThread)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtSetInformationThread");
//	t_NtQuerySystemInformation _NtQuerySystemInformation = (t_NtQuerySystemInformation)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQuerySystemInformation");
//	t_NtQueryInformationProcess _NtQueryInformationProcess = (t_NtQueryInformationProcess)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQueryInformationProcess");
//	t_NtSetInformationProcess _NtSetInformationProcess = (t_NtSetInformationProcess)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtSetInformationProcess");
//	t_NtQueryObject _NtQueryObject = (t_NtQueryObject)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQueryObject");
//	t_NtYieldExecution _NtYieldExecution = (t_NtYieldExecution)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtYieldExecution");
//	t_NtGetContextThread _NtGetContextThread = (t_NtGetContextThread)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtGetContextThread");
//	t_NtSetContextThread _NtSetContextThread = (t_NtSetContextThread)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtSetContextThread");
//	t_KiUserExceptionDispatcher _KiUserExceptionDispatcher = (t_KiUserExceptionDispatcher)DllExchange.fGetProcAddress(DllExchange.hNtdll, "KiUserExceptionDispatcher");
//	t_NtContinue _NtContinue = (t_NtContinue)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtContinue");
//	t_NtClose _NtClose = (t_NtClose)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtClose");
//
//	t_OutputDebugStringA _OutputDebugStringA;
//	t_GetTickCount _GetTickCount;
//	if (DllExchange.hkernelBase)
//	{
//		_GetTickCount = (t_GetTickCount)DllExchange.fGetProcAddress(DllExchange.hkernelBase, "GetTickCount");
//		_OutputDebugStringA = (t_OutputDebugStringA)DllExchange.fGetProcAddress(DllExchange.hkernelBase, "OutputDebugStringA");
//	}
//	else
//	{
//		_GetTickCount = (t_GetTickCount)DllExchange.fGetProcAddress(DllExchange.hkernel32, "GetTickCount");
//		_OutputDebugStringA = (t_OutputDebugStringA)DllExchange.fGetProcAddress(DllExchange.hkernel32, "OutputDebugStringA");
//	}
//
//	if (DllExchange.hUser32)
//	{
//		t_NtUserFindWindowEx _NtUserFindWindowEx = 0;
//		if (DllExchange.NtUserFindWindowExRVA)
//		{
//			_NtUserFindWindowEx = (t_NtUserFindWindowEx)((DWORD_PTR)DllExchange.hUser32 + DllExchange.NtUserFindWindowExRVA);
//		}
//		t_BlockInput _BlockInput = (t_BlockInput)DllExchange.fGetProcAddress(DllExchange.hUser32, "BlockInput");
//
//		if (DllExchange.EnableBlockInputHook == TRUE) HOOK(BlockInput);
//		if (DllExchange.EnableNtUserFindWindowExHook == TRUE && _NtUserFindWindowEx != 0) HOOK(NtUserFindWindowEx);
//	}
//
//
//	if (DllExchange.EnablePebHiding == TRUE) FixPebAntidebug();
//
//	if (DllExchange.EnableNtSetInformationThreadHook == TRUE) HOOK(NtSetInformationThread);
//	if (DllExchange.EnableNtQuerySystemInformationHook == TRUE) HOOK(NtQuerySystemInformation);
//	if (DllExchange.EnableNtQueryInformationProcessHook == TRUE)
//	{
//		HOOK(NtQueryInformationProcess);
//		HOOK(NtSetInformationProcess);
//	}
//	if (DllExchange.EnableNtQueryObjectHook == TRUE) HOOK(NtQueryObject);
//	if (DllExchange.EnableNtYieldExecutionHook == TRUE) HOOK(NtYieldExecution);
//	if (DllExchange.EnableNtGetContextThreadHook == TRUE) HOOK(NtGetContextThread);
//	if (DllExchange.EnableNtSetContextThreadHook == TRUE) HOOK(NtSetContextThread);
//    //if (DllExchange.EnableKiUserExceptionDispatcherHook == TRUE) HOOK(KiUserExceptionDispatcher);
//	if (DllExchange.EnableNtContinueHook == TRUE) HOOK(NtContinue);
//	if (DllExchange.EnableNtCloseHook == TRUE) HOOK(NtClose);
//
//	if (DllExchange.EnableGetTickCountHook == TRUE) HOOK(GetTickCount);
//
//	if (DllExchange.EnableOutputDebugStringHook == TRUE) HOOK_NOTRAMP(OutputDebugStringA);
//}

