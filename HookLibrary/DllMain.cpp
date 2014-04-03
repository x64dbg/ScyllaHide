#include "HookMain.h"
#include "Hook.h"
#include "ntdll.h"
#include "HookedFunctions.h"
#include "PebHider.h"

HOOK_DLL_EXCHANGE DllExchange = { 0 };

void StartHiding();
bool ResolveImports(PIMAGE_IMPORT_DESCRIPTOR pImport, DWORD_PTR module);

extern t_NtSetInformationThread dNtSetInformationThread;
extern t_NtQuerySystemInformation dNtQuerySystemInformation;
extern t_NtQueryInformationProcess dNtQueryInformationProcess;
extern t_NtSetInformationProcess dNtSetInformationProcess;
extern t_NtQueryObject dNtQueryObject;
extern t_NtYieldExecution dNtYieldExecution;
extern t_NtGetContextThread dNtGetContextThread;
extern t_NtSetContextThread dNtSetContextThread;
extern t_KiUserExceptionDispatcher dKiUserExceptionDispatcher;
extern t_NtContinue dNtContinue;
extern t_NtClose dNtClose;

extern t_GetTickCount dGetTickCount;
extern t_BlockInput dBlockInput;
//extern t_OutputDebugStringA dOutputDebugStringA;

#define HOOK(name) d##name = (t_##name)DetourCreate(_##name, Hooked##name, true)
#define HOOK_NOTRAMP(name) DetourCreate(_##name, Hooked##name, false)

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
    return TRUE;
}

DWORD WINAPI InitDll(LPVOID imageBase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
    t_DllMain _DLLMain = (t_DllMain)((DWORD_PTR)imageBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);

    if (pDosHeader && pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && pNtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        if (ResolveImports((PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)imageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), (DWORD_PTR)imageBase))
        {
            if (_DLLMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, 0))
            {
                ZeroMemory(imageBase, pNtHeader->OptionalHeader.SizeOfHeaders);
                StartHiding();
                return HOOK_ERROR_SUCCESS;
            }
            else
            {
                return HOOK_ERROR_DLLMAIN;
            }
        }
        else
        {
            return HOOK_ERROR_RESOLVE_IMPORT;
        }
    }
    else
    {
        return HOOK_ERROR_PEHEADER;
    }
}

void StartHiding()
{
    MessageBoxA(0, "StartHiding", "StartHiding", 0);

	t_NtSetInformationThread _NtSetInformationThread = (t_NtSetInformationThread)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtSetInformationThread");
	t_NtQuerySystemInformation _NtQuerySystemInformation = (t_NtQuerySystemInformation)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQuerySystemInformation");
	t_NtQueryInformationProcess _NtQueryInformationProcess = (t_NtQueryInformationProcess)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQueryInformationProcess");
	t_NtSetInformationProcess _NtSetInformationProcess = (t_NtSetInformationProcess)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtSetInformationProcess");
	t_NtQueryObject _NtQueryObject = (t_NtQueryObject)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQueryObject");
	t_NtYieldExecution _NtYieldExecution = (t_NtYieldExecution)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtYieldExecution");
	t_NtGetContextThread _NtGetContextThread = (t_NtGetContextThread)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtGetContextThread");
	t_NtSetContextThread _NtSetContextThread = (t_NtSetContextThread)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtSetContextThread");
	t_KiUserExceptionDispatcher _KiUserExceptionDispatcher = (t_KiUserExceptionDispatcher)DllExchange.fGetProcAddress(DllExchange.hNtdll, "KiUserExceptionDispatcher");
	t_NtContinue _NtContinue = (t_NtContinue)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtContinue");
	t_NtClose _NtClose = (t_NtClose)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtClose");

	t_OutputDebugStringA _OutputDebugStringA;
	t_GetTickCount _GetTickCount;
	if (DllExchange.hkernelBase)
	{
		_GetTickCount = (t_GetTickCount)DllExchange.fGetProcAddress(DllExchange.hkernelBase, "GetTickCount");
		_OutputDebugStringA = (t_OutputDebugStringA)DllExchange.fGetProcAddress(DllExchange.hkernelBase, "OutputDebugStringA");
	}
	else
	{
		_GetTickCount = (t_GetTickCount)DllExchange.fGetProcAddress(DllExchange.hkernel32, "GetTickCount");
		_OutputDebugStringA = (t_OutputDebugStringA)DllExchange.fGetProcAddress(DllExchange.hkernel32, "OutputDebugStringA");
	}

	if (DllExchange.hUser32)
	{
		t_BlockInput _BlockInput = (t_BlockInput)DllExchange.fGetProcAddress(DllExchange.hUser32, "BlockInput");
		if (DllExchange.EnableBlockInputHook == TRUE) HOOK(BlockInput);
	}


	if (DllExchange.EnablePebHiding == TRUE) FixPebAntidebug();

	if (DllExchange.EnableNtSetInformationThreadHook == TRUE) HOOK(NtSetInformationThread);
	if (DllExchange.EnableNtQuerySystemInformationHook == TRUE) HOOK(NtQuerySystemInformation);
	if (DllExchange.EnableNtQueryInformationProcessHook == TRUE)
	{
		HOOK(NtQueryInformationProcess);
		HOOK(NtSetInformationProcess);
	}
	if (DllExchange.EnableNtQueryObjectHook == TRUE) HOOK(NtQueryObject);
	if (DllExchange.EnableNtYieldExecutionHook == TRUE) HOOK(NtYieldExecution);
	if (DllExchange.EnableNtGetContextThreadHook == TRUE) HOOK(NtGetContextThread);
	if (DllExchange.EnableNtSetContextThreadHook == TRUE) HOOK(NtSetContextThread);
    //if (DllExchange.EnableKiUserExceptionDispatcherHook == TRUE) HOOK(KiUserExceptionDispatcher);
	if (DllExchange.EnableNtContinueHook == TRUE) HOOK(NtContinue);
	if (DllExchange.EnableNtCloseHook == TRUE) HOOK(NtClose);

	if (DllExchange.EnableGetTickCountHook == TRUE) HOOK(GetTickCount);

	if (DllExchange.EnableOutputDebugStringHook == TRUE) HOOK_NOTRAMP(OutputDebugStringA);
}

bool ResolveImports(PIMAGE_IMPORT_DESCRIPTOR pImport, DWORD_PTR module)
{
    PIMAGE_THUNK_DATA thunkRef;
    PIMAGE_THUNK_DATA funcRef;

    while (pImport->FirstThunk)
    {
        char * moduleName = (char *)(module + pImport->Name);

        HMODULE hModule = DllExchange.fGetModuleHandleA(moduleName);

        if (!hModule)
        {
            hModule = DllExchange.fLoadLibraryA(moduleName);
            if (!hModule)
            {
                return false;
            }
        }

        funcRef = (PIMAGE_THUNK_DATA)(module + pImport->FirstThunk);
        if (pImport->OriginalFirstThunk)
        {
            thunkRef = (PIMAGE_THUNK_DATA)(module + pImport->OriginalFirstThunk);
        }
        else
        {
            thunkRef = (PIMAGE_THUNK_DATA)(module + pImport->FirstThunk);
        }

        while (thunkRef->u1.Function)
        {
            if (IMAGE_SNAP_BY_ORDINAL(thunkRef->u1.Function))
            {
                funcRef->u1.Function = (DWORD_PTR)DllExchange.fGetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(thunkRef->u1.Ordinal));
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(module + thunkRef->u1.AddressOfData);
                funcRef->u1.Function = (DWORD_PTR)DllExchange.fGetProcAddress(hModule, (LPCSTR)thunkData->Name);
            }

            if (!funcRef->u1.Function)
            {
                return false;
            }

            thunkRef++;
            funcRef++;
        }

        pImport++;
    }

    return true;
}