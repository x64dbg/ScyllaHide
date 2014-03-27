#include "HookMain.h"
#include "Hook.h"
#include "ntdll.h"
#include "HookedFunctions.h"

HOOK_DLL_EXCHANGE DllExchange = { 0 };

void StartHooking();
bool ResolveImports(PIMAGE_IMPORT_DESCRIPTOR pImport, DWORD_PTR module);

extern t_NtSetInformationThread dNtSetInformationThread;
extern t_NtQuerySystemInformation dNtQuerySystemInformation;
extern t_NtQueryInformationProcess dNtQueryInformationProcess;
extern t_GetTickCount dGetTickCount;
extern t_BlockInput dBlockInput;

#define HOOK(name) d##name = (t_##name)DetourCreate(_##name, Hooked##name)

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
				StartHooking();
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

void StartHooking()
{
	MessageBoxA(0, "StartHooking", "StartHooking", 0);

	t_NtSetInformationThread _NtSetInformationThread = (t_NtSetInformationThread)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtSetInformationThread");
	t_NtQuerySystemInformation _NtQuerySystemInformation = (t_NtQuerySystemInformation)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQuerySystemInformation");
	t_NtQueryInformationProcess _NtQueryInformationProcess = (t_NtQueryInformationProcess)DllExchange.fGetProcAddress(DllExchange.hNtdll, "NtQueryInformationProcess");

	

	t_GetTickCount _GetTickCount;
	if (DllExchange.hkernelBase)
	{
		_GetTickCount = (t_GetTickCount)DllExchange.fGetProcAddress(DllExchange.hkernelBase, "GetTickCount");
	}
	else
	{
		_GetTickCount = (t_GetTickCount)DllExchange.fGetProcAddress(DllExchange.hkernel32, "GetTickCount");
	}

	if (DllExchange.hUser32)
	{
		t_BlockInput _BlockInput = (t_BlockInput)DllExchange.fGetProcAddress(DllExchange.hUser32, "BlockInput");
		HOOK(BlockInput);
	}

	HOOK(NtSetInformationThread);
	HOOK(NtQuerySystemInformation);
	HOOK(NtQueryInformationProcess);
	HOOK(GetTickCount);
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