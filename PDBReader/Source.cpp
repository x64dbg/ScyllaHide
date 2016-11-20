#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <dbghelp_wrapper.h>
#include <stdio.h>
#include "..\InjectorCLI\OperatingSysInfo.h"

#pragma comment(lib,"dbghelp.lib")


BYTE memory[0x2000];
WCHAR symbolPath[0x2000] = { 0 };
OSVERSIONINFOEXW osver = { 0 };
SYSTEM_INFO si = { 0 };

WCHAR OsId[500] = { 0 };
WCHAR temp[100] = { 0 };
WCHAR returnBuf[0x2000] = { 0 };
WCHAR iniPath[MAX_PATH] = { 0 };


typedef void (WINAPI *t_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);


WCHAR * functionNames[] = {
	L"NtUserQueryWindow",
	L"NtUserBuildHwndList",
	L"NtUserFindWindowEx",
	L"NtUserInternalGetWindowText",
	L"NtUserGetClassName"
};

DWORD_PTR functionVA[_countof(functionNames)] = {0};
DWORD functionRVA[_countof(functionNames)] = {0};

void WriteApiInIni(const WCHAR * name, DWORD address) //rva
{
	wsprintfW(returnBuf, L"%08X", address);
	WritePrivateProfileStringW(OsId, name, returnBuf, iniPath);
}

ULONG_PTR GetFunctionAddressPDB(HMODULE hMod, const WCHAR * name)
{
	ZeroMemory(memory, sizeof(memory));

	SYMBOL_INFOW * info = (SYMBOL_INFOW *)memory;
	info->SizeOfStruct = sizeof(SYMBOL_INFOW);
	info->MaxNameLen = MAX_SYM_NAME;
	info->ModBase = (ULONG_PTR)hMod;

	if (!SymFromNameW(GetCurrentProcess(), name, info))
	{
		DWORD err = GetLastError();
		printf("SymFromName %S returned error : %d\n", name, err);

		if (err == ERROR_MOD_NOT_FOUND)
		{
			printf("126 - ERROR_MOD_NOT_FOUND - You must have a working internet connection to download missing PDB files!\n\n");
		}
		return 0;
	}

	return (ULONG_PTR)info->Address;
}

void QueryOsInfo()
{
	t_GetNativeSystemInfo _GetNativeSystemInfo = (t_GetNativeSystemInfo)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNativeSystemInfo");
	if (_GetNativeSystemInfo)
	{
		_GetNativeSystemInfo(&si);
	}
	else
	{
		GetSystemInfo(&si);
	}

	osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&osver);

    if (_IsWindows8Point1OrGreater())
    {
        //adjust real major minor version
        GetPEBWindowsMajorMinorVersion(&osver.dwMajorVersion, &osver.dwMinorVersion);
    }
}

int wmain(int argc, wchar_t* argv[])
{
	QueryOsInfo();

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED);

	WCHAR path[MAX_PATH] = { 0 };

	GetModuleFileNameW(0, path, _countof(path));
	WCHAR * temp = wcsrchr(path, L'\\');
	*temp = 0;

	wcscpy(iniPath, path);
	wcscat(iniPath, L"\\NtApiCollection.ini");

	wcscat(symbolPath, L"SRV*");
	wcscat(symbolPath, path);
	wcscat(symbolPath, L"*http://msdl.microsoft.com/download/symbols");


#ifdef _WIN64
	wsprintfW(OsId, L"%02X%02X%02X%02X%02X%02X_x64", (DWORD)osver.dwMajorVersion, (DWORD)osver.dwMinorVersion, (DWORD)osver.wServicePackMajor, (DWORD)osver.wServicePackMinor, (DWORD)osver.wProductType, (DWORD)si.wProcessorArchitecture);
#else
	wsprintfW(OsId, L"%02X%02X%02X%02X%02X%02X_x86", (DWORD)osver.dwMajorVersion, (DWORD)osver.dwMinorVersion, (DWORD)osver.wServicePackMajor, (DWORD)osver.wServicePackMinor, (DWORD)osver.wProductType, (DWORD)si.wProcessorArchitecture);
#endif

	printf("OS MajorVersion %d MinorVersion %d\n", (DWORD)osver.dwMajorVersion, (DWORD)osver.dwMinorVersion);

	printf("OS ID: %S\n\n", OsId);

	if (!SymInitializeW(GetCurrentProcess(), symbolPath, TRUE))
	{
		printf("SymInitialize returned error : %d\n", GetLastError());
		return 0;
	}

	HMODULE hUser = GetModuleHandleW(L"user32.dll");
	PIMAGE_DOS_HEADER pDosUser = (PIMAGE_DOS_HEADER)hUser;
	PIMAGE_NT_HEADERS pNtUser = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosUser + pDosUser->e_lfanew);

	if (pNtUser->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Wrong User NT Header\n");
		return 0;
	}
	wsprintfW(temp, L"%08X", pNtUser->OptionalHeader.AddressOfEntryPoint);
	wcscat(OsId, L"_");
	wcscat(OsId, temp);

	if (hUser)
	{
		printf("User32 Base %p\n", hUser);

		for (int i = 0; i < _countof(functionNames); i++)
		{
			functionVA[i] = GetFunctionAddressPDB(hUser, functionNames[i]);
			if (functionVA[i])
			{
				functionRVA[i] = (DWORD)(functionVA[i] - (DWORD_PTR)hUser);
				printf("Name %S VA %p RVA %08X\n", functionNames[i], functionVA[i], functionRVA[i]);
				WriteApiInIni(functionNames[i], functionRVA[i]);
			}
		}
	}

	SymCleanup(GetCurrentProcess());

	printf("\nDone!\n");

	getchar();
	return 0;
}