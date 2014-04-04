#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include "DynamicMapping.h"
#include <Shlwapi.h>
#include "..\HookLibrary\HookMain.h"
#include "RemoteHook.h"
#include "RemotePebHider.h"

const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
#define INI_APPNAME L"SCYLLA_HIDE"

void ChangeBadWindowText();
void CreateSettings();
void ReadSettings();
void ReadNtApiInformation();
void ReadSettingsFromIni(const WCHAR * iniFile);
void CreateDummyUnicodeFile(const WCHAR * file);
bool WriteIniSettings(const WCHAR * settingName, const WCHAR * settingValue, const WCHAR* inifile);
void CreateDefaultSettings(const WCHAR * iniFile);
DWORD GetProcessIdByName(const WCHAR * processName);
void startInjection(DWORD targetPid, const WCHAR * dllPath);
DWORD SetDebugPrivileges();
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory);
void StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };

WCHAR NtApiIniPath[MAX_PATH] = { 0 };
WCHAR ScyllaHideIniPath[MAX_PATH] = { 0 };

int wmain(int argc, wchar_t* argv[])
{
	DWORD targetPid = 0;
	WCHAR * dllPath = 0;

	GetModuleFileNameW(0, NtApiIniPath, _countof(NtApiIniPath));

	WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
	temp++;
	*temp = 0;
	wcscpy(ScyllaHideIniPath, NtApiIniPath);
	wcscat(ScyllaHideIniPath, ScyllaHideIniFilename);
	wcscat(NtApiIniPath, NtApiIniFilename);

	ReadNtApiInformation();
	SetDebugPrivileges();
	//ChangeBadWindowText();
	CreateSettings();
	ReadSettings();

	if (argc >= 3)
	{
		targetPid = GetProcessIdByName(argv[1]);
		dllPath = argv[2];
	}
	else
	{

#ifdef _WIN64
		targetPid = GetProcessIdByName(L"scylla_x64.exe");//scylla_x64
		dllPath = L"c:\\Users\\Admin\\documents\\visual studio 2013\\Projects\\ScyllaHide\\x64\\Release\\HookLibrary.dll";
#else
		targetPid = GetProcessIdByName(L"VMProtect.vmp.exe");//GetProcessIdByName(L"scylla_x86.exe");
		dllPath = L"c:\\Users\\Admin\\documents\\visual studio 2013\\Projects\\ScyllaHide\\Release\\HookLibrary.dll";
#endif
	}

	if (targetPid && dllPath)
	{
		wprintf(L"\nPID\t: %d 0x%X\nDLL Path: %s\n\n", targetPid, targetPid, dllPath);
		startInjection(targetPid, dllPath);
	}
	else
	{
		wprintf(L"Usage: %s <process name> <dll path>", argv[0]);
	}

	getchar();
	return 0;
}

#define HOOK(name) DllExchangeLoader.d##name = (t_##name)DetourCreateRemote(hProcess,_##name, Hooked##name, true)
#define HOOK_NOTRAMP(name) DetourCreateRemote(hProcess,_##name, Hooked##name, false)

void StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
	HMODULE hUser = GetModuleHandleW(L"kernel32.dll");
	HMODULE hKernelbase = GetModuleHandleW(L"kernelbase.dll");

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

	if (hUser)
	{
		t_NtUserFindWindowEx _NtUserFindWindowEx = 0;
		if (DllExchangeLoader.NtUserFindWindowExRVA)
		{
			_NtUserFindWindowEx = (t_NtUserFindWindowEx)((DWORD_PTR)hUser + DllExchangeLoader.NtUserFindWindowExRVA);
		}
		t_BlockInput _BlockInput = (t_BlockInput)GetProcAddress(hUser, "BlockInput");

		if (DllExchangeLoader.EnableBlockInputHook == TRUE) HOOK(BlockInput);
		if (DllExchangeLoader.EnableNtUserFindWindowExHook == TRUE && _NtUserFindWindowEx != 0) HOOK(NtUserFindWindowEx);
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
	//if (DllExchangeLoader.EnableKiUserExceptionDispatcherHook == TRUE) HOOK(KiUserExceptionDispatcher);
	if (DllExchangeLoader.EnableNtContinueHook == TRUE) HOOK(NtContinue);
	if (DllExchangeLoader.EnableNtCloseHook == TRUE) HOOK(NtClose);

	if (DllExchangeLoader.EnableGetTickCountHook == TRUE) HOOK(GetTickCount);

	if (DllExchangeLoader.EnableOutputDebugStringHook == TRUE) HOOK_NOTRAMP(OutputDebugStringA);
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


			//if (exitCode == HOOK_ERROR_SUCCESS)

			//{
			wprintf(L"Injection successful, Imagebase %p\n", remoteImageBase);
			//}
			//else
			//{
			//	wprintf(L"Injection failed, exit code %d 0x%X Imagebase %p\n", exitCode, exitCode, remoteImageBase);
			//}
		}
		else
		{
			wprintf(L"Failed to write exchange struct\n");
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
			wprintf(L"Cannot read file to memory %s\n", dllPath);
		}
		CloseHandle(hProcess);
	}
	else
	{
		wprintf(L"Cannot open process handle %d\n", targetPid);
	}
}

void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data)
{
	HMODULE localKernel = GetModuleHandleW(L"kernel32.dll");
	HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");

	data->hNtdll = GetModuleBaseRemote(hProcess, L"ntdll.dll");
	data->hkernel32 = GetModuleBaseRemote(hProcess, L"kernel32.dll");
	data->hkernelBase = GetModuleBaseRemote(hProcess, L"kernelbase.dll");
	data->hUser32 = GetModuleBaseRemote(hProcess, L"user32.dll");

	//data->fLoadLibraryA = (t_LoadLibraryA)((DWORD_PTR)GetProcAddress(localKernel, "LoadLibraryA") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
	//data->fGetModuleHandleA = (t_GetModuleHandleA)((DWORD_PTR)GetProcAddress(localKernel, "GetModuleHandleA") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
	//data->fGetProcAddress = (t_GetProcAddress)((DWORD_PTR)GetProcAddress(localKernel, "GetProcAddress") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
	//data->fLdrGetProcedureAddress = (t_LdrGetProcedureAddress)((DWORD_PTR)GetProcAddress(localNtdll, "LdrGetProcedureAddress") - (DWORD_PTR)localNtdll + (DWORD_PTR)data->hNtdll);

	//data->EnablePebHiding = TRUE;

	//data->EnableBlockInputHook = TRUE;
	//data->EnableGetTickCountHook = TRUE;
	//data->EnableOutputDebugStringHook = TRUE;

	//data->EnableNtSetInformationThreadHook = TRUE;
	//data->EnableNtQueryInformationProcessHook = TRUE;
	//data->EnableNtQuerySystemInformationHook = TRUE;
	//data->EnableNtQueryObjectHook = TRUE;
	//data->EnableNtYieldExecutionHook = TRUE;

	//data->EnableNtGetContextThreadHook = TRUE;
	//data->EnableNtSetContextThreadHook = TRUE;
	//data->EnableNtContinueHook = TRUE;
	//data->EnableKiUserExceptionDispatcherHook = TRUE;
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

DWORD SetDebugPrivileges()
{
	DWORD err = 0;
	TOKEN_PRIVILEGES Debug_Privileges;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid)) return GetLastError();

	HANDLE hToken = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		err = GetLastError();
		if (hToken) CloseHandle(hToken);
		return err;
	}

	Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	Debug_Privileges.PrivilegeCount = 1;

	if (!AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, NULL, NULL))
	{
		err = GetLastError();
		if (hToken) CloseHandle(hToken);
	}

	return err;
}

DWORD GetProcessIdByName(const WCHAR * processName)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		wprintf(L"Error getting first process\n");
		CloseHandle(hProcessSnap);
		return 0;
	}

	DWORD pid = 0;

	do
	{
		if (!_wcsicmp(pe32.szExeFile, processName))
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return pid;
}

BOOL FileExists(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void CreateDummyUnicodeFile(const WCHAR * file)
{
	//http://www.codeproject.com/Articles/9071/Using-Unicode-in-INI-files

	if (!FileExists(file))
	{
		const WCHAR section[] = L"[" INI_APPNAME L"]\r\n";
		// UTF16-LE BOM(FFFE)
		WORD wBOM = 0xFEFF;
		DWORD NumberOfBytesWritten;

		HANDLE hFile = CreateFile(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, NULL);
		WriteFile(hFile, section, (wcslen(section) + 1)*(sizeof(WCHAR)), &NumberOfBytesWritten, NULL);
		CloseHandle(hFile);
	}
}

bool WriteIniSettings(const WCHAR * settingName, const WCHAR * settingValue, const WCHAR* inifile)
{
	CreateDummyUnicodeFile(inifile);

	if (!WritePrivateProfileStringW(INI_APPNAME, settingName, settingValue, inifile))
	{
		printf("WritePrivateProfileStringW error %d\n", GetLastError());
		return false;
	}

	return true;
}

int ReadIniSettingsInt(const WCHAR * settingName, const WCHAR* inifile)
{
	return GetPrivateProfileIntW(INI_APPNAME, settingName, 0, inifile);
}

void CreateSettings()
{
	if (!FileExists(ScyllaHideIniPath))
	{
		CreateDefaultSettings(ScyllaHideIniPath);
	}
}

void CreateDefaultSettings(const WCHAR * iniFile)
{
	WriteIniSettings(L"PebHiding", L"1", iniFile);

	WriteIniSettings(L"BlockInputHook", L"1", iniFile);
	WriteIniSettings(L"GetTickCountHook", L"1", iniFile);
	WriteIniSettings(L"OutputDebugStringHook", L"1", iniFile);

	WriteIniSettings(L"NtSetInformationThreadHook", L"1", iniFile);
	WriteIniSettings(L"NtQueryInformationProcessHook", L"1", iniFile);
	WriteIniSettings(L"NtQuerySystemInformationHook", L"1", iniFile);
	WriteIniSettings(L"NtQueryObjectHook", L"1", iniFile);
	WriteIniSettings(L"NtYieldExecutionHook", L"1", iniFile);

	WriteIniSettings(L"NtGetContextThreadHook", L"1", iniFile);
	WriteIniSettings(L"NtSetContextThreadHook", L"1", iniFile);
	WriteIniSettings(L"NtContinueHook", L"1", iniFile);
	WriteIniSettings(L"KiUserExceptionDispatcherHook", L"1", iniFile);
}

void ReadSettings()
{

	ReadSettingsFromIni(ScyllaHideIniPath);
}

void ReadSettingsFromIni(const WCHAR * iniFile)
{

	DllExchangeLoader.EnablePebHiding = ReadIniSettingsInt(L"PebHiding", iniFile);

	DllExchangeLoader.EnableBlockInputHook = ReadIniSettingsInt(L"BlockInputHook", iniFile);
	DllExchangeLoader.EnableGetTickCountHook = ReadIniSettingsInt(L"GetTickCountHook", iniFile);
	DllExchangeLoader.EnableOutputDebugStringHook = ReadIniSettingsInt(L"OutputDebugStringHook", iniFile);

	DllExchangeLoader.EnableNtSetInformationThreadHook = ReadIniSettingsInt(L"NtSetInformationThreadHook", iniFile);
	DllExchangeLoader.EnableNtQueryInformationProcessHook = ReadIniSettingsInt(L"NtQueryInformationProcessHook", iniFile);
	DllExchangeLoader.EnableNtQuerySystemInformationHook = ReadIniSettingsInt(L"NtQuerySystemInformationHook", iniFile);
	DllExchangeLoader.EnableNtQueryObjectHook = ReadIniSettingsInt(L"NtQueryObjectHook", iniFile);
	DllExchangeLoader.EnableNtYieldExecutionHook = ReadIniSettingsInt(L"NtYieldExecutionHook", iniFile);

	DllExchangeLoader.EnableNtGetContextThreadHook = ReadIniSettingsInt(L"NtGetContextThreadHook", iniFile);
	DllExchangeLoader.EnableNtSetContextThreadHook = ReadIniSettingsInt(L"NtSetContextThreadHook", iniFile);
	DllExchangeLoader.EnableNtContinueHook = ReadIniSettingsInt(L"NtContinueHook", iniFile);
	DllExchangeLoader.EnableKiUserExceptionDispatcherHook = ReadIniSettingsInt(L"KiUserExceptionDispatcherHook", iniFile);
}

OSVERSIONINFOEXW osver = { 0 };
SYSTEM_INFO si = { 0 };

void QueryOsInfo()
{
	typedef void (WINAPI *t_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
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
}

DWORD ReadApiFromIni(const WCHAR * name, const WCHAR * section) //rva
{
	WCHAR buf[100] = { 0 };
	if (GetPrivateProfileStringW(section, name, L"0", buf, _countof(buf), NtApiIniPath) > 0)
	{
		return wcstoul(buf, 0, 16);
	}

	return 0;
}


void ReadNtApiInformation()
{
	WCHAR OsId[300] = { 0 };
	WCHAR temp[50] = { 0 };
	QueryOsInfo();
#ifdef _WIN64
	wsprintfW(OsId, L"%02X%02X%02X%02X%02X%02X_x64", (DWORD)osver.dwMajorVersion, (DWORD)osver.dwMinorVersion, (DWORD)osver.wServicePackMajor, (DWORD)osver.wServicePackMinor, (DWORD)osver.wProductType, (DWORD)si.wProcessorArchitecture);
#else
	wsprintfW(OsId, L"%02X%02X%02X%02X%02X%02X_x86", (DWORD)osver.dwMajorVersion, (DWORD)osver.dwMinorVersion, (DWORD)osver.wServicePackMajor, (DWORD)osver.wServicePackMinor, (DWORD)osver.wProductType, (DWORD)si.wProcessorArchitecture);
#endif
	HMODULE hUser = GetModuleHandleW(L"user32.dll");
	PIMAGE_DOS_HEADER pDosUser = (PIMAGE_DOS_HEADER)hUser;
	PIMAGE_NT_HEADERS pNtUser = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosUser + pDosUser->e_lfanew);

	if (pNtUser->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Wrong User NT Header\n");
		return;
	}
	wsprintfW(temp, L"%08X", pNtUser->OptionalHeader.AddressOfEntryPoint);
	wcscat(OsId, L"_");
	wcscat(OsId, temp);

	DllExchangeLoader.NtUserBuildHwndListRVA = ReadApiFromIni(L"NtUserBuildHwndList", OsId);
	DllExchangeLoader.NtUserFindWindowExRVA = ReadApiFromIni(L"NtUserFindWindowEx", OsId);
	DllExchangeLoader.NtUserQueryWindowRVA = ReadApiFromIni(L"NtUserQueryWindow", OsId);

	if (!DllExchangeLoader.NtUserBuildHwndListRVA || !DllExchangeLoader.NtUserFindWindowExRVA || !DllExchangeLoader.NtUserQueryWindowRVA)
	{
		printf("NT APIs missing %S %S\n", OsId, NtApiIniPath);
	}
}



//BOOL CALLBACK MyEnumChildProc(
//	_In_  HWND hwnd,
//	_In_  LPARAM lParam
//	)
//{
//	WCHAR windowText[1000] = { 0 };
//	WCHAR classText[1000] = { 0 };
//	if (GetWindowTextW(hwnd, windowText, _countof(windowText)) > 1)
//	{
//		GetClassName(hwnd, classText, _countof(classText));
//
//		wprintf(L"\t%s\n\t%s\n", windowText, classText);
//	}
//
//	return TRUE;
//}
//
//BOOL CALLBACK MyEnumWindowsProc(HWND hwnd,LPARAM lParam)
//{
//	WCHAR windowText[1000] = { 0 };
//	WCHAR classText[1000] = { 0 };
//	if (GetWindowTextW(hwnd, windowText, _countof(windowText)) > 1)
//	{
//		GetClassName(hwnd, classText, _countof(classText));
//
//		wprintf(L"------------------\n%s\n%s\n", windowText, classText);
//
//		if (wcsistr(windowText, L"x32_dbg"))
//		{
//
//			EnumChildWindows(hwnd, MyEnumChildProc, 0);
//
//			DWORD_PTR result;
//			SendMessageTimeoutW(hwnd, WM_SETTEXT, 0, (LPARAM)title, SMTO_ABORTIFHUNG, 1000, &result);
//
//			//LPVOID stringW = WriteStringInProcessW(hwnd, L"ficken");
//			//LPVOID stringA = WriteStringInProcessA(hwnd, "ficken");
//			//if (!SetClassLongPtrW(hwnd, (int)&((WNDCLASSEXW*)0)->lpszClassName, (LONG_PTR)stringW))
//			//{
//			//	printf("%d %d\n", (int)&((WNDCLASSEXW*)0)->lpszClassName,  GetLastError());
//			//}
//			//if (!SetClassLongPtrA(hwnd, (int)&((WNDCLASSEXA*)0)->lpszClassName, (LONG_PTR)stringA))
//			//{
//			//	printf("%d %d\n", (int)&((WNDCLASSEXA*)0)->lpszClassName, GetLastError());
//			//}
//		}
//	}
//
//	return TRUE;
//}
//void ChangeBadWindowText()
//{
//	EnumWindows(MyEnumWindowsProc, 0);
//}