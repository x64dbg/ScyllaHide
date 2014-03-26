#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include "DynamicMapping.h"

#include "..\HookLibrary\HookMain.h"




DWORD GetProcessIdByName(const WCHAR * processName);
void startInjection(DWORD targetPid, const WCHAR * dllPath);
DWORD SetDebugPrivileges();
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);

void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };

int wmain(int argc, wchar_t* argv[])
{
	DWORD targetPid = 0;
	WCHAR * dllPath = 0;

	SetDebugPrivileges();

	if (argc >= 3)
	{
		targetPid = GetProcessIdByName(argv[1]);
		dllPath = argv[2];
	}
	else
	{
		targetPid = GetProcessIdByName(L"test.exe");
#ifdef _WIN64
		dllPath = L"c:\\Users\\Admin\\documents\\visual studio 2013\\Projects\\ScyllaHook\\x64\\Release\\HookLibrary.dll";
#else
		dllPath = L"c:\\Users\\Admin\\documents\\visual studio 2013\\Projects\\ScyllaHook\\Release\\HookLibrary.dll";
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


void startInjection(DWORD targetPid, const WCHAR * dllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, targetPid);
	if (hProcess)
	{
		BYTE * dllMemory = ReadFileToMemory(dllPath);
		if (dllMemory)
		{
			LPVOID remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
			if (remoteImageBase)
			{
				FillExchangeStruct(hProcess, &DllExchangeLoader);
				DWORD initDllFuncAddressRva = GetDllFunctionAddressRVA(dllMemory, "InitDll");
				DWORD exchangeDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "DllExchange");

				if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)exchangeDataAddressRva + (DWORD_PTR)remoteImageBase), &DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE), 0))
				{
					DWORD exitCode = StartDllInitFunction(hProcess, ((DWORD_PTR)initDllFuncAddressRva + (DWORD_PTR)remoteImageBase), remoteImageBase);

					if (exitCode == HOOK_ERROR_SUCCESS)
					{
						wprintf(L"Injection successful, Imagebase %p\n", remoteImageBase);
					}
					else
					{
						wprintf(L"Injection failed, exit code %d Imagebase %p\n", exitCode, remoteImageBase);
					}
				}
				else
				{
					wprintf(L"Failed to write exchange struct\n");
				}
			}

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

	data->fLoadLibraryA = (t_LoadLibraryA)((DWORD_PTR)GetProcAddress(localKernel, "LoadLibraryA") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
	data->fGetModuleHandleA = (t_GetModuleHandleA)((DWORD_PTR)GetProcAddress(localKernel, "GetModuleHandleA") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
	data->fGetProcAddress = (t_GetProcAddress)((DWORD_PTR)GetProcAddress(localKernel, "GetProcAddress") - (DWORD_PTR)localKernel + (DWORD_PTR)data->hkernel32);
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