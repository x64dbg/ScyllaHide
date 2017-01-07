#include <Windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>

#include "DynamicMapping.h"
#include "..\HookLibrary\HookMain.h"
#include "RemoteHook.h"
#include "RemotePebHider.h"
#include "ApplyHooking.h"
#include "ReadNtConfig.h"

const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

scl::Settings g_settings;

void ChangeBadWindowText();
void ReadSettings();
DWORD GetProcessIdByName(const WCHAR * processName);
void startInjection(DWORD targetPid, const WCHAR * dllPath);
bool SetDebugPrivileges();
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory);
bool StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);

HOOK_DLL_EXCHANGE DllExchangeLoader = { 0 };

WCHAR NtApiIniPath[MAX_PATH] = { 0 };
WCHAR ScyllaHideIniPath[MAX_PATH] = { 0 };

#define PREFIX_PATH L"C:\\Users\\Admin\\Documents\\Visual Studio 2010\\Projects\\ScyllaHide"

int wmain(int argc, wchar_t* argv[])
{
    DWORD targetPid = 0;
    WCHAR * dllPath = 0;

    GetModuleFileNameW(0, NtApiIniPath, _countof(NtApiIniPath));

    WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
    temp++;
    *temp = 0;
    wcscpy(ScyllaHideIniPath, NtApiIniPath);
    wcscat(ScyllaHideIniPath, scl::Settings::kFileName);
    wcscat(NtApiIniPath, NtApiIniFilename);

    ReadNtApiInformation(NtApiIniPath, &DllExchangeLoader);
    SetDebugPrivileges();
    //ChangeBadWindowText();
    g_settings.Load(ScyllaHideIniPath);
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
        dllPath = PREFIX_PATH L"\\Release\\HookLibraryx64.dll";
#else
        targetPid = GetProcessIdByName(L"ThemidaTest.exe");//GetProcessIdByName(L"ThemidaTest.exe");//GetProcessIdByName(L"VMProtect.vmp.exe");//GetProcessIdByName(L"scylla_x86.exe");
        dllPath = PREFIX_PATH L"\\Release\\HookLibraryx86.dll";
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



bool StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    DllExchangeLoader.dwProtectedProcessId = 0; //for olly plugins
    DllExchangeLoader.EnableProtectProcessId = FALSE;

    DWORD enableEverything = PEB_PATCH_BeingDebugged|PEB_PATCH_HeapFlags|PEB_PATCH_NtGlobalFlag|PEB_PATCH_StartUpInfo;
    ApplyPEBPatch(&DllExchangeLoader, hProcess, enableEverything);

    return ApplyHook(&DllExchangeLoader, hProcess, dllMemory, imageBase);
}

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory)
{
    LPVOID remoteImageBase = MapModuleToProcess(hProcess, dllMemory);
    if (remoteImageBase)
    {
        FillExchangeStruct(hProcess, &DllExchangeLoader);
        //DWORD initDllFuncAddressRva = GetDllFunctionAddressRVA(dllMemory, "InitDll");
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

bool SetDebugPrivileges()
{
    TOKEN_PRIVILEGES Debug_Privileges;
	bool retVal = false;

    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
	{
		HANDLE hToken = 0;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			Debug_Privileges.PrivilegeCount = 1;

			retVal = AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL) != FALSE;

			CloseHandle(hToken);
		}
	}

    return retVal;
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

void ReadSettings()
{
    DllExchangeLoader.EnableBlockInputHook = g_settings.opts().BlockInput;
    DllExchangeLoader.EnableGetLocalTimeHook = g_settings.opts().GetLocalTime;
    DllExchangeLoader.EnableGetSystemTimeHook = g_settings.opts().GetSystemTime;
    DllExchangeLoader.EnableGetTickCount64Hook = g_settings.opts().GetTickCount64;
    DllExchangeLoader.EnableGetTickCountHook = g_settings.opts().GetTickCount;
    DllExchangeLoader.EnableKiUserExceptionDispatcherHook = g_settings.opts().KiUserExceptionDispatcher;
    DllExchangeLoader.EnableNtCloseHook = g_settings.opts().NtClose;
    DllExchangeLoader.EnableNtContinueHook = g_settings.opts().NtContinue;
    DllExchangeLoader.EnableNtCreateThreadExHook = g_settings.opts().NtCreateThreadEx;
    DllExchangeLoader.EnableNtGetContextThreadHook = g_settings.opts().NtGetContextThread;
    DllExchangeLoader.EnableNtQueryInformationProcessHook = g_settings.opts().NtQueryInformationProcess;
    DllExchangeLoader.EnableNtQueryObjectHook = g_settings.opts().NtQueryObject;
    DllExchangeLoader.EnableNtQueryPerformanceCounterHook = g_settings.opts().NtQueryPerformanceCounter;
    DllExchangeLoader.EnableNtQuerySystemInformationHook = g_settings.opts().NtQuerySystemInformation;
    DllExchangeLoader.EnableNtQuerySystemTimeHook = g_settings.opts().NtQuerySystemTime;
    DllExchangeLoader.EnableNtSetContextThreadHook = g_settings.opts().NtSetContextThread;
    DllExchangeLoader.EnableNtSetDebugFilterStateHook = g_settings.opts().NtSetDebugFilterState;
    DllExchangeLoader.EnableNtSetInformationThreadHook = g_settings.opts().NtSetInformationThread;
    DllExchangeLoader.EnableNtUserBuildHwndListHook = g_settings.opts().NtUserBuildHwndList;
    DllExchangeLoader.EnableNtUserFindWindowExHook = g_settings.opts().NtUserFindWindowEx;
    DllExchangeLoader.EnableNtUserQueryWindowHook = g_settings.opts().NtUserQueryWindow;
    DllExchangeLoader.EnableNtYieldExecutionHook = g_settings.opts().NtYieldExecution;
    DllExchangeLoader.EnableOutputDebugStringHook = g_settings.opts().OutputDebugStringA;
    DllExchangeLoader.EnablePebBeingDebugged = g_settings.opts().PEBBeingDebugged;
    DllExchangeLoader.EnablePebHeapFlags = g_settings.opts().PEBHeapFlags;
    DllExchangeLoader.EnablePebNtGlobalFlag = g_settings.opts().PEBNtGlobalFlag;
    DllExchangeLoader.EnablePebStartupInfo = g_settings.opts().PEBStartupInfo;
    DllExchangeLoader.EnablePreventThreadCreation = g_settings.opts().preventThreadCreation;
    DllExchangeLoader.EnableProtectProcessId = g_settings.opts().protectProcessId;
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
