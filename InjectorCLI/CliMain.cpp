#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>
#include "DynamicMapping.h"
#include <Shlwapi.h>
#include "..\HookLibrary\HookMain.h"
#include "RemoteHook.h"
#include "RemotePebHider.h"
#include "ApplyHooking.h"

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
        WriteFile(hFile, section, (DWORD)((wcslen(section) + 1)*(sizeof(WCHAR))), &NumberOfBytesWritten, NULL);
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
    WriteIniSettings(L"BlockInputHook", L"1", iniFile);
    WriteIniSettings(L"GetTickCountHook", L"1", iniFile);
    WriteIniSettings(L"KiUserExceptionDispatcherHook", L"1", iniFile);
    WriteIniSettings(L"NtCloseHook", L"1", iniFile);
    WriteIniSettings(L"NtContinueHook", L"1", iniFile);
    WriteIniSettings(L"NtGetContextThreadHook", L"1", iniFile);
    WriteIniSettings(L"NtQueryInformationProcessHook", L"1", iniFile);
    WriteIniSettings(L"NtQueryObjectHook", L"1", iniFile);
    WriteIniSettings(L"NtQuerySystemInformationHook", L"1", iniFile);
    WriteIniSettings(L"NtSetContextThreadHook", L"1", iniFile);
    WriteIniSettings(L"NtSetDebugFilterStateHook", L"1", iniFile);
    WriteIniSettings(L"NtSetInformationThreadHook", L"1", iniFile);
    WriteIniSettings(L"NtUserBuildHwndListHook", L"1", iniFile);
    WriteIniSettings(L"NtUserFindWindowExHook", L"1", iniFile);
    WriteIniSettings(L"NtYieldExecutionHook", L"1", iniFile);
    WriteIniSettings(L"OutputDebugStringHook", L"1", iniFile);
    WriteIniSettings(L"PebBeingDebugged", L"1", iniFile);
    WriteIniSettings(L"PebHeapFlags", L"1", iniFile);
    WriteIniSettings(L"PebNtGlobalFlag", L"1", iniFile);
    WriteIniSettings(L"PebStartupInfo", L"1", iniFile);
    WriteIniSettings(L"CreateThreadHook", L"1", iniFile);

    WriteIniSettings(L"EnableProtectProcessId", L"1", iniFile);
}

void ReadSettings()
{

    ReadSettingsFromIni(ScyllaHideIniPath);
}

void ReadSettingsFromIni(const WCHAR * iniFile)
{
    DllExchangeLoader.EnableBlockInputHook = ReadIniSettingsInt(L"BlockInputHook", iniFile);
    DllExchangeLoader.EnableGetTickCountHook = ReadIniSettingsInt(L"GetTickCountHook", iniFile);
    DllExchangeLoader.EnableKiUserExceptionDispatcherHook = ReadIniSettingsInt(L"KiUserExceptionDispatcherHook", iniFile);
    DllExchangeLoader.EnableNtCloseHook = ReadIniSettingsInt(L"NtCloseHook", iniFile);
    DllExchangeLoader.EnableNtContinueHook = ReadIniSettingsInt(L"NtContinueHook", iniFile);
    DllExchangeLoader.EnableNtGetContextThreadHook = ReadIniSettingsInt(L"NtGetContextThreadHook", iniFile);
    DllExchangeLoader.EnableNtQueryInformationProcessHook = ReadIniSettingsInt(L"NtQueryInformationProcessHook", iniFile);
    DllExchangeLoader.EnableNtQueryObjectHook = ReadIniSettingsInt(L"NtQueryObjectHook", iniFile);
    DllExchangeLoader.EnableNtQuerySystemInformationHook = ReadIniSettingsInt(L"NtQuerySystemInformationHook", iniFile);
    DllExchangeLoader.EnableNtSetContextThreadHook = ReadIniSettingsInt(L"NtSetContextThreadHook", iniFile);
    DllExchangeLoader.EnableNtSetDebugFilterStateHook = ReadIniSettingsInt(L"NtSetDebugFilterStateHook", iniFile);
    DllExchangeLoader.EnableNtSetInformationThreadHook = ReadIniSettingsInt(L"NtSetInformationThreadHook", iniFile);
    DllExchangeLoader.EnableNtUserBuildHwndListHook = ReadIniSettingsInt(L"NtUserBuildHwndListHook", iniFile);
    DllExchangeLoader.EnableNtUserFindWindowExHook = ReadIniSettingsInt(L"NtUserFindWindowExHook", iniFile);
    DllExchangeLoader.EnableNtYieldExecutionHook = ReadIniSettingsInt(L"NtYieldExecutionHook", iniFile);
    DllExchangeLoader.EnableOutputDebugStringHook = ReadIniSettingsInt(L"OutputDebugStringHook", iniFile);
    DllExchangeLoader.EnablePebBeingDebugged = ReadIniSettingsInt(L"PebBeingDebugged", iniFile);
    DllExchangeLoader.EnablePebHeapFlags = ReadIniSettingsInt(L"PebHeapFlags", iniFile);
    DllExchangeLoader.EnablePebNtGlobalFlag = ReadIniSettingsInt(L"PebNtGlobalFlag", iniFile);
    DllExchangeLoader.EnablePebStartupInfo = ReadIniSettingsInt(L"PebStartupInfo", iniFile);
    DllExchangeLoader.EnableCreateThreadHook = ReadIniSettingsInt(L"CreateThreadHook", iniFile);

    DllExchangeLoader.EnableProtectProcessId = ReadIniSettingsInt(L"EnableProtectProcessId", iniFile);
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