#define _CRT_SECURE_NO_WARNINGS
#include "ReadNtConfig.h"
#include "..\HookLibrary\HookMain.h"
#include <windows.h>

OSVERSIONINFOEXW osver = { 0 };
SYSTEM_INFO si = { 0 };

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern WCHAR NtApiIniPath[MAX_PATH];

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

WCHAR text[500];

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
        MessageBoxA(0,"Wrong user32.dll IMAGE_NT_SIGNATURE", "ERROR", MB_ICONERROR);
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
        wsprintfW(text, L"NtUser* API Addresses missing!\r\nSection: %s\r\nFile: %s\r\n\r\nPlease read the documentation to fix this problem! https://bitbucket.org/NtQuery/scyllahide/downloads/ScyllaHide.pdf", OsId, NtApiIniPath);
        MessageBoxW(0, text, L"ERROR", MB_ICONERROR);
    }
}
