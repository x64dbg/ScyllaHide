#include <stdio.h>
#include "IniSettings.h"
#include "..\ScyllaHideOlly2Plugin\Injector.h"

#define INI_APPNAME L"SCYLLA_HIDE"

extern struct HideOptions pHideOptions;
extern WCHAR ScyllaHideIniPath[MAX_PATH];

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

bool WriteIniSettingsInt(const WCHAR * settingName, int settingValue, const WCHAR* inifile)
{
    wchar_t buf[256];
    swprintf_s(buf, L"%d", settingValue);

    return WriteIniSettings(settingName, buf, inifile);
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
    WriteIniSettings(L"NtUserQueryWindowHook", L"1", iniFile);
    WriteIniSettings(L"NtYieldExecutionHook", L"1", iniFile);
    WriteIniSettings(L"OutputDebugStringHook", L"1", iniFile);
    WriteIniSettings(L"PebBeingDebugged", L"1", iniFile);
    WriteIniSettings(L"PebHeapFlags", L"1", iniFile);
    WriteIniSettings(L"PebNtGlobalFlag", L"1", iniFile);
    WriteIniSettings(L"PebStartupInfo", L"1", iniFile);
    WriteIniSettings(L"NtCreateThreadExHook", L"1", iniFile);
    WriteIniSettings(L"DLLStealth", L"1", iniFile);
    WriteIniSettings(L"DLLNormal", L"1", iniFile);
    WriteIniSettings(L"DLLUnload", L"1", iniFile);
    WriteIniSettings(L"PreventThreadCreation", L"0", iniFile); //special hook disabled by default
}

void ReadSettings()
{
    ReadSettingsFromIni(ScyllaHideIniPath);
}

void ReadSettingsFromIni(const WCHAR * iniFile)
{
    pHideOptions.BlockInput = ReadIniSettingsInt(L"BlockInputHook", iniFile);
    pHideOptions.GetTickCount = ReadIniSettingsInt(L"GetTickCountHook", iniFile);
    pHideOptions.KiUserExceptionDispatcher = ReadIniSettingsInt(L"KiUserExceptionDispatcherHook", iniFile);
    pHideOptions.NtClose = ReadIniSettingsInt(L"NtCloseHook", iniFile);
    pHideOptions.NtContinue = ReadIniSettingsInt(L"NtContinueHook", iniFile);
    pHideOptions.NtGetContextThread = ReadIniSettingsInt(L"NtGetContextThreadHook", iniFile);
    pHideOptions.NtQueryInformationProcess = ReadIniSettingsInt(L"NtQueryInformationProcessHook", iniFile);
    pHideOptions.NtQueryObject = ReadIniSettingsInt(L"NtQueryObjectHook", iniFile);
    pHideOptions.NtQuerySystemInformation = ReadIniSettingsInt(L"NtQuerySystemInformationHook", iniFile);
    pHideOptions.NtSetContextThread = ReadIniSettingsInt(L"NtSetContextThreadHook", iniFile);
    pHideOptions.NtSetDebugFilterState = ReadIniSettingsInt(L"NtSetDebugFilterStateHook", iniFile);
    pHideOptions.NtSetInformationThread = ReadIniSettingsInt(L"NtSetInformationThreadHook", iniFile);
    pHideOptions.NtUserBuildHwndList = ReadIniSettingsInt(L"NtUserBuildHwndListHook", iniFile);
    pHideOptions.NtUserFindWindowEx = ReadIniSettingsInt(L"NtUserFindWindowExHook", iniFile);
    pHideOptions.NtUserQueryWindow = ReadIniSettingsInt(L"NtUserQueryWindowHook", iniFile);
    pHideOptions.NtYieldExecution = ReadIniSettingsInt(L"NtYieldExecutionHook", iniFile);
    pHideOptions.OutputDebugStringA = ReadIniSettingsInt(L"OutputDebugStringHook", iniFile);
    pHideOptions.PEBBeingDebugged = ReadIniSettingsInt(L"PebBeingDebugged", iniFile);
    pHideOptions.PEBHeapFlags = ReadIniSettingsInt(L"PebHeapFlags", iniFile);
    pHideOptions.PEBNtGlobalFlag = ReadIniSettingsInt(L"PebNtGlobalFlag", iniFile);
    pHideOptions.PEBStartupInfo = ReadIniSettingsInt(L"PebStartupInfo", iniFile);
    pHideOptions.NtCreateThreadEx = ReadIniSettingsInt(L"NtCreateThreadExHook", iniFile);
    pHideOptions.preventThreadCreation = ReadIniSettingsInt(L"PreventThreadCreation", iniFile);
    pHideOptions.DLLNormal = ReadIniSettingsInt(L"DLLNormal", iniFile);
    pHideOptions.DLLStealth = ReadIniSettingsInt(L"DLLStealth", iniFile);
    pHideOptions.DLLUnload = ReadIniSettingsInt(L"DLLUnload", iniFile);
}

void SaveSettings()
{
    SaveSettingsToIni(ScyllaHideIniPath);
}

void SaveSettingsToIni(const WCHAR * iniFile)
{
    WriteIniSettingsInt(L"BlockInputHook", pHideOptions.BlockInput, iniFile);
    WriteIniSettingsInt(L"GetTickCountHook", pHideOptions.GetTickCount, iniFile);
    WriteIniSettingsInt(L"KiUserExceptionDispatcherHook", pHideOptions.KiUserExceptionDispatcher, iniFile);
    WriteIniSettingsInt(L"NtCloseHook", pHideOptions.NtClose, iniFile);
    WriteIniSettingsInt(L"NtContinueHook", pHideOptions.NtContinue, iniFile);
    WriteIniSettingsInt(L"NtGetContextThreadHook", pHideOptions.NtGetContextThread, iniFile);
    WriteIniSettingsInt(L"NtQueryInformationProcessHook", pHideOptions.NtQueryInformationProcess, iniFile);
    WriteIniSettingsInt(L"NtQueryObjectHook", pHideOptions.NtQueryObject, iniFile);
    WriteIniSettingsInt(L"NtQuerySystemInformationHook", pHideOptions.NtQuerySystemInformation, iniFile);
    WriteIniSettingsInt(L"NtSetContextThreadHook", pHideOptions.NtSetContextThread, iniFile);
    WriteIniSettingsInt(L"NtSetDebugFilterStateHook", pHideOptions.NtSetDebugFilterState, iniFile);
    WriteIniSettingsInt(L"NtSetInformationThreadHook", pHideOptions.NtSetInformationThread, iniFile);
    WriteIniSettingsInt(L"NtUserBuildHwndListHook", pHideOptions.NtUserBuildHwndList, iniFile);
    WriteIniSettingsInt(L"NtUserFindWindowExHook", pHideOptions.NtUserFindWindowEx, iniFile);
    WriteIniSettingsInt(L"NtUserQueryWindowHook", pHideOptions.NtUserQueryWindow, iniFile);
    WriteIniSettingsInt(L"NtYieldExecutionHook", pHideOptions.NtYieldExecution, iniFile);
    WriteIniSettingsInt(L"OutputDebugStringHook", pHideOptions.OutputDebugStringA, iniFile);
    WriteIniSettingsInt(L"PebBeingDebugged", pHideOptions.PEBBeingDebugged, iniFile);
    WriteIniSettingsInt(L"PebHeapFlags", pHideOptions.PEBHeapFlags, iniFile);
    WriteIniSettingsInt(L"PebNtGlobalFlag", pHideOptions.PEBNtGlobalFlag, iniFile);
    WriteIniSettingsInt(L"PebStartupInfo", pHideOptions.PEBStartupInfo, iniFile);
    WriteIniSettingsInt(L"NtCreateThreadExHook", pHideOptions.NtCreateThreadEx, iniFile);
    WriteIniSettingsInt(L"PreventThreadCreation", pHideOptions.preventThreadCreation, iniFile);
    WriteIniSettingsInt(L"DLLStealth", pHideOptions.DLLNormal, iniFile);
    WriteIniSettingsInt(L"DLLNormal", pHideOptions.DLLStealth, iniFile);
    WriteIniSettingsInt(L"DLLUnload", pHideOptions.DLLUnload, iniFile);
}