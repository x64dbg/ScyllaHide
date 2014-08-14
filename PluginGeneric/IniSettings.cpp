#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "IniSettings.h"
#include "..\PluginGeneric\Injector.h"

extern struct HideOptions pHideOptions;
extern WCHAR ScyllaHideIniPath[MAX_PATH];
WCHAR ProfileNames[2048] = {0};
WCHAR CurrentProfile[MAX_SECTION_NAME] = {0};

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
        const WCHAR section[] = L"[" DEFAULT_PROFILE L"]\r\n";
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

    if (!WritePrivateProfileStringW(CurrentProfile, settingName, settingValue, inifile))
    {
        //printf("WritePrivateProfileStringW error %d\n", GetLastError());
        MessageBoxA(0, "WritePrivateProfileStringW failed", "ERROR", MB_ICONERROR);
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
    return GetPrivateProfileIntW(CurrentProfile, settingName, 0, inifile);
}

void ReadIniSettings(const WCHAR * settingName, const WCHAR* inifile, WCHAR* buf, int bufsz)
{
    GetPrivateProfileStringW(CurrentProfile, settingName, L"", buf, bufsz, inifile);
}

void CreateSettings()
{
    if (!FileExists(ScyllaHideIniPath))
    {
        CreateDefaultSettings(ScyllaHideIniPath);
    }
}

void ReadSettings()
{
    ReadSettingsFromIni(ScyllaHideIniPath);
}

void SaveSettings()
{
    SaveSettingsToIni(ScyllaHideIniPath);
}

void CreateDefaultSettings(const WCHAR * iniFile)
{
    WriteIniSettings(L"BlockInputHook", L"1", iniFile);
    WriteIniSettings(L"DLLNormal", L"1", iniFile);
    WriteIniSettings(L"DLLStealth", L"0", iniFile);
    WriteIniSettings(L"DLLUnload", L"1", iniFile);
    WriteIniSettings(L"GetLocalTimeHook", L"1", iniFile);
    WriteIniSettings(L"GetSystemTimeHook", L"1", iniFile);
    WriteIniSettings(L"GetTickCount64Hook", L"1", iniFile);
    WriteIniSettings(L"GetTickCountHook", L"1", iniFile);
    WriteIniSettings(L"KiUserExceptionDispatcherHook", L"1", iniFile);
    WriteIniSettings(L"NtCloseHook", L"1", iniFile);
    WriteIniSettings(L"NtContinueHook", L"1", iniFile);
    WriteIniSettings(L"NtCreateThreadExHook", L"1", iniFile);
    WriteIniSettings(L"NtGetContextThreadHook", L"1", iniFile);
    WriteIniSettings(L"NtQueryInformationProcessHook", L"1", iniFile);
    WriteIniSettings(L"NtQueryObjectHook", L"1", iniFile);
    WriteIniSettings(L"NtQueryPerformanceCounterHook", L"1", iniFile);
    WriteIniSettings(L"NtQuerySystemInformationHook", L"1", iniFile);
    WriteIniSettings(L"NtQuerySystemTimeHook", L"1", iniFile);
    WriteIniSettings(L"NtSetContextThreadHook", L"1", iniFile);
    WriteIniSettings(L"NtSetDebugFilterStateHook", L"1", iniFile);
    WriteIniSettings(L"NtSetInformationThreadHook", L"1", iniFile);
    WriteIniSettings(L"NtSetInformationProcessHook", L"1", iniFile);
    WriteIniSettings(L"NtUserBuildHwndListHook", L"1", iniFile);
    WriteIniSettings(L"NtUserFindWindowExHook", L"1", iniFile);
    WriteIniSettings(L"NtUserQueryWindowHook", L"1", iniFile);
    WriteIniSettings(L"NtYieldExecutionHook", L"1", iniFile);
    WriteIniSettings(L"OutputDebugStringHook", L"1", iniFile);
    WriteIniSettings(L"PebBeingDebugged", L"1", iniFile);
    WriteIniSettings(L"PebHeapFlags", L"1", iniFile);
    WriteIniSettings(L"PebNtGlobalFlag", L"1", iniFile);
    WriteIniSettings(L"PebStartupInfo", L"1", iniFile);
    WriteIniSettings(L"PreventThreadCreation", L"0", iniFile); //special hook disabled by default
    WriteIniSettings(L"RemoveDebugPrivileges", L"1", iniFile);
    WriteIniSettings(L"KillAntiAttach", L"1", iniFile);

    //ida specific
    WriteIniSettings(L"AutostartServer", L"1", iniFile);
    WriteIniSettings(L"ServerPort", L"1337", iniFile);

    //olly1 specific
    WriteIniSettings(L"BreakOnTLS", L"1", iniFile);
    WriteIniSettings(L"FixOllyBugs", L"1", iniFile);
    WriteIniSettings(L"RemoveEPBreak", L"0", iniFile);
    WriteIniSettings(L"SkipEPOutsideCode", L"1", iniFile);
    WriteIniSettings(L"X64Fix", L"0", iniFile);
    WriteIniSettings(L"WindowTitle", L"ScyllaHide", iniFile);
    WriteIniSettings(L"advancedGoto", L"0", iniFile);
    WriteIniSettings(L"ignoreBadPEImage", L"0", iniFile);
    WriteIniSettings(L"skipCompressedDoAnalyze", L"0", iniFile);
    WriteIniSettings(L"skipCompressedDoNothing", L"0", iniFile);
    WriteIniSettings(L"skipLoadDllDoLoad", L"0", iniFile);
    WriteIniSettings(L"skipLoadDllDoNothing", L"0", iniFile);
}

void ReadSettingsFromIni(const WCHAR * iniFile)
{
    pHideOptions.BlockInput = ReadIniSettingsInt(L"BlockInputHook", iniFile);
    pHideOptions.DLLNormal = ReadIniSettingsInt(L"DLLNormal", iniFile);
    pHideOptions.DLLStealth = ReadIniSettingsInt(L"DLLStealth", iniFile);
    pHideOptions.DLLUnload = ReadIniSettingsInt(L"DLLUnload", iniFile);
    pHideOptions.GetLocalTime = ReadIniSettingsInt(L"GetLocalTimeHook", iniFile);
    pHideOptions.GetSystemTime = ReadIniSettingsInt(L"GetSystemTimeHook", iniFile);
    pHideOptions.GetTickCount = ReadIniSettingsInt(L"GetTickCountHook", iniFile);
    pHideOptions.GetTickCount64 = ReadIniSettingsInt(L"GetTickCount64Hook", iniFile);
    pHideOptions.KiUserExceptionDispatcher = ReadIniSettingsInt(L"KiUserExceptionDispatcherHook", iniFile);
    pHideOptions.NtClose = ReadIniSettingsInt(L"NtCloseHook", iniFile);
    pHideOptions.NtContinue = ReadIniSettingsInt(L"NtContinueHook", iniFile);
    pHideOptions.NtCreateThreadEx = ReadIniSettingsInt(L"NtCreateThreadExHook", iniFile);
    pHideOptions.NtGetContextThread = ReadIniSettingsInt(L"NtGetContextThreadHook", iniFile);
    pHideOptions.NtQueryInformationProcess = ReadIniSettingsInt(L"NtQueryInformationProcessHook", iniFile);
    pHideOptions.NtQueryObject = ReadIniSettingsInt(L"NtQueryObjectHook", iniFile);
    pHideOptions.NtQueryPerformanceCounter = ReadIniSettingsInt(L"NtQueryPerformanceCounterHook", iniFile);
    pHideOptions.NtQuerySystemInformation = ReadIniSettingsInt(L"NtQuerySystemInformationHook", iniFile);
    pHideOptions.NtQuerySystemTime = ReadIniSettingsInt(L"NtQuerySystemTimeHook", iniFile);
    pHideOptions.NtSetContextThread = ReadIniSettingsInt(L"NtSetContextThreadHook", iniFile);
    pHideOptions.NtSetDebugFilterState = ReadIniSettingsInt(L"NtSetDebugFilterStateHook", iniFile);
    pHideOptions.NtSetInformationThread = ReadIniSettingsInt(L"NtSetInformationThreadHook", iniFile);
    pHideOptions.NtSetInformationProcess = ReadIniSettingsInt(L"NtSetInformationProcessHook", iniFile);
    pHideOptions.NtUserBuildHwndList = ReadIniSettingsInt(L"NtUserBuildHwndListHook", iniFile);
    pHideOptions.NtUserFindWindowEx = ReadIniSettingsInt(L"NtUserFindWindowExHook", iniFile);
    pHideOptions.NtUserQueryWindow = ReadIniSettingsInt(L"NtUserQueryWindowHook", iniFile);
    pHideOptions.NtYieldExecution = ReadIniSettingsInt(L"NtYieldExecutionHook", iniFile);
    pHideOptions.OutputDebugStringA = ReadIniSettingsInt(L"OutputDebugStringHook", iniFile);
    pHideOptions.PEBBeingDebugged = ReadIniSettingsInt(L"PebBeingDebugged", iniFile);
    pHideOptions.PEBHeapFlags = ReadIniSettingsInt(L"PebHeapFlags", iniFile);
    pHideOptions.PEBNtGlobalFlag = ReadIniSettingsInt(L"PebNtGlobalFlag", iniFile);
    pHideOptions.PEBStartupInfo = ReadIniSettingsInt(L"PebStartupInfo", iniFile);
    pHideOptions.preventThreadCreation = ReadIniSettingsInt(L"PreventThreadCreation", iniFile);
    pHideOptions.removeDebugPrivileges = ReadIniSettingsInt(L"RemoveDebugPrivileges", iniFile);
    pHideOptions.killAntiAttach = ReadIniSettingsInt(L"KillAntiAttach", iniFile);

    if (pHideOptions.DLLNormal)
    {
        pHideOptions.DLLStealth = 0;
    }

    //ida specific
    ReadIniSettings(L"ServerPort", iniFile, pHideOptions.serverPort, _countof(pHideOptions.serverPort));
    pHideOptions.autostartServer = ReadIniSettingsInt(L"AutostartServer", iniFile);

    //olly1 specific
    pHideOptions.breakTLS = ReadIniSettingsInt(L"BreakOnTLS", iniFile);
    pHideOptions.fixOllyBugs = ReadIniSettingsInt(L"FixOllyBugs", iniFile);
    pHideOptions.removeEPBreak = ReadIniSettingsInt(L"RemoveEPBreak", iniFile);
    pHideOptions.skipEPOutsideCode = ReadIniSettingsInt(L"SkipEPOutsideCode", iniFile);
    pHideOptions.x64Fix = ReadIniSettingsInt(L"X64Fix", iniFile);
    pHideOptions.advancedGoto = ReadIniSettingsInt(L"advancedGoto", iniFile);
    pHideOptions.ignoreBadPEImage = ReadIniSettingsInt(L"ignoreBadPEImage", iniFile);
    pHideOptions.skipCompressedDoAnalyze = ReadIniSettingsInt(L"skipCompressedDoAnalyze", iniFile);
    pHideOptions.skipCompressedDoNothing = ReadIniSettingsInt(L"skipCompressedDoNothing", iniFile);
    pHideOptions.skipLoadDllDoLoad = ReadIniSettingsInt(L"skipLoadDllDoLoad", iniFile);
    pHideOptions.skipLoadDllDoNothing = ReadIniSettingsInt(L"skipLoadDllDoNothing", iniFile);
    ReadIniSettings(L"WindowTitle", iniFile, pHideOptions.ollyTitle, _countof(pHideOptions.ollyTitle));
}

void SaveSettingsToIni(const WCHAR * iniFile)
{
    WriteIniSettingsInt(L"BlockInputHook", pHideOptions.BlockInput, iniFile);
    WriteIniSettingsInt(L"DLLNormal", pHideOptions.DLLNormal, iniFile);
    WriteIniSettingsInt(L"DLLStealth", pHideOptions.DLLStealth, iniFile);
    WriteIniSettingsInt(L"DLLUnload", pHideOptions.DLLUnload, iniFile);
    WriteIniSettingsInt(L"GetLocalTimeHook", pHideOptions.GetLocalTime, iniFile);
    WriteIniSettingsInt(L"GetSystemTimeHook", pHideOptions.GetSystemTime, iniFile);
    WriteIniSettingsInt(L"GetTickCount64Hook", pHideOptions.GetTickCount64, iniFile);
    WriteIniSettingsInt(L"GetTickCountHook", pHideOptions.GetTickCount, iniFile);
    WriteIniSettingsInt(L"KiUserExceptionDispatcherHook", pHideOptions.KiUserExceptionDispatcher, iniFile);
    WriteIniSettingsInt(L"NtCloseHook", pHideOptions.NtClose, iniFile);
    WriteIniSettingsInt(L"NtContinueHook", pHideOptions.NtContinue, iniFile);
    WriteIniSettingsInt(L"NtCreateThreadExHook", pHideOptions.NtCreateThreadEx, iniFile);
    WriteIniSettingsInt(L"NtGetContextThreadHook", pHideOptions.NtGetContextThread, iniFile);
    WriteIniSettingsInt(L"NtQueryInformationProcessHook", pHideOptions.NtQueryInformationProcess, iniFile);
    WriteIniSettingsInt(L"NtQueryObjectHook", pHideOptions.NtQueryObject, iniFile);
    WriteIniSettingsInt(L"NtQueryPerformanceCounterHook", pHideOptions.NtQueryPerformanceCounter, iniFile);
    WriteIniSettingsInt(L"NtQuerySystemInformationHook", pHideOptions.NtQuerySystemInformation, iniFile);
    WriteIniSettingsInt(L"NtQuerySystemTimeHook", pHideOptions.NtQuerySystemTime, iniFile);
    WriteIniSettingsInt(L"NtSetContextThreadHook", pHideOptions.NtSetContextThread, iniFile);
    WriteIniSettingsInt(L"NtSetDebugFilterStateHook", pHideOptions.NtSetDebugFilterState, iniFile);
    WriteIniSettingsInt(L"NtSetInformationThreadHook", pHideOptions.NtSetInformationThread, iniFile);
    WriteIniSettingsInt(L"NtSetInformationProcessHook", pHideOptions.NtSetInformationProcess, iniFile);
    WriteIniSettingsInt(L"NtUserBuildHwndListHook", pHideOptions.NtUserBuildHwndList, iniFile);
    WriteIniSettingsInt(L"NtUserFindWindowExHook", pHideOptions.NtUserFindWindowEx, iniFile);
    WriteIniSettingsInt(L"NtUserQueryWindowHook", pHideOptions.NtUserQueryWindow, iniFile);
    WriteIniSettingsInt(L"NtYieldExecutionHook", pHideOptions.NtYieldExecution, iniFile);
    WriteIniSettingsInt(L"OutputDebugStringHook", pHideOptions.OutputDebugStringA, iniFile);
    WriteIniSettingsInt(L"PebBeingDebugged", pHideOptions.PEBBeingDebugged, iniFile);
    WriteIniSettingsInt(L"PebHeapFlags", pHideOptions.PEBHeapFlags, iniFile);
    WriteIniSettingsInt(L"PebNtGlobalFlag", pHideOptions.PEBNtGlobalFlag, iniFile);
    WriteIniSettingsInt(L"PebStartupInfo", pHideOptions.PEBStartupInfo, iniFile);
    WriteIniSettingsInt(L"PreventThreadCreation", pHideOptions.preventThreadCreation, iniFile);
    WriteIniSettingsInt(L"RemoveDebugPrivileges", pHideOptions.removeDebugPrivileges, iniFile);
    WriteIniSettingsInt(L"KillAntiAttach", pHideOptions.killAntiAttach, iniFile);

    //ida specific
    WriteIniSettingsInt(L"AutostartServer", pHideOptions.autostartServer, iniFile);
    WriteIniSettings(L"ServerPort", pHideOptions.serverPort, iniFile);

    //olly1 specific
    WriteIniSettingsInt(L"BreakOnTLS", pHideOptions.breakTLS, iniFile);
    WriteIniSettingsInt(L"FixOllyBugs", pHideOptions.fixOllyBugs, iniFile);
    WriteIniSettingsInt(L"RemoveEPBreak", pHideOptions.removeEPBreak, iniFile);
    WriteIniSettingsInt(L"SkipEPOutsideCode", pHideOptions.skipEPOutsideCode, iniFile);
    WriteIniSettingsInt(L"X64Fix", pHideOptions.x64Fix, iniFile);
    WriteIniSettings(L"WindowTitle", pHideOptions.ollyTitle, iniFile);
    WriteIniSettingsInt(L"advancedGoto", pHideOptions.advancedGoto, iniFile);
    WriteIniSettingsInt(L"ignoreBadPEImage", pHideOptions.ignoreBadPEImage, iniFile);
    WriteIniSettingsInt(L"skipCompressedDoAnalyze", pHideOptions.skipCompressedDoAnalyze, iniFile);
    WriteIniSettingsInt(L"skipCompressedDoNothing", pHideOptions.skipCompressedDoNothing, iniFile);
    WriteIniSettingsInt(L"skipLoadDllDoLoad", pHideOptions.skipLoadDllDoLoad, iniFile);
    WriteIniSettingsInt(L"skipLoadDllDoNothing", pHideOptions.skipLoadDllDoNothing, iniFile);
}

void GetProfileNames(char* profileNamesA)
{
    GetPrivateProfileSectionNamesWithFilter();

    int offset = 10; //increase when top-level menu needs more than 9 elements, probably never
    char buf[MAX_SECTION_NAME];
    WCHAR* profile = ProfileNames;
    strcpy(profileNamesA, "{");
    while(*profile != 0x00)
    {
        _ultoa(offset, buf, 10);
        strcat(profileNamesA, buf);
        wcstombs_s(NULL, buf, _countof(buf), profile, _TRUNCATE);
        strcat(profileNamesA, buf);
        strcat(profileNamesA, ",");

        offset++;

        profile = profile + wcslen(profile) + 1;
    }

    strcat(profileNamesA, "}");
}

void SetCurrentProfile(const WCHAR* profile)
{
    wcscpy(CurrentProfile, profile);
    SaveCurrentProfile(profile);
}

void SaveCurrentProfile(const WCHAR* profile)
{
    WritePrivateProfileStringW(INDEPENDENT_SECTION, L"CurrentProfile", profile, ScyllaHideIniPath);
}

void ReadCurrentProfile()
{
    GetPrivateProfileStringW(INDEPENDENT_SECTION, L"CurrentProfile", L"", CurrentProfile, _countof(CurrentProfile), ScyllaHideIniPath);

    if (wcslen(CurrentProfile) == 0)
    {
        wcscpy(CurrentProfile, DEFAULT_PROFILE);
        CreateSettings();
        SetCurrentProfile(DEFAULT_PROFILE);
    }
}

void GetPrivateProfileSectionNamesWithFilter()
{
    WCHAR tempBuffer[_countof(ProfileNames)] = {0};
    GetPrivateProfileSectionNamesW(tempBuffer, _countof(tempBuffer), ScyllaHideIniPath);

    ZeroMemory(ProfileNames, sizeof(ProfileNames));

    WCHAR *profile = tempBuffer;
    WCHAR *Copy = ProfileNames;

    while(*profile != 0x00)
    {
        if (_wcsicmp(profile, INDEPENDENT_SECTION) != 0)
        {
            wcscpy(Copy, profile);
            Copy += wcslen(profile) + 1;
        }

        profile = profile + wcslen(profile) + 1;
    }
}

void SetCurrentProfile(int index)
{
    int offset = 10; //increase when top-level menu needs more than 9 elements, probably never

    WCHAR* profile = ProfileNames;
    while(*profile != 0x00) {

        if(offset==index) {
            SetCurrentProfile(profile);
            return;
        }

        offset++;
        profile = profile + wcslen(profile) + 1;
    }
}