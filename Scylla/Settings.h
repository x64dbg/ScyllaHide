#pragma once

#include <string>
#include <vector>

namespace Scylla
{
    struct HideSettings
    {
        int PEBBeingDebugged;
        int PEBHeapFlags;
        int PEBNtGlobalFlag;
        int PEBStartupInfo;
        int NtSetInformationThread;
        int NtQuerySystemInformation;
        int NtQueryInformationProcess;
        int NtSetInformationProcess;
        int NtQueryObject;
        int NtYieldExecution;
        int GetTickCount;
        int GetTickCount64;
        int GetLocalTime;
        int GetSystemTime;
        int NtQuerySystemTime;
        int NtQueryPerformanceCounter;
        int OutputDebugStringA;
        int BlockInput;
        int NtGetContextThread;
        int NtSetContextThread;
        int NtContinue;
        int KiUserExceptionDispatcher;
        int NtUserFindWindowEx;
        int NtUserBuildHwndList;
        int NtUserQueryWindow;
        int NtSetDebugFilterState;
        int NtClose;
        int NtCreateThreadEx;
        int removeEPBreak;
        int fixOllyBugs;
        int breakTLS;
        int skipEPOutsideCode;
        std::wstring ollyTitle;
        int x64Fix;
        int preventThreadCreation;
        int DLLStealth;
        int DLLNormal;
        int DLLUnload;
        std::wstring serverPort;
        int autostartServer;
        int removeDebugPrivileges;
        int malwareRunpeUnpacker;
        int killAntiAttach;
        int ignoreBadPEImage;
        int advancedGoto;
        int skipCompressedDoAnalyze;
        int skipCompressedDoNothing;
        int skipLoadDllDoLoad;
        int skipLoadDllDoNothing;
        int advancedInfobar;
        int handleExceptionPrint;
        int handleExceptionRip;
        int handleExceptionInvalidLockSequence;
        int handleExceptionIllegalInstruction;
        int handleExceptionNoncontinuableException;
        int handleExceptionAssertionFailure;
        int handleExceptionBreakpoint;
        int handleExceptionWx86Breakpoint;
        int handleExceptionGuardPageViolation;
    };

    std::vector<std::wstring> LoadHideProfileNames(const wchar_t *wszIniFile);
    std::wstring LoadHideProfileName(const wchar_t *wszIniFile);
    std::wstring SaveHideProfileName(const wchar_t *wszIniFile);
    void LoadHideProfileSettings(const wchar_t *wszIniFile, const wchar_t *wszProfile, HideSettings *pSettings);
    bool SaveHideProfileSettings(const wchar_t *wszIniFile, const wchar_t *wszProfile, const HideSettings *pSettings);
}
