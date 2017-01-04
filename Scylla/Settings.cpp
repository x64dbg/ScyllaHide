#include "Settings.h"
#include <Windows.h>
#include <algorithm>

#include "Util.h"

static const wchar_t kSettingsSectionName[] = L"SETTINGS";
static const wchar_t kDefaultHideProfileName[] = L"SCYLLA_HIDE";

std::vector<std::wstring> Scylla::LoadHideProfileNames(const wchar_t *wszIniFile)
{
    auto sections = GetPrivateProfileSectionNamesW(wszIniFile);
    sections.erase(std::remove(sections.begin(), sections.end(), kSettingsSectionName), sections.end());
    return sections;
}

std::wstring Scylla::LoadHideProfileName(const wchar_t *wszIniFile)
{
    return GetPrivateProfileStringW(kSettingsSectionName, L"CurrentProfile", kDefaultHideProfileName, wszIniFile);
}

void Scylla::LoadHideProfileSettings(const wchar_t *wszIniFile, const wchar_t *wszProfile, HideSettings *pSettings)
{
    pSettings->BlockInput = ::GetPrivateProfileIntW(wszProfile, L"BlockInputHook", 1, wszIniFile);
    pSettings->DLLNormal = ::GetPrivateProfileIntW(wszProfile, L"DLLNormal", 1, wszIniFile);
    pSettings->DLLStealth = ::GetPrivateProfileIntW(wszProfile, L"DLLStealth", 0, wszIniFile);
    pSettings->DLLUnload = ::GetPrivateProfileIntW(wszProfile, L"DLLUnload", 1, wszIniFile);
    pSettings->GetLocalTime = ::GetPrivateProfileIntW(wszProfile, L"GetLocalTimeHook", 1, wszIniFile);
    pSettings->GetSystemTime = ::GetPrivateProfileIntW(wszProfile, L"GetSystemTimeHook", 1, wszIniFile);
    pSettings->GetTickCount = ::GetPrivateProfileIntW(wszProfile, L"GetTickCountHook", 1, wszIniFile);
    pSettings->GetTickCount64 = ::GetPrivateProfileIntW(wszProfile, L"GetTickCount64Hook", 1, wszIniFile);
    pSettings->KiUserExceptionDispatcher = ::GetPrivateProfileIntW(wszProfile, L"KiUserExceptionDispatcherHook", 1, wszIniFile);
    pSettings->NtClose = ::GetPrivateProfileIntW(wszProfile, L"NtCloseHook", 1, wszIniFile);
    pSettings->NtContinue = ::GetPrivateProfileIntW(wszProfile, L"NtContinueHook", 1, wszIniFile);
    pSettings->NtCreateThreadEx = ::GetPrivateProfileIntW(wszProfile, L"NtCreateThreadExHook", 1, wszIniFile);
    pSettings->NtGetContextThread = ::GetPrivateProfileIntW(wszProfile, L"NtGetContextThreadHook", 1, wszIniFile);
    pSettings->NtQueryInformationProcess = ::GetPrivateProfileIntW(wszProfile, L"NtQueryInformationProcessHook", 1, wszIniFile);
    pSettings->NtQueryObject = ::GetPrivateProfileIntW(wszProfile, L"NtQueryObjectHook", 1, wszIniFile);
    pSettings->NtQueryPerformanceCounter = ::GetPrivateProfileIntW(wszProfile, L"NtQueryPerformanceCounterHook", 1, wszIniFile);
    pSettings->NtQuerySystemInformation = ::GetPrivateProfileIntW(wszProfile, L"NtQuerySystemInformationHook", 1, wszIniFile);
    pSettings->NtQuerySystemTime = ::GetPrivateProfileIntW(wszProfile, L"NtQuerySystemTimeHook", 1, wszIniFile);
    pSettings->NtSetContextThread = ::GetPrivateProfileIntW(wszProfile, L"NtSetContextThreadHook", 1, wszIniFile);
    pSettings->NtSetDebugFilterState = ::GetPrivateProfileIntW(wszProfile, L"NtSetDebugFilterStateHook", 1, wszIniFile);
    pSettings->NtSetInformationThread = ::GetPrivateProfileIntW(wszProfile, L"NtSetInformationThreadHook", 1, wszIniFile);
    pSettings->NtSetInformationProcess = ::GetPrivateProfileIntW(wszProfile, L"NtSetInformationProcessHook", 1, wszIniFile);
    pSettings->NtUserBuildHwndList = ::GetPrivateProfileIntW(wszProfile, L"NtUserBuildHwndListHook", 1, wszIniFile);
    pSettings->NtUserFindWindowEx = ::GetPrivateProfileIntW(wszProfile, L"NtUserFindWindowExHook", 1, wszIniFile);
    pSettings->NtUserQueryWindow = ::GetPrivateProfileIntW(wszProfile, L"NtUserQueryWindowHook", 1, wszIniFile);
    pSettings->NtYieldExecution = ::GetPrivateProfileIntW(wszProfile, L"NtYieldExecutionHook", 1, wszIniFile);
    pSettings->OutputDebugStringA = ::GetPrivateProfileIntW(wszProfile, L"OutputDebugStringHook", 1, wszIniFile);
    pSettings->PEBBeingDebugged = ::GetPrivateProfileIntW(wszProfile, L"PebBeingDebugged", 1, wszIniFile);
    pSettings->PEBHeapFlags = ::GetPrivateProfileIntW(wszProfile, L"PebHeapFlags", 1, wszIniFile);
    pSettings->PEBNtGlobalFlag = ::GetPrivateProfileIntW(wszProfile, L"PebNtGlobalFlag", 1, wszIniFile);
    pSettings->PEBStartupInfo = ::GetPrivateProfileIntW(wszProfile, L"PebStartupInfo", 1, wszIniFile);
    pSettings->preventThreadCreation = ::GetPrivateProfileIntW(wszProfile, L"PreventThreadCreation", 0, wszIniFile); // disabled by default
    pSettings->removeDebugPrivileges = ::GetPrivateProfileIntW(wszProfile, L"RemoveDebugPrivileges", 1, wszIniFile);
    pSettings->killAntiAttach = ::GetPrivateProfileIntW(wszProfile, L"KillAntiAttach", 1, wszIniFile);

    pSettings->handleExceptionPrint = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionPrint", 1, wszIniFile);
    pSettings->handleExceptionRip = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionRip", 1, wszIniFile);
    pSettings->handleExceptionIllegalInstruction = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionIllegalInstruction", 1, wszIniFile);
    pSettings->handleExceptionInvalidLockSequence = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionInvalidLockSequence", 1, wszIniFile);
    pSettings->handleExceptionNoncontinuableException = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionNoncontinuableException", 1, wszIniFile);
    pSettings->handleExceptionAssertionFailure = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionAssertionFailure", 1, wszIniFile);
    pSettings->handleExceptionBreakpoint = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionBreakpoint", 1, wszIniFile);
    pSettings->handleExceptionGuardPageViolation = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionGuardPageViolation", 1, wszIniFile);
    pSettings->handleExceptionWx86Breakpoint = ::GetPrivateProfileIntW(wszProfile, L"handleExceptionWx86Breakpoint", 1, wszIniFile);

    if (pSettings->DLLNormal)
        pSettings->DLLStealth = 0;

    //ida specific
    pSettings->autostartServer = ::GetPrivateProfileIntW(wszProfile, L"AutostartServer", 1, wszIniFile);
    pSettings->serverPort = GetPrivateProfileStringW(wszProfile, L"ServerPort", L"1337", wszIniFile);

    //olly1 specific
    pSettings->breakTLS = ::GetPrivateProfileIntW(wszProfile, L"BreakOnTLS", 1, wszIniFile);
    pSettings->fixOllyBugs = ::GetPrivateProfileIntW(wszProfile, L"FixOllyBugs", 1, wszIniFile);
    pSettings->removeEPBreak = ::GetPrivateProfileIntW(wszProfile, L"RemoveEPBreak", 0, wszIniFile);
    pSettings->skipEPOutsideCode = ::GetPrivateProfileIntW(wszProfile, L"SkipEPOutsideCode", 1, wszIniFile);
    pSettings->x64Fix = ::GetPrivateProfileIntW(wszProfile, L"X64Fix", 0, wszIniFile);
    pSettings->advancedGoto = ::GetPrivateProfileIntW(wszProfile, L"advancedGoto", 0, wszIniFile);
    pSettings->ignoreBadPEImage = ::GetPrivateProfileIntW(wszProfile, L"ignoreBadPEImage", 0, wszIniFile);
    pSettings->skipCompressedDoAnalyze = ::GetPrivateProfileIntW(wszProfile, L"skipCompressedDoAnalyze", 0, wszIniFile);
    pSettings->skipCompressedDoNothing = ::GetPrivateProfileIntW(wszProfile, L"skipCompressedDoNothing", 0, wszIniFile);
    pSettings->skipLoadDllDoLoad = ::GetPrivateProfileIntW(wszProfile, L"skipLoadDllDoLoad", 0, wszIniFile);
    pSettings->skipLoadDllDoNothing = ::GetPrivateProfileIntW(wszProfile, L"skipLoadDllDoNothing", 0, wszIniFile);
    pSettings->advancedInfobar = ::GetPrivateProfileIntW(wszProfile, L"advancedInfobar", 0, wszIniFile);
    pSettings->ollyTitle = GetPrivateProfileStringW(wszProfile, L"WindowTitle", L"ScyllaHide", wszIniFile);
}

bool Scylla::SaveHideProfileSettings(const wchar_t *wszIniFile, const wchar_t *wszProfile, const HideSettings *pSettings)
{
    if (!FileExistsW(wszIniFile))
    {
        WORD wBOM = 0xFEFF; // UTF16-LE
        DWORD NumberOfBytesWritten;

        auto hFile = CreateFileW(wszIniFile, GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!hFile)
            return false;
        WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, nullptr);
        CloseHandle(hFile);
    }

    auto success = true;
    success &= WritePrivateProfileIntW(wszProfile, L"BlockInputHook", pSettings->BlockInput, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"DLLNormal", pSettings->DLLNormal, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"DLLStealth", pSettings->DLLStealth, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"DLLUnload", pSettings->DLLUnload, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"GetLocalTimeHook", pSettings->GetLocalTime, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"GetSystemTimeHook", pSettings->GetSystemTime, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"GetTickCount64Hook", pSettings->GetTickCount64, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"GetTickCountHook", pSettings->GetTickCount, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"KiUserExceptionDispatcherHook", pSettings->KiUserExceptionDispatcher, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtCloseHook", pSettings->NtClose, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtContinueHook", pSettings->NtContinue, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtCreateThreadExHook", pSettings->NtCreateThreadEx, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtGetContextThreadHook", pSettings->NtGetContextThread, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtQueryInformationProcessHook", pSettings->NtQueryInformationProcess, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtQueryObjectHook", pSettings->NtQueryObject, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtQueryPerformanceCounterHook", pSettings->NtQueryPerformanceCounter, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtQuerySystemInformationHook", pSettings->NtQuerySystemInformation, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtQuerySystemTimeHook", pSettings->NtQuerySystemTime, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtSetContextThreadHook", pSettings->NtSetContextThread, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtSetDebugFilterStateHook", pSettings->NtSetDebugFilterState, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtSetInformationThreadHook", pSettings->NtSetInformationThread, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtSetInformationProcessHook", pSettings->NtSetInformationProcess, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtUserBuildHwndListHook", pSettings->NtUserBuildHwndList, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtUserFindWindowExHook", pSettings->NtUserFindWindowEx, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtUserQueryWindowHook", pSettings->NtUserQueryWindow, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"NtYieldExecutionHook", pSettings->NtYieldExecution, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"OutputDebugStringHook", pSettings->OutputDebugStringA, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"PebBeingDebugged", pSettings->PEBBeingDebugged, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"PebHeapFlags", pSettings->PEBHeapFlags, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"PebNtGlobalFlag", pSettings->PEBNtGlobalFlag, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"PebStartupInfo", pSettings->PEBStartupInfo, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"PreventThreadCreation", pSettings->preventThreadCreation, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"RemoveDebugPrivileges", pSettings->removeDebugPrivileges, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"KillAntiAttach", pSettings->killAntiAttach, wszIniFile);

    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionPrint", pSettings->handleExceptionPrint, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionRip", pSettings->handleExceptionRip, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionIllegalInstruction", pSettings->handleExceptionIllegalInstruction, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionInvalidLockSequence", pSettings->handleExceptionInvalidLockSequence, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionNoncontinuableException", pSettings->handleExceptionNoncontinuableException, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionAssertionFailure", pSettings->handleExceptionAssertionFailure, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionBreakpoint", pSettings->handleExceptionBreakpoint, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionGuardPageViolation", pSettings->handleExceptionGuardPageViolation, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"handleExceptionWx86Breakpoint", pSettings->handleExceptionWx86Breakpoint, wszIniFile);

    //ida specific
    success &= WritePrivateProfileIntW(wszProfile, L"AutostartServer", pSettings->autostartServer, wszIniFile);
    success &= ::WritePrivateProfileStringW(wszProfile, L"ServerPort", pSettings->serverPort.c_str(), wszIniFile) == TRUE;

    //olly1 specific
    success &= WritePrivateProfileIntW(wszProfile, L"BreakOnTLS", pSettings->breakTLS, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"FixOllyBugs", pSettings->fixOllyBugs, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"RemoveEPBreak", pSettings->removeEPBreak, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"SkipEPOutsideCode", pSettings->skipEPOutsideCode, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"X64Fix", pSettings->x64Fix, wszIniFile);
    success &= ::WritePrivateProfileStringW(wszProfile, L"WindowTitle", pSettings->ollyTitle.c_str(), wszIniFile) == TRUE;
    success &= WritePrivateProfileIntW(wszProfile, L"advancedGoto", pSettings->advancedGoto, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"ignoreBadPEImage", pSettings->ignoreBadPEImage, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"skipCompressedDoAnalyze", pSettings->skipCompressedDoAnalyze, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"skipCompressedDoNothing", pSettings->skipCompressedDoNothing, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"skipLoadDllDoLoad", pSettings->skipLoadDllDoLoad, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"skipLoadDllDoNothing", pSettings->skipLoadDllDoNothing, wszIniFile);
    success &= WritePrivateProfileIntW(wszProfile, L"advancedInfobar", pSettings->advancedInfobar, wszIniFile);

    return success;
}
