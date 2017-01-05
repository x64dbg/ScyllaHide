#include "Settings.h"
#include <Windows.h>
#include <algorithm>

#include "Util.h"

#define SCYLLA_HIDE_SETTINGS_SECTION                L"SETTINGS"
#define SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY    L"CurrentProfile"
#define SCYLLA_HIDE_SETTINGS_DEFAULT_PROFILE        L"SCYLLA_HIDE"

const wchar_t Scylla::Settings::kFileName[] = L"scylla_hide.ini";

void Scylla::Settings::Load(const wchar_t *ini_path)
{
    ini_path_ = ini_path;
    profile_names_ = GetPrivateProfileSectionNamesW(ini_path);
    profile_names_.erase(std::remove(profile_names_.begin(), profile_names_.end(), SCYLLA_HIDE_SETTINGS_SECTION), profile_names_.end());

    profile_name_ = GetPrivateProfileStringW(SCYLLA_HIDE_SETTINGS_SECTION, SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY, SCYLLA_HIDE_SETTINGS_DEFAULT_PROFILE, ini_path);
    LoadProfile(profile_name_.c_str());
}

bool Scylla::Settings::AddProfile(const wchar_t *name)
{
    if (std::find(profile_names_.begin(), profile_names_.end(), name) != profile_names_.end())
        return false;

    profile_names_.push_back(name);
    return true;
}

void Scylla::Settings::SetProfile(const wchar_t *name)
{
    if (profile_name_ == name)
        return;

    profile_name_ = name;
    WritePrivateProfileStringW(SCYLLA_HIDE_SETTINGS_SECTION, SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY, name, ini_path_.c_str());

    LoadProfile(name);
}


void Scylla::Settings::LoadProfile(const wchar_t *name)
{
    profile_.BlockInput = ::GetPrivateProfileIntW(name, L"BlockInputHook", 1, ini_path_.c_str());
    profile_.DLLNormal = ::GetPrivateProfileIntW(name, L"DLLNormal", 1, ini_path_.c_str());
    profile_.DLLStealth = ::GetPrivateProfileIntW(name, L"DLLStealth", 0, ini_path_.c_str());
    profile_.DLLUnload = ::GetPrivateProfileIntW(name, L"DLLUnload", 1, ini_path_.c_str());
    profile_.GetLocalTime = ::GetPrivateProfileIntW(name, L"GetLocalTimeHook", 1, ini_path_.c_str());
    profile_.GetSystemTime = ::GetPrivateProfileIntW(name, L"GetSystemTimeHook", 1, ini_path_.c_str());
    profile_.GetTickCount = ::GetPrivateProfileIntW(name, L"GetTickCountHook", 1, ini_path_.c_str());
    profile_.GetTickCount64 = ::GetPrivateProfileIntW(name, L"GetTickCount64Hook", 1, ini_path_.c_str());
    profile_.KiUserExceptionDispatcher = ::GetPrivateProfileIntW(name, L"KiUserExceptionDispatcherHook", 1, ini_path_.c_str());
    profile_.NtClose = ::GetPrivateProfileIntW(name, L"NtCloseHook", 1, ini_path_.c_str());
    profile_.NtContinue = ::GetPrivateProfileIntW(name, L"NtContinueHook", 1, ini_path_.c_str());
    profile_.NtCreateThreadEx = ::GetPrivateProfileIntW(name, L"NtCreateThreadExHook", 1, ini_path_.c_str());
    profile_.NtGetContextThread = ::GetPrivateProfileIntW(name, L"NtGetContextThreadHook", 1, ini_path_.c_str());
    profile_.NtQueryInformationProcess = ::GetPrivateProfileIntW(name, L"NtQueryInformationProcessHook", 1, ini_path_.c_str());
    profile_.NtQueryObject = ::GetPrivateProfileIntW(name, L"NtQueryObjectHook", 1, ini_path_.c_str());
    profile_.NtQueryPerformanceCounter = ::GetPrivateProfileIntW(name, L"NtQueryPerformanceCounterHook", 1, ini_path_.c_str());
    profile_.NtQuerySystemInformation = ::GetPrivateProfileIntW(name, L"NtQuerySystemInformationHook", 1, ini_path_.c_str());
    profile_.NtQuerySystemTime = ::GetPrivateProfileIntW(name, L"NtQuerySystemTimeHook", 1, ini_path_.c_str());
    profile_.NtSetContextThread = ::GetPrivateProfileIntW(name, L"NtSetContextThreadHook", 1, ini_path_.c_str());
    profile_.NtSetDebugFilterState = ::GetPrivateProfileIntW(name, L"NtSetDebugFilterStateHook", 1, ini_path_.c_str());
    profile_.NtSetInformationThread = ::GetPrivateProfileIntW(name, L"NtSetInformationThreadHook", 1, ini_path_.c_str());
    profile_.NtSetInformationProcess = ::GetPrivateProfileIntW(name, L"NtSetInformationProcessHook", 1, ini_path_.c_str());
    profile_.NtUserBuildHwndList = ::GetPrivateProfileIntW(name, L"NtUserBuildHwndListHook", 1, ini_path_.c_str());
    profile_.NtUserFindWindowEx = ::GetPrivateProfileIntW(name, L"NtUserFindWindowExHook", 1, ini_path_.c_str());
    profile_.NtUserQueryWindow = ::GetPrivateProfileIntW(name, L"NtUserQueryWindowHook", 1, ini_path_.c_str());
    profile_.NtYieldExecution = ::GetPrivateProfileIntW(name, L"NtYieldExecutionHook", 1, ini_path_.c_str());
    profile_.OutputDebugStringA = ::GetPrivateProfileIntW(name, L"OutputDebugStringHook", 1, ini_path_.c_str());
    profile_.PEBBeingDebugged = ::GetPrivateProfileIntW(name, L"PebBeingDebugged", 1, ini_path_.c_str());
    profile_.PEBHeapFlags = ::GetPrivateProfileIntW(name, L"PebHeapFlags", 1, ini_path_.c_str());
    profile_.PEBNtGlobalFlag = ::GetPrivateProfileIntW(name, L"PebNtGlobalFlag", 1, ini_path_.c_str());
    profile_.PEBStartupInfo = ::GetPrivateProfileIntW(name, L"PebStartupInfo", 1, ini_path_.c_str());
    profile_.preventThreadCreation = ::GetPrivateProfileIntW(name, L"PreventThreadCreation", 0, ini_path_.c_str());
    profile_.removeDebugPrivileges = ::GetPrivateProfileIntW(name, L"RemoveDebugPrivileges", 1, ini_path_.c_str());
    profile_.killAntiAttach = ::GetPrivateProfileIntW(name, L"KillAntiAttach", 1, ini_path_.c_str());

    profile_.handleExceptionPrint = ::GetPrivateProfileIntW(name, L"handleExceptionPrint", 1, ini_path_.c_str());
    profile_.handleExceptionRip = ::GetPrivateProfileIntW(name, L"handleExceptionRip", 1, ini_path_.c_str());
    profile_.handleExceptionIllegalInstruction = ::GetPrivateProfileIntW(name, L"handleExceptionIllegalInstruction", 1, ini_path_.c_str());
    profile_.handleExceptionInvalidLockSequence = ::GetPrivateProfileIntW(name, L"handleExceptionInvalidLockSequence", 1, ini_path_.c_str());
    profile_.handleExceptionNoncontinuableException = ::GetPrivateProfileIntW(name, L"handleExceptionNoncontinuableException", 1, ini_path_.c_str());
    profile_.handleExceptionAssertionFailure = ::GetPrivateProfileIntW(name, L"handleExceptionAssertionFailure", 1, ini_path_.c_str());
    profile_.handleExceptionBreakpoint = ::GetPrivateProfileIntW(name, L"handleExceptionBreakpoint", 1, ini_path_.c_str());
    profile_.handleExceptionGuardPageViolation = ::GetPrivateProfileIntW(name, L"handleExceptionGuardPageViolation", 1, ini_path_.c_str());
    profile_.handleExceptionWx86Breakpoint = ::GetPrivateProfileIntW(name, L"handleExceptionWx86Breakpoint", 1, ini_path_.c_str());

    if (profile_.DLLNormal)
        profile_.DLLStealth = 0;

    //ida specific
    profile_.autostartServer = ::GetPrivateProfileIntW(name, L"AutostartServer", 1, ini_path_.c_str());
    profile_.serverPort = GetPrivateProfileStringW(name, L"ServerPort", L"1337", ini_path_.c_str());

    //olly1 specific
    profile_.breakTLS = ::GetPrivateProfileIntW(name, L"BreakOnTLS", 1, ini_path_.c_str());
    profile_.fixOllyBugs = ::GetPrivateProfileIntW(name, L"FixOllyBugs", 1, ini_path_.c_str());
    profile_.removeEPBreak = ::GetPrivateProfileIntW(name, L"RemoveEPBreak", 0, ini_path_.c_str());
    profile_.skipEPOutsideCode = ::GetPrivateProfileIntW(name, L"SkipEPOutsideCode", 1, ini_path_.c_str());
    profile_.x64Fix = ::GetPrivateProfileIntW(name, L"X64Fix", 0, ini_path_.c_str());
    profile_.advancedGoto = ::GetPrivateProfileIntW(name, L"advancedGoto", 0, ini_path_.c_str());
    profile_.ignoreBadPEImage = ::GetPrivateProfileIntW(name, L"ignoreBadPEImage", 0, ini_path_.c_str());
    profile_.skipCompressedDoAnalyze = ::GetPrivateProfileIntW(name, L"skipCompressedDoAnalyze", 0, ini_path_.c_str());
    profile_.skipCompressedDoNothing = ::GetPrivateProfileIntW(name, L"skipCompressedDoNothing", 0, ini_path_.c_str());
    profile_.skipLoadDllDoLoad = ::GetPrivateProfileIntW(name, L"skipLoadDllDoLoad", 0, ini_path_.c_str());
    profile_.skipLoadDllDoNothing = ::GetPrivateProfileIntW(name, L"skipLoadDllDoNothing", 0, ini_path_.c_str());
    profile_.advancedInfobar = ::GetPrivateProfileIntW(name, L"advancedInfobar", 0, ini_path_.c_str());
    profile_.ollyTitle = GetPrivateProfileStringW(name, L"WindowTitle", L"ScyllaHide", ini_path_.c_str());
}

bool Scylla::Settings::SaveProfile() const
{
    if (!FileExistsW(ini_path_.c_str()))
    {
        WORD wBOM = 0xFEFF; // UTF16-LE
        DWORD NumberOfBytesWritten;

        auto hFile = CreateFileW(ini_path_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!hFile)
            return false;
        WriteFile(hFile, &wBOM, sizeof(WORD), &NumberOfBytesWritten, nullptr);
        CloseHandle(hFile);
    }

    auto success = true;
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"BlockInputHook", profile_.BlockInput, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"DLLNormal", profile_.DLLNormal, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"DLLStealth", profile_.DLLStealth, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"DLLUnload", profile_.DLLUnload, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"GetLocalTimeHook", profile_.GetLocalTime, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"GetSystemTimeHook", profile_.GetSystemTime, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"GetTickCount64Hook", profile_.GetTickCount64, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"GetTickCountHook", profile_.GetTickCount, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"KiUserExceptionDispatcherHook", profile_.KiUserExceptionDispatcher, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtCloseHook", profile_.NtClose, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtContinueHook", profile_.NtContinue, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtCreateThreadExHook", profile_.NtCreateThreadEx, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtGetContextThreadHook", profile_.NtGetContextThread, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtQueryInformationProcessHook", profile_.NtQueryInformationProcess, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtQueryObjectHook", profile_.NtQueryObject, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtQueryPerformanceCounterHook", profile_.NtQueryPerformanceCounter, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtQuerySystemInformationHook", profile_.NtQuerySystemInformation, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtQuerySystemTimeHook", profile_.NtQuerySystemTime, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtSetContextThreadHook", profile_.NtSetContextThread, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtSetDebugFilterStateHook", profile_.NtSetDebugFilterState, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtSetInformationThreadHook", profile_.NtSetInformationThread, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtSetInformationProcessHook", profile_.NtSetInformationProcess, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtUserBuildHwndListHook", profile_.NtUserBuildHwndList, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtUserFindWindowExHook", profile_.NtUserFindWindowEx, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtUserQueryWindowHook", profile_.NtUserQueryWindow, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"NtYieldExecutionHook", profile_.NtYieldExecution, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"OutputDebugStringHook", profile_.OutputDebugStringA, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"PebBeingDebugged", profile_.PEBBeingDebugged, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"PebHeapFlags", profile_.PEBHeapFlags, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"PebNtGlobalFlag", profile_.PEBNtGlobalFlag, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"PebStartupInfo", profile_.PEBStartupInfo, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"PreventThreadCreation", profile_.preventThreadCreation, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"RemoveDebugPrivileges", profile_.removeDebugPrivileges, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"KillAntiAttach", profile_.killAntiAttach, ini_path_.c_str());

    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionPrint", profile_.handleExceptionPrint, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionRip", profile_.handleExceptionRip, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionIllegalInstruction", profile_.handleExceptionIllegalInstruction, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionInvalidLockSequence", profile_.handleExceptionInvalidLockSequence, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionNoncontinuableException", profile_.handleExceptionNoncontinuableException, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionAssertionFailure", profile_.handleExceptionAssertionFailure, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionBreakpoint", profile_.handleExceptionBreakpoint, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionGuardPageViolation", profile_.handleExceptionGuardPageViolation, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"handleExceptionWx86Breakpoint", profile_.handleExceptionWx86Breakpoint, ini_path_.c_str());

    //ida specific
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"AutostartServer", profile_.autostartServer, ini_path_.c_str());
    success &= ::WritePrivateProfileStringW(profile_name().c_str(), L"ServerPort", profile_.serverPort.c_str(), ini_path_.c_str()) == TRUE;

    //olly1 specific
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"BreakOnTLS", profile_.breakTLS, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"FixOllyBugs", profile_.fixOllyBugs, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"RemoveEPBreak", profile_.removeEPBreak, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"SkipEPOutsideCode", profile_.skipEPOutsideCode, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"X64Fix", profile_.x64Fix, ini_path_.c_str());
    success &= ::WritePrivateProfileStringW(profile_name().c_str(), L"WindowTitle", profile_.ollyTitle.c_str(), ini_path_.c_str()) == TRUE;
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"advancedGoto", profile_.advancedGoto, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"ignoreBadPEImage", profile_.ignoreBadPEImage, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"skipCompressedDoAnalyze", profile_.skipCompressedDoAnalyze, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"skipCompressedDoNothing", profile_.skipCompressedDoNothing, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"skipLoadDllDoLoad", profile_.skipLoadDllDoLoad, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"skipLoadDllDoNothing", profile_.skipLoadDllDoNothing, ini_path_.c_str());
    success &= WritePrivateProfileIntW(profile_name().c_str(), L"advancedInfobar", profile_.advancedInfobar, ini_path_.c_str());

    return success;
}








