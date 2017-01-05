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
    profile_names_ = IniLoadSectionNames(ini_path);
    profile_names_.erase(std::remove(profile_names_.begin(), profile_names_.end(), SCYLLA_HIDE_SETTINGS_SECTION), profile_names_.end());

    profile_name_ = IniLoadString(ini_path, SCYLLA_HIDE_SETTINGS_SECTION, SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY, SCYLLA_HIDE_SETTINGS_DEFAULT_PROFILE);
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
    IniSaveString(ini_path_.c_str(), SCYLLA_HIDE_SETTINGS_SECTION, SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY, name);

    LoadProfile(name);
}


void Scylla::Settings::LoadProfile(const wchar_t *name)
{
    profile_.BlockInput = IniLoadNum(ini_path_.c_str(), name, L"BlockInputHook", 1);
    profile_.DLLNormal = IniLoadNum(ini_path_.c_str(), name, L"DLLNormal", 1);
    profile_.DLLStealth = IniLoadNum(ini_path_.c_str(), name, L"DLLStealth", 0);
    profile_.DLLUnload = IniLoadNum(ini_path_.c_str(), name, L"DLLUnload", 1);
    profile_.GetLocalTime = IniLoadNum(ini_path_.c_str(), name, L"GetLocalTimeHook", 1);
    profile_.GetSystemTime = IniLoadNum(ini_path_.c_str(), name, L"GetSystemTimeHook", 1);
    profile_.GetTickCount = IniLoadNum(ini_path_.c_str(), name, L"GetTickCountHook", 1);
    profile_.GetTickCount64 = IniLoadNum(ini_path_.c_str(), name, L"GetTickCount64Hook", 1);
    profile_.KiUserExceptionDispatcher = IniLoadNum(ini_path_.c_str(), name, L"KiUserExceptionDispatcherHook", 1);
    profile_.NtClose = IniLoadNum(ini_path_.c_str(), name, L"NtCloseHook", 1);
    profile_.NtContinue = IniLoadNum(ini_path_.c_str(), name, L"NtContinueHook", 1);
    profile_.NtCreateThreadEx = IniLoadNum(ini_path_.c_str(), name, L"NtCreateThreadExHook", 1);
    profile_.NtGetContextThread = IniLoadNum(ini_path_.c_str(), name, L"NtGetContextThreadHook", 1);
    profile_.NtQueryInformationProcess = IniLoadNum(ini_path_.c_str(), name, L"NtQueryInformationProcessHook", 1);
    profile_.NtQueryObject = IniLoadNum(ini_path_.c_str(), name, L"NtQueryObjectHook", 1);
    profile_.NtQueryPerformanceCounter = IniLoadNum(ini_path_.c_str(), name, L"NtQueryPerformanceCounterHook", 1);
    profile_.NtQuerySystemInformation = IniLoadNum(ini_path_.c_str(), name, L"NtQuerySystemInformationHook", 1);
    profile_.NtQuerySystemTime = IniLoadNum(ini_path_.c_str(), name, L"NtQuerySystemTimeHook", 1);
    profile_.NtSetContextThread = IniLoadNum(ini_path_.c_str(), name, L"NtSetContextThreadHook", 1);
    profile_.NtSetDebugFilterState = IniLoadNum(ini_path_.c_str(), name, L"NtSetDebugFilterStateHook", 1);
    profile_.NtSetInformationThread = IniLoadNum(ini_path_.c_str(), name, L"NtSetInformationThreadHook", 1);
    profile_.NtSetInformationProcess = IniLoadNum(ini_path_.c_str(), name, L"NtSetInformationProcessHook", 1);
    profile_.NtUserBuildHwndList = IniLoadNum(ini_path_.c_str(), name, L"NtUserBuildHwndListHook", 1);
    profile_.NtUserFindWindowEx = IniLoadNum(ini_path_.c_str(), name, L"NtUserFindWindowExHook", 1);
    profile_.NtUserQueryWindow = IniLoadNum(ini_path_.c_str(), name, L"NtUserQueryWindowHook", 1);
    profile_.NtYieldExecution = IniLoadNum(ini_path_.c_str(), name, L"NtYieldExecutionHook", 1);
    profile_.OutputDebugStringA = IniLoadNum(ini_path_.c_str(), name, L"OutputDebugStringHook", 1);
    profile_.PEBBeingDebugged = IniLoadNum(ini_path_.c_str(), name, L"PebBeingDebugged", 1);
    profile_.PEBHeapFlags = IniLoadNum(ini_path_.c_str(), name, L"PebHeapFlags", 1);
    profile_.PEBNtGlobalFlag = IniLoadNum(ini_path_.c_str(), name, L"PebNtGlobalFlag", 1);
    profile_.PEBStartupInfo = IniLoadNum(ini_path_.c_str(), name, L"PebStartupInfo", 1);
    profile_.preventThreadCreation = IniLoadNum(ini_path_.c_str(), name, L"PreventThreadCreation", 0);
    profile_.protectProcessId = IniLoadNum(ini_path_.c_str(), name, L"ProtectProcessId", 1);
    profile_.removeDebugPrivileges = IniLoadNum(ini_path_.c_str(), name, L"RemoveDebugPrivileges", 1);
    profile_.killAntiAttach = IniLoadNum(ini_path_.c_str(), name, L"KillAntiAttach", 1);

    profile_.handleExceptionPrint = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionPrint", 1);
    profile_.handleExceptionRip = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionRip", 1);
    profile_.handleExceptionIllegalInstruction = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionIllegalInstruction", 1);
    profile_.handleExceptionInvalidLockSequence = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionInvalidLockSequence", 1);
    profile_.handleExceptionNoncontinuableException = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionNoncontinuableException", 1);
    profile_.handleExceptionAssertionFailure = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionAssertionFailure", 1);
    profile_.handleExceptionBreakpoint = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionBreakpoint", 1);
    profile_.handleExceptionGuardPageViolation = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionGuardPageViolation", 1);
    profile_.handleExceptionWx86Breakpoint = IniLoadNum(ini_path_.c_str(), name, L"handleExceptionWx86Breakpoint", 1);

    if (profile_.DLLNormal)
        profile_.DLLStealth = 0;

    //ida specific
    profile_.autostartServer = IniLoadNum(ini_path_.c_str(), name, L"AutostartServer", 1);
    profile_.serverPort = IniLoadString(ini_path_.c_str(), name, L"ServerPort", L"1337");

    //olly1 specific
    profile_.breakTLS = IniLoadNum(ini_path_.c_str(), name, L"BreakOnTLS", 1);
    profile_.fixOllyBugs = IniLoadNum(ini_path_.c_str(), name, L"FixOllyBugs", 1);
    profile_.removeEPBreak = IniLoadNum(ini_path_.c_str(), name, L"RemoveEPBreak", 0);
    profile_.skipEPOutsideCode = IniLoadNum(ini_path_.c_str(), name, L"SkipEPOutsideCode", 1);
    profile_.x64Fix = IniLoadNum(ini_path_.c_str(), name, L"X64Fix", 0);
    profile_.advancedGoto = IniLoadNum(ini_path_.c_str(), name, L"advancedGoto", 0);
    profile_.ignoreBadPEImage = IniLoadNum(ini_path_.c_str(), name, L"ignoreBadPEImage", 0);
    profile_.skipCompressedDoAnalyze = IniLoadNum(ini_path_.c_str(), name, L"skipCompressedDoAnalyze", 0);
    profile_.skipCompressedDoNothing = IniLoadNum(ini_path_.c_str(), name, L"skipCompressedDoNothing", 0);
    profile_.skipLoadDllDoLoad = IniLoadNum(ini_path_.c_str(), name, L"skipLoadDllDoLoad", 0);
    profile_.skipLoadDllDoNothing = IniLoadNum(ini_path_.c_str(), name, L"skipLoadDllDoNothing", 0);
    profile_.advancedInfobar = IniLoadNum(ini_path_.c_str(), name, L"advancedInfobar", 0);
    profile_.ollyTitle = IniLoadString(ini_path_.c_str(), name, L"WindowTitle", L"ScyllaHide");
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
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"BlockInputHook", profile_.BlockInput);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"DLLNormal", profile_.DLLNormal);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"DLLStealth", profile_.DLLStealth);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"DLLUnload", profile_.DLLUnload);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"GetLocalTimeHook", profile_.GetLocalTime);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"GetSystemTimeHook", profile_.GetSystemTime);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"GetTickCount64Hook", profile_.GetTickCount64);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"GetTickCountHook", profile_.GetTickCount);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"KiUserExceptionDispatcherHook", profile_.KiUserExceptionDispatcher);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtCloseHook", profile_.NtClose);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtContinueHook", profile_.NtContinue);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtCreateThreadExHook", profile_.NtCreateThreadEx);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtGetContextThreadHook", profile_.NtGetContextThread);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtQueryInformationProcessHook", profile_.NtQueryInformationProcess);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtQueryObjectHook", profile_.NtQueryObject);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtQueryPerformanceCounterHook", profile_.NtQueryPerformanceCounter);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtQuerySystemInformationHook", profile_.NtQuerySystemInformation);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtQuerySystemTimeHook", profile_.NtQuerySystemTime);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtSetContextThreadHook", profile_.NtSetContextThread);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtSetDebugFilterStateHook", profile_.NtSetDebugFilterState);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtSetInformationThreadHook", profile_.NtSetInformationThread);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtSetInformationProcessHook", profile_.NtSetInformationProcess);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtUserBuildHwndListHook", profile_.NtUserBuildHwndList);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtUserFindWindowExHook", profile_.NtUserFindWindowEx);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtUserQueryWindowHook", profile_.NtUserQueryWindow);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"NtYieldExecutionHook", profile_.NtYieldExecution);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"OutputDebugStringHook", profile_.OutputDebugStringA);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"PebBeingDebugged", profile_.PEBBeingDebugged);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"PebHeapFlags", profile_.PEBHeapFlags);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"PebNtGlobalFlag", profile_.PEBNtGlobalFlag);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"PebStartupInfo", profile_.PEBStartupInfo);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"PreventThreadCreation", profile_.preventThreadCreation);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"ProtectProcessId", profile_.protectProcessId);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"RemoveDebugPrivileges", profile_.removeDebugPrivileges);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"KillAntiAttach", profile_.killAntiAttach);

    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionPrint", profile_.handleExceptionPrint);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionRip", profile_.handleExceptionRip);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionIllegalInstruction", profile_.handleExceptionIllegalInstruction);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionInvalidLockSequence", profile_.handleExceptionInvalidLockSequence);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionNoncontinuableException", profile_.handleExceptionNoncontinuableException);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionAssertionFailure", profile_.handleExceptionAssertionFailure);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionBreakpoint", profile_.handleExceptionBreakpoint);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionGuardPageViolation", profile_.handleExceptionGuardPageViolation);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"handleExceptionWx86Breakpoint", profile_.handleExceptionWx86Breakpoint);

    //ida specific
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"AutostartServer", profile_.autostartServer);
    success &= IniSaveString(ini_path_.c_str(), profile_name().c_str(), L"ServerPort", profile_.serverPort.c_str());

    //olly1 specific
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"BreakOnTLS", profile_.breakTLS);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"FixOllyBugs", profile_.fixOllyBugs);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"RemoveEPBreak", profile_.removeEPBreak);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"SkipEPOutsideCode", profile_.skipEPOutsideCode);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"X64Fix", profile_.x64Fix);
    success &= IniSaveString(ini_path_.c_str(), profile_name().c_str(), L"WindowTitle", profile_.ollyTitle.c_str());
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"advancedGoto", profile_.advancedGoto);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"ignoreBadPEImage", profile_.ignoreBadPEImage);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"skipCompressedDoAnalyze", profile_.skipCompressedDoAnalyze);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"skipCompressedDoNothing", profile_.skipCompressedDoNothing);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"skipLoadDllDoLoad", profile_.skipLoadDllDoLoad);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"skipLoadDllDoNothing", profile_.skipLoadDllDoNothing);
    success &= IniSaveNum(ini_path_.c_str(), profile_name().c_str(), L"advancedInfobar", profile_.advancedInfobar);

    return success;
}








