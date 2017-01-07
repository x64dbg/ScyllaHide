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
    LoadProfile(ini_path_.c_str(), profile_name_.c_str(), &profile_);
}

bool Scylla::Settings::Save() const
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

    return SaveProfile(ini_path_.c_str(), profile_name_.c_str(), &profile_);
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

    LoadProfile(ini_path_.c_str(), name, &profile_);
}


void Scylla::Settings::LoadProfile(const wchar_t *file, const wchar_t *name, Profile *profile)
{
    profile->BlockInput = IniLoadNum(file, name, L"BlockInputHook", 1);
    profile->DLLNormal = IniLoadNum(file, name, L"DLLNormal", 1);
    profile->DLLStealth = IniLoadNum(file, name, L"DLLStealth", 0);
    profile->DLLUnload = IniLoadNum(file, name, L"DLLUnload", 1);
    profile->GetLocalTime = IniLoadNum(file, name, L"GetLocalTimeHook", 1);
    profile->GetSystemTime = IniLoadNum(file, name, L"GetSystemTimeHook", 1);
    profile->GetTickCount = IniLoadNum(file, name, L"GetTickCountHook", 1);
    profile->GetTickCount64 = IniLoadNum(file, name, L"GetTickCount64Hook", 1);
    profile->KiUserExceptionDispatcher = IniLoadNum(file, name, L"KiUserExceptionDispatcherHook", 1);
    profile->NtClose = IniLoadNum(file, name, L"NtCloseHook", 1);
    profile->NtContinue = IniLoadNum(file, name, L"NtContinueHook", 1);
    profile->NtCreateThreadEx = IniLoadNum(file, name, L"NtCreateThreadExHook", 1);
    profile->NtGetContextThread = IniLoadNum(file, name, L"NtGetContextThreadHook", 1);
    profile->NtQueryInformationProcess = IniLoadNum(file, name, L"NtQueryInformationProcessHook", 1);
    profile->NtQueryObject = IniLoadNum(file, name, L"NtQueryObjectHook", 1);
    profile->NtQueryPerformanceCounter = IniLoadNum(file, name, L"NtQueryPerformanceCounterHook", 1);
    profile->NtQuerySystemInformation = IniLoadNum(file, name, L"NtQuerySystemInformationHook", 1);
    profile->NtQuerySystemTime = IniLoadNum(file, name, L"NtQuerySystemTimeHook", 1);
    profile->NtSetContextThread = IniLoadNum(file, name, L"NtSetContextThreadHook", 1);
    profile->NtSetDebugFilterState = IniLoadNum(file, name, L"NtSetDebugFilterStateHook", 1);
    profile->NtSetInformationThread = IniLoadNum(file, name, L"NtSetInformationThreadHook", 1);
    profile->NtSetInformationProcess = IniLoadNum(file, name, L"NtSetInformationProcessHook", 1);
    profile->NtUserBuildHwndList = IniLoadNum(file, name, L"NtUserBuildHwndListHook", 1);
    profile->NtUserFindWindowEx = IniLoadNum(file, name, L"NtUserFindWindowExHook", 1);
    profile->NtUserQueryWindow = IniLoadNum(file, name, L"NtUserQueryWindowHook", 1);
    profile->NtYieldExecution = IniLoadNum(file, name, L"NtYieldExecutionHook", 1);
    profile->OutputDebugStringA = IniLoadNum(file, name, L"OutputDebugStringHook", 1);
    profile->PEBBeingDebugged = IniLoadNum(file, name, L"PebBeingDebugged", 1);
    profile->PEBHeapFlags = IniLoadNum(file, name, L"PebHeapFlags", 1);
    profile->PEBNtGlobalFlag = IniLoadNum(file, name, L"PebNtGlobalFlag", 1);
    profile->PEBStartupInfo = IniLoadNum(file, name, L"PebStartupInfo", 1);
    profile->preventThreadCreation = IniLoadNum(file, name, L"PreventThreadCreation", 0);
    profile->protectProcessId = IniLoadNum(file, name, L"ProtectProcessId", 1);
    profile->removeDebugPrivileges = IniLoadNum(file, name, L"RemoveDebugPrivileges", 1);
    profile->killAntiAttach = IniLoadNum(file, name, L"KillAntiAttach", 1);

    profile->handleExceptionPrint = IniLoadNum(file, name, L"handleExceptionPrint", 1);
    profile->handleExceptionRip = IniLoadNum(file, name, L"handleExceptionRip", 1);
    profile->handleExceptionIllegalInstruction = IniLoadNum(file, name, L"handleExceptionIllegalInstruction", 1);
    profile->handleExceptionInvalidLockSequence = IniLoadNum(file, name, L"handleExceptionInvalidLockSequence", 1);
    profile->handleExceptionNoncontinuableException = IniLoadNum(file, name, L"handleExceptionNoncontinuableException", 1);
    profile->handleExceptionAssertionFailure = IniLoadNum(file, name, L"handleExceptionAssertionFailure", 1);
    profile->handleExceptionBreakpoint = IniLoadNum(file, name, L"handleExceptionBreakpoint", 1);
    profile->handleExceptionGuardPageViolation = IniLoadNum(file, name, L"handleExceptionGuardPageViolation", 1);
    profile->handleExceptionWx86Breakpoint = IniLoadNum(file, name, L"handleExceptionWx86Breakpoint", 1);

    if (profile->DLLNormal)
        profile->DLLStealth = 0;

    //ida specific
    profile->autostartServer = IniLoadNum(file, name, L"AutostartServer", 1);
    profile->serverPort = IniLoadString(file, name, L"ServerPort", L"1337");

    //olly1 specific
    profile->breakTLS = IniLoadNum(file, name, L"BreakOnTLS", 1);
    profile->fixOllyBugs = IniLoadNum(file, name, L"FixOllyBugs", 1);
    profile->removeEPBreak = IniLoadNum(file, name, L"RemoveEPBreak", 0);
    profile->skipEPOutsideCode = IniLoadNum(file, name, L"SkipEPOutsideCode", 1);
    profile->x64Fix = IniLoadNum(file, name, L"X64Fix", 0);
    profile->advancedGoto = IniLoadNum(file, name, L"advancedGoto", 0);
    profile->ignoreBadPEImage = IniLoadNum(file, name, L"ignoreBadPEImage", 0);
    profile->skipCompressedDoAnalyze = IniLoadNum(file, name, L"skipCompressedDoAnalyze", 0);
    profile->skipCompressedDoNothing = IniLoadNum(file, name, L"skipCompressedDoNothing", 0);
    profile->skipLoadDllDoLoad = IniLoadNum(file, name, L"skipLoadDllDoLoad", 0);
    profile->skipLoadDllDoNothing = IniLoadNum(file, name, L"skipLoadDllDoNothing", 0);
    profile->advancedInfobar = IniLoadNum(file, name, L"advancedInfobar", 0);
    profile->ollyTitle = IniLoadString(file, name, L"WindowTitle", L"ScyllaHide");
}

bool Scylla::Settings::SaveProfile(const wchar_t *file, const wchar_t *name, const Profile *profile)
{
    auto success = true;
    success &= IniSaveNum(file, name, L"BlockInputHook", profile->BlockInput);
    success &= IniSaveNum(file, name, L"DLLNormal", profile->DLLNormal);
    success &= IniSaveNum(file, name, L"DLLStealth", profile->DLLStealth);
    success &= IniSaveNum(file, name, L"DLLUnload", profile->DLLUnload);
    success &= IniSaveNum(file, name, L"GetLocalTimeHook", profile->GetLocalTime);
    success &= IniSaveNum(file, name, L"GetSystemTimeHook", profile->GetSystemTime);
    success &= IniSaveNum(file, name, L"GetTickCount64Hook", profile->GetTickCount64);
    success &= IniSaveNum(file, name, L"GetTickCountHook", profile->GetTickCount);
    success &= IniSaveNum(file, name, L"KiUserExceptionDispatcherHook", profile->KiUserExceptionDispatcher);
    success &= IniSaveNum(file, name, L"NtCloseHook", profile->NtClose);
    success &= IniSaveNum(file, name, L"NtContinueHook", profile->NtContinue);
    success &= IniSaveNum(file, name, L"NtCreateThreadExHook", profile->NtCreateThreadEx);
    success &= IniSaveNum(file, name, L"NtGetContextThreadHook", profile->NtGetContextThread);
    success &= IniSaveNum(file, name, L"NtQueryInformationProcessHook", profile->NtQueryInformationProcess);
    success &= IniSaveNum(file, name, L"NtQueryObjectHook", profile->NtQueryObject);
    success &= IniSaveNum(file, name, L"NtQueryPerformanceCounterHook", profile->NtQueryPerformanceCounter);
    success &= IniSaveNum(file, name, L"NtQuerySystemInformationHook", profile->NtQuerySystemInformation);
    success &= IniSaveNum(file, name, L"NtQuerySystemTimeHook", profile->NtQuerySystemTime);
    success &= IniSaveNum(file, name, L"NtSetContextThreadHook", profile->NtSetContextThread);
    success &= IniSaveNum(file, name, L"NtSetDebugFilterStateHook", profile->NtSetDebugFilterState);
    success &= IniSaveNum(file, name, L"NtSetInformationThreadHook", profile->NtSetInformationThread);
    success &= IniSaveNum(file, name, L"NtSetInformationProcessHook", profile->NtSetInformationProcess);
    success &= IniSaveNum(file, name, L"NtUserBuildHwndListHook", profile->NtUserBuildHwndList);
    success &= IniSaveNum(file, name, L"NtUserFindWindowExHook", profile->NtUserFindWindowEx);
    success &= IniSaveNum(file, name, L"NtUserQueryWindowHook", profile->NtUserQueryWindow);
    success &= IniSaveNum(file, name, L"NtYieldExecutionHook", profile->NtYieldExecution);
    success &= IniSaveNum(file, name, L"OutputDebugStringHook", profile->OutputDebugStringA);
    success &= IniSaveNum(file, name, L"PebBeingDebugged", profile->PEBBeingDebugged);
    success &= IniSaveNum(file, name, L"PebHeapFlags", profile->PEBHeapFlags);
    success &= IniSaveNum(file, name, L"PebNtGlobalFlag", profile->PEBNtGlobalFlag);
    success &= IniSaveNum(file, name, L"PebStartupInfo", profile->PEBStartupInfo);
    success &= IniSaveNum(file, name, L"PreventThreadCreation", profile->preventThreadCreation);
    success &= IniSaveNum(file, name, L"ProtectProcessId", profile->protectProcessId);
    success &= IniSaveNum(file, name, L"RemoveDebugPrivileges", profile->removeDebugPrivileges);
    success &= IniSaveNum(file, name, L"KillAntiAttach", profile->killAntiAttach);

    success &= IniSaveNum(file, name, L"handleExceptionPrint", profile->handleExceptionPrint);
    success &= IniSaveNum(file, name, L"handleExceptionRip", profile->handleExceptionRip);
    success &= IniSaveNum(file, name, L"handleExceptionIllegalInstruction", profile->handleExceptionIllegalInstruction);
    success &= IniSaveNum(file, name, L"handleExceptionInvalidLockSequence", profile->handleExceptionInvalidLockSequence);
    success &= IniSaveNum(file, name, L"handleExceptionNoncontinuableException", profile->handleExceptionNoncontinuableException);
    success &= IniSaveNum(file, name, L"handleExceptionAssertionFailure", profile->handleExceptionAssertionFailure);
    success &= IniSaveNum(file, name, L"handleExceptionBreakpoint", profile->handleExceptionBreakpoint);
    success &= IniSaveNum(file, name, L"handleExceptionGuardPageViolation", profile->handleExceptionGuardPageViolation);
    success &= IniSaveNum(file, name, L"handleExceptionWx86Breakpoint", profile->handleExceptionWx86Breakpoint);

    //ida specific
    success &= IniSaveNum(file, name, L"AutostartServer", profile->autostartServer);
    success &= IniSaveString(file, name, L"ServerPort", profile->serverPort.c_str());

    //olly1 specific
    success &= IniSaveNum(file, name, L"BreakOnTLS", profile->breakTLS);
    success &= IniSaveNum(file, name, L"FixOllyBugs", profile->fixOllyBugs);
    success &= IniSaveNum(file, name, L"RemoveEPBreak", profile->removeEPBreak);
    success &= IniSaveNum(file, name, L"SkipEPOutsideCode", profile->skipEPOutsideCode);
    success &= IniSaveNum(file, name, L"X64Fix", profile->x64Fix);
    success &= IniSaveString(file, name, L"WindowTitle", profile->ollyTitle.c_str());
    success &= IniSaveNum(file, name, L"advancedGoto", profile->advancedGoto);
    success &= IniSaveNum(file, name, L"ignoreBadPEImage", profile->ignoreBadPEImage);
    success &= IniSaveNum(file, name, L"skipCompressedDoAnalyze", profile->skipCompressedDoAnalyze);
    success &= IniSaveNum(file, name, L"skipCompressedDoNothing", profile->skipCompressedDoNothing);
    success &= IniSaveNum(file, name, L"skipLoadDllDoLoad", profile->skipLoadDllDoLoad);
    success &= IniSaveNum(file, name, L"skipLoadDllDoNothing", profile->skipLoadDllDoNothing);
    success &= IniSaveNum(file, name, L"advancedInfobar", profile->advancedInfobar);

    return success;
}
