#include "Settings.h"
#include <algorithm>

#include "Util.h"

#define SCYLLA_HIDE_SETTINGS_SECTION                L"SETTINGS"
#define SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY    L"CurrentProfile"
#define SCYLLA_HIDE_SETTINGS_DEFAULT_PROFILE        L"SCYLLA_HIDE"

const wchar_t scl::Settings::kFileName[] = L"scylla_hide.ini";

void scl::Settings::Load(const wchar_t *ini_path)
{
    ini_path_ = ini_path;
    profile_names_ = IniLoadSectionNames(ini_path);
    profile_names_.erase(std::remove(profile_names_.begin(), profile_names_.end(), SCYLLA_HIDE_SETTINGS_SECTION), profile_names_.end());

    profile_name_ = IniLoadString(ini_path, SCYLLA_HIDE_SETTINGS_SECTION, SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY, SCYLLA_HIDE_SETTINGS_DEFAULT_PROFILE);
    LoadProfile(ini_path_.c_str(), profile_name_.c_str(), &profile_);
}

bool scl::Settings::Save() const
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

bool scl::Settings::AddProfile(const wchar_t *name)
{
    if (std::find(profile_names_.begin(), profile_names_.end(), name) != profile_names_.end())
        return false;

    profile_names_.push_back(name);
    return true;
}

void scl::Settings::SetProfile(const wchar_t *name)
{
    if (profile_name_ == name)
        return;

    profile_name_ = name;
    IniSaveString(ini_path_.c_str(), SCYLLA_HIDE_SETTINGS_SECTION, SCYLLA_HIDE_SETTINGS_CURRENT_PROFILE_KEY, name);

    LoadProfile(ini_path_.c_str(), name, &profile_);
}


void scl::Settings::LoadProfile(const wchar_t *file, const wchar_t *name, Profile *profile)
{
    profile->dllNormal = IniLoadNum(file, name, L"DLLNormal", 1);
    profile->dllStealth = IniLoadNum(file, name, L"DLLStealth", 0);
    profile->dllUnload = IniLoadNum(file, name, L"DLLUnload", 0);

    profile->hookGetLocalTime = IniLoadNum(file, name, L"GetLocalTimeHook", 1);
    profile->hookGetSystemTime = IniLoadNum(file, name, L"GetSystemTimeHook", 1);
    profile->hookGetTickCount = IniLoadNum(file, name, L"GetTickCountHook", 1);
    profile->hookGetTickCount64 = IniLoadNum(file, name, L"GetTickCount64Hook", 1);
    profile->hookKiUserExceptionDispatcher = IniLoadNum(file, name, L"KiUserExceptionDispatcherHook", 1);
    profile->hookNtClose = IniLoadNum(file, name, L"NtCloseHook", 1);
    profile->hookNtContinue = IniLoadNum(file, name, L"NtContinueHook", 1);
    profile->hookNtCreateThreadEx = IniLoadNum(file, name, L"NtCreateThreadExHook", 1);
    profile->hookNtGetContextThread = IniLoadNum(file, name, L"NtGetContextThreadHook", 1);
    profile->hookNtQueryInformationProcess = IniLoadNum(file, name, L"NtQueryInformationProcessHook", 1);
    profile->hookNtQueryObject = IniLoadNum(file, name, L"NtQueryObjectHook", 1);
    profile->hookNtQueryPerformanceCounter = IniLoadNum(file, name, L"NtQueryPerformanceCounterHook", 1);
    profile->hookNtQuerySystemInformation = IniLoadNum(file, name, L"NtQuerySystemInformationHook", 1);
    profile->hookNtQuerySystemTime = IniLoadNum(file, name, L"NtQuerySystemTimeHook", 1);
    profile->hookNtSetContextThread = IniLoadNum(file, name, L"NtSetContextThreadHook", 1);
    profile->hookNtSetDebugFilterState = IniLoadNum(file, name, L"NtSetDebugFilterStateHook", 1);
    profile->hookNtSetInformationThread = IniLoadNum(file, name, L"NtSetInformationThreadHook", 1);
    profile->hookNtSetInformationProcess = IniLoadNum(file, name, L"NtSetInformationProcessHook", 1);
    profile->hookNtUserBlockInput = IniLoadNum(file, name, L"NtUserBlockInputHook", 1);
    profile->hookNtUserBuildHwndList = IniLoadNum(file, name, L"NtUserBuildHwndListHook", 1);
    profile->hookNtUserFindWindowEx = IniLoadNum(file, name, L"NtUserFindWindowExHook", 1);
    profile->hookNtUserQueryWindow = IniLoadNum(file, name, L"NtUserQueryWindowHook", 1);
    profile->hookNtYieldExecution = IniLoadNum(file, name, L"NtYieldExecutionHook", 1);
    profile->hookOutputDebugStringA = IniLoadNum(file, name, L"OutputDebugStringHook", 1);

    profile->fixPebBeingDebugged = IniLoadNum(file, name, L"PebBeingDebugged", 1);
    profile->fixPebHeapFlags = IniLoadNum(file, name, L"PebHeapFlags", 1);
    profile->fixPebNtGlobalFlag = IniLoadNum(file, name, L"PebNtGlobalFlag", 1);
    profile->fixPebStartupInfo = IniLoadNum(file, name, L"PebStartupInfo", 1);

    profile->preventThreadCreation = IniLoadNum(file, name, L"PreventThreadCreation", 0);
    profile->protectProcessId = IniLoadNum(file, name, L"ProtectProcessId", 1);
    profile->removeDebugPrivileges = IniLoadNum(file, name, L"RemoveDebugPrivileges", 1);
    profile->killAntiAttach = IniLoadNum(file, name, L"KillAntiAttach", 1);
    profile->malwareRunpeUnpacker = IniLoadNum(file, name, L"MalwareRunPeUnpacker", 0);

    profile->handleExceptionPrint = IniLoadNum(file, name, L"handleExceptionPrint", 1);
    profile->handleExceptionRip = IniLoadNum(file, name, L"handleExceptionRip", 1);
    profile->handleExceptionIllegalInstruction = IniLoadNum(file, name, L"handleExceptionIllegalInstruction", 1);
    profile->handleExceptionInvalidLockSequence = IniLoadNum(file, name, L"handleExceptionInvalidLockSequence", 1);
    profile->handleExceptionNoncontinuableException = IniLoadNum(file, name, L"handleExceptionNoncontinuableException", 1);
    profile->handleExceptionAssertionFailure = IniLoadNum(file, name, L"handleExceptionAssertionFailure", 1);
    profile->handleExceptionBreakpoint = IniLoadNum(file, name, L"handleExceptionBreakpoint", 1);
    profile->handleExceptionGuardPageViolation = IniLoadNum(file, name, L"handleExceptionGuardPageViolation", 1);
    profile->handleExceptionWx86Breakpoint = IniLoadNum(file, name, L"handleExceptionWx86Breakpoint", 1);

    profile->idaAutoStartServer = IniLoadNum(file, name, L"AutostartServer", 1);
    profile->idaServerPort = IniLoadString(file, name, L"ServerPort", L"1337");

    profile->ollyBreakOnTls = IniLoadNum(file, name, L"BreakOnTLS", 1);
    profile->ollyFixBugs = IniLoadNum(file, name, L"FixOllyBugs", 1);
    profile->ollyRemoveEpBreak = IniLoadNum(file, name, L"RemoveEPBreak", 0);
    profile->ollySkipEpOutsideCode = IniLoadNum(file, name, L"SkipEPOutsideCode", 1);
    profile->ollyX64Fix = IniLoadNum(file, name, L"X64Fix", 0);
    profile->ollyAdvancedGoto = IniLoadNum(file, name, L"advancedGoto", 0);
    profile->ollyIgnoreBadPeImage = IniLoadNum(file, name, L"ignoreBadPEImage", 0);
    profile->ollySkipCompressedDoAnalyze = IniLoadNum(file, name, L"skipCompressedDoAnalyze", 0);
    profile->ollySkipCompressedDoNothing = IniLoadNum(file, name, L"skipCompressedDoNothing", 0);
    profile->ollySkipLoadDllDoLoad = IniLoadNum(file, name, L"skipLoadDllDoLoad", 0);
    profile->ollySkipLoadDllDoNothing = IniLoadNum(file, name, L"skipLoadDllDoNothing", 0);
    profile->ollyAdvancedInfobar = IniLoadNum(file, name, L"advancedInfobar", 0);
    profile->ollyWindowTitle = IniLoadString(file, name, L"WindowTitle", L"ScyllaHide");

    if (profile->dllNormal)
        profile->dllStealth = FALSE;
}

bool scl::Settings::SaveProfile(const wchar_t *file, const wchar_t *name, const Profile *profile)
{
    auto success = true;

    success &= IniSaveNum(file, name, L"DLLNormal", profile->dllNormal);
    success &= IniSaveNum(file, name, L"DLLStealth", profile->dllStealth);
    success &= IniSaveNum(file, name, L"DLLUnload", profile->dllUnload);

    success &= IniSaveNum(file, name, L"GetLocalTimeHook", profile->hookGetLocalTime);
    success &= IniSaveNum(file, name, L"GetSystemTimeHook", profile->hookGetSystemTime);
    success &= IniSaveNum(file, name, L"GetTickCount64Hook", profile->hookGetTickCount64);
    success &= IniSaveNum(file, name, L"GetTickCountHook", profile->hookGetTickCount);
    success &= IniSaveNum(file, name, L"KiUserExceptionDispatcherHook", profile->hookKiUserExceptionDispatcher);
    success &= IniSaveNum(file, name, L"NtCloseHook", profile->hookNtClose);
    success &= IniSaveNum(file, name, L"NtContinueHook", profile->hookNtContinue);
    success &= IniSaveNum(file, name, L"NtCreateThreadExHook", profile->hookNtCreateThreadEx);
    success &= IniSaveNum(file, name, L"NtGetContextThreadHook", profile->hookNtGetContextThread);
    success &= IniSaveNum(file, name, L"NtQueryInformationProcessHook", profile->hookNtQueryInformationProcess);
    success &= IniSaveNum(file, name, L"NtQueryObjectHook", profile->hookNtQueryObject);
    success &= IniSaveNum(file, name, L"NtQueryPerformanceCounterHook", profile->hookNtQueryPerformanceCounter);
    success &= IniSaveNum(file, name, L"NtQuerySystemInformationHook", profile->hookNtQuerySystemInformation);
    success &= IniSaveNum(file, name, L"NtQuerySystemTimeHook", profile->hookNtQuerySystemTime);
    success &= IniSaveNum(file, name, L"NtSetContextThreadHook", profile->hookNtSetContextThread);
    success &= IniSaveNum(file, name, L"NtSetDebugFilterStateHook", profile->hookNtSetDebugFilterState);
    success &= IniSaveNum(file, name, L"NtSetInformationThreadHook", profile->hookNtSetInformationThread);
    success &= IniSaveNum(file, name, L"NtSetInformationProcessHook", profile->hookNtSetInformationProcess);
    success &= IniSaveNum(file, name, L"NtUserBlockInputHook", profile->hookNtUserBlockInput);
    success &= IniSaveNum(file, name, L"NtUserBuildHwndListHook", profile->hookNtUserBuildHwndList);
    success &= IniSaveNum(file, name, L"NtUserFindWindowExHook", profile->hookNtUserFindWindowEx);
    success &= IniSaveNum(file, name, L"NtUserQueryWindowHook", profile->hookNtUserQueryWindow);
    success &= IniSaveNum(file, name, L"NtYieldExecutionHook", profile->hookNtYieldExecution);
    success &= IniSaveNum(file, name, L"OutputDebugStringHook", profile->hookOutputDebugStringA);

    success &= IniSaveNum(file, name, L"PebBeingDebugged", profile->fixPebBeingDebugged);
    success &= IniSaveNum(file, name, L"PebHeapFlags", profile->fixPebHeapFlags);
    success &= IniSaveNum(file, name, L"PebNtGlobalFlag", profile->fixPebNtGlobalFlag);
    success &= IniSaveNum(file, name, L"PebStartupInfo", profile->fixPebStartupInfo);
    success &= IniSaveNum(file, name, L"PreventThreadCreation", profile->preventThreadCreation);
    success &= IniSaveNum(file, name, L"ProtectProcessId", profile->protectProcessId);
    success &= IniSaveNum(file, name, L"RemoveDebugPrivileges", profile->removeDebugPrivileges);
    success &= IniSaveNum(file, name, L"KillAntiAttach", profile->killAntiAttach);
    success &= IniSaveNum(file, name, L"MalwareRunPeUnpacker", profile->malwareRunpeUnpacker);

    success &= IniSaveNum(file, name, L"handleExceptionPrint", profile->handleExceptionPrint);
    success &= IniSaveNum(file, name, L"handleExceptionRip", profile->handleExceptionRip);
    success &= IniSaveNum(file, name, L"handleExceptionIllegalInstruction", profile->handleExceptionIllegalInstruction);
    success &= IniSaveNum(file, name, L"handleExceptionInvalidLockSequence", profile->handleExceptionInvalidLockSequence);
    success &= IniSaveNum(file, name, L"handleExceptionNoncontinuableException", profile->handleExceptionNoncontinuableException);
    success &= IniSaveNum(file, name, L"handleExceptionAssertionFailure", profile->handleExceptionAssertionFailure);
    success &= IniSaveNum(file, name, L"handleExceptionBreakpoint", profile->handleExceptionBreakpoint);
    success &= IniSaveNum(file, name, L"handleExceptionGuardPageViolation", profile->handleExceptionGuardPageViolation);
    success &= IniSaveNum(file, name, L"handleExceptionWx86Breakpoint", profile->handleExceptionWx86Breakpoint);

    success &= IniSaveNum(file, name, L"AutostartServer", profile->idaAutoStartServer);
    success &= IniSaveString(file, name, L"ServerPort", profile->idaServerPort.c_str());

    success &= IniSaveNum(file, name, L"BreakOnTls", profile->ollyBreakOnTls);
    success &= IniSaveNum(file, name, L"FixOllyBugs", profile->ollyFixBugs);
    success &= IniSaveNum(file, name, L"RemoveEPBreak", profile->ollyRemoveEpBreak);
    success &= IniSaveNum(file, name, L"SkipEPOutsideCode", profile->ollySkipEpOutsideCode);
    success &= IniSaveNum(file, name, L"X64Fix", profile->ollyX64Fix);
    success &= IniSaveNum(file, name, L"advancedGoto", profile->ollyAdvancedGoto);
    success &= IniSaveNum(file, name, L"ignoreBadPEImage", profile->ollyIgnoreBadPeImage);
    success &= IniSaveNum(file, name, L"skipCompressedDoAnalyze", profile->ollySkipCompressedDoAnalyze);
    success &= IniSaveNum(file, name, L"skipCompressedDoNothing", profile->ollySkipCompressedDoNothing);
    success &= IniSaveNum(file, name, L"skipLoadDllDoLoad", profile->ollySkipLoadDllDoLoad);
    success &= IniSaveNum(file, name, L"skipLoadDllDoNothing", profile->ollySkipLoadDllDoNothing);
    success &= IniSaveNum(file, name, L"advancedInfobar", profile->ollyAdvancedInfobar);
    success &= IniSaveString(file, name, L"WindowTitle", profile->ollyWindowTitle.c_str());

    return success;
}
