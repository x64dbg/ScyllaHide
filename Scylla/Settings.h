#pragma once

#include <string>
#include <vector>

namespace Scylla
{
    class Settings
    {
    public:
        struct Profile
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
            int protectProcessId;
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

        static const wchar_t kFileName[];

        void Load(const wchar_t *ini_file);
        bool Save() const;

        bool AddProfile(const wchar_t *name);
        void SetProfile(const wchar_t *name);


        const std::vector<std::wstring> &profile_names() const
        {
            return profile_names_;
        }

        const std::wstring &profile_name() const
        {
            return profile_name_;
        }

        const Profile &opts() const
        {
            return profile_;
        }

        Profile &opts()
        {
            return profile_;
        }

    protected:
        static void LoadProfile(const wchar_t *file, const wchar_t *name, Profile *profile);
        static bool SaveProfile(const wchar_t *file, const wchar_t *name, const Profile *profile);

    private:
        std::wstring ini_path_;
        std::vector<std::wstring> profile_names_;
        std::wstring profile_name_;
        Profile profile_;
    };
}
