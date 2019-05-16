#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace scl
{
    class Settings
    {
    public:
        struct Profile
        {
            BOOL dllNormal;
            BOOL dllStealth;
            BOOL dllUnload;
            BOOL hookGetLocalTime;
            BOOL hookGetSystemTime;
            BOOL hookGetTickCount;
            BOOL hookGetTickCount64;
            BOOL hookKiUserExceptionDispatcher;
            BOOL hookNtClose;
            BOOL hookNtContinue;
            BOOL hookNtCreateThreadEx;
            BOOL hookNtGetContextThread;
            BOOL hookNtQueryInformationProcess;
            BOOL hookNtQueryObject;
            BOOL hookNtQueryPerformanceCounter;
            BOOL hookNtQuerySystemInformation;
            BOOL hookNtQuerySystemTime;
            BOOL hookNtSetContextThread;
            BOOL hookNtSetDebugFilterState;
            BOOL hookNtSetInformationThread;
            BOOL hookNtSetInformationProcess;
            BOOL hookNtUserBlockInput;
            BOOL hookNtUserBuildHwndList;
            BOOL hookNtUserFindWindowEx;
            BOOL hookNtUserQueryWindow;
            BOOL hookNtYieldExecution;
            BOOL hookOutputDebugStringA;
            BOOL fixPebBeingDebugged;
            BOOL fixPebHeapFlags;
            BOOL fixPebNtGlobalFlag;
            BOOL fixPebStartupInfo;
            BOOL preventThreadCreation;
            BOOL protectProcessId;
            BOOL removeDebugPrivileges;
            BOOL killAntiAttach;
            BOOL malwareRunpeUnpacker;
            BOOL handleExceptionPrint;
            BOOL handleExceptionRip;
            BOOL handleExceptionIllegalInstruction;
            BOOL handleExceptionInvalidLockSequence;
            BOOL handleExceptionNoncontinuableException;
            BOOL handleExceptionAssertionFailure;
            BOOL handleExceptionBreakpoint;
            BOOL handleExceptionGuardPageViolation;
            BOOL handleExceptionWx86Breakpoint;
            BOOL idaAutoStartServer;
            std::wstring idaServerPort;
            BOOL ollyBreakOnTls;
            BOOL ollyFixBugs;
            BOOL ollyRemoveEpBreak;
            BOOL ollySkipEpOutsideCode;
            BOOL ollyX64Fix;
            BOOL ollyAdvancedGoto;
            BOOL ollyIgnoreBadPeImage;
            BOOL ollySkipCompressedDoAnalyze;
            BOOL ollySkipCompressedDoNothing;
            BOOL ollySkipLoadDllDoLoad;
            BOOL ollySkipLoadDllDoNothing;
            BOOL ollyAdvancedInfobar;
            std::wstring ollyWindowTitle;
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

        bool hook_dll_needed() const
        {
            return
                profile_.hookGetLocalTime ||
                profile_.hookGetSystemTime ||
                profile_.hookGetTickCount ||
                profile_.hookGetTickCount64 ||
                profile_.hookKiUserExceptionDispatcher ||
                profile_.hookNtClose ||
                profile_.hookNtContinue ||
                profile_.hookNtCreateThreadEx ||
                profile_.hookNtGetContextThread ||
                profile_.hookNtQueryInformationProcess ||
                profile_.hookNtQueryObject ||
                profile_.hookNtQueryPerformanceCounter ||
                profile_.hookNtQuerySystemInformation ||
                profile_.hookNtQuerySystemTime ||
                profile_.hookNtSetContextThread ||
                profile_.hookNtSetDebugFilterState ||
                profile_.hookNtSetInformationThread ||
                profile_.hookNtSetInformationProcess ||
                profile_.hookNtUserBlockInput ||
                profile_.hookNtUserBuildHwndList ||
                profile_.hookNtUserFindWindowEx ||
                profile_.hookNtUserQueryWindow ||
                profile_.hookNtYieldExecution ||
                profile_.hookOutputDebugStringA ||
                profile_.preventThreadCreation ||
                profile_.malwareRunpeUnpacker;
        }

    protected:
        static void LoadProfile(const wchar_t *file, const wchar_t *name, Profile *profile);
        static bool SaveProfile(const wchar_t *file, const wchar_t *name, const Profile *profile);

    private:
        std::wstring ini_path_;
        std::vector<std::wstring> profile_names_;
        std::wstring profile_name_;
        Profile profile_{};
    };
}
