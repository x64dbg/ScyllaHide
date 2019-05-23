#include "OptionsDialog.h"
#include <CommCtrl.h>
#include <codecvt>
#include <locale>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>
#include <Scylla/Version.h>

#include "..\PluginGeneric\Injector.h"

#ifdef OLLY1
#pragma pack(push)
#include <ollydbg1/ollyplugindefinitions.h>
#pragma pack(pop)
#include "..\ScyllaHideOlly1Plugin\resource.h"

#elif defined(OLLY2)
#pragma pack(push)
#include <ollydbg2/plugin.h>
#pragma pack(pop)
#include "..\ScyllaHideOlly2Plugin\resource.h"

#elif defined(__IDP__)
//#define BUILD_IDA_64BIT 1
#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include "..\ScyllaHideIDAProPlugin\IdaServerClient.h"
#include "..\PluginGeneric\AttachDialog.h"
#include "..\ScyllaHideIDAProPlugin\resource.h"

#elif defined(X64DBG)
#include <x64dbg/bridgemain.h>
#include "..\ScyllaHideX64DBGPlugin\resource.h"
#define IDC_EXCEPTION_ALL 123432
#define IDC_SELECT_EXCEPTIONS 23949
#endif

#define SCYLLA_MAX_TOOLTIP_WIDTH    500

extern scl::Settings g_settings;
extern HOOK_DLL_DATA g_hdd;

extern std::wstring g_scyllaHideDllPath;
extern DWORD ProcessId;
extern bool bHooked;

#ifdef OLLY1
extern HWND hwmain;

#elif defined(__IDP__)
extern HINSTANCE hinst;
wchar_t DllPathForInjection[MAX_PATH] = { 0 };
#endif

void createExceptionWindow(HWND hwnd);

static void UpdateOptionsExceptions(HWND hWnd, const scl::Settings *settings)
{
    auto opts = &settings->opts();

#ifdef OLLY1
    auto check = opts->handleExceptionIllegalInstruction &&
        opts->handleExceptionInvalidLockSequence &&
        opts->handleExceptionNoncontinuableException &&
        opts->handleExceptionPrint &&
        opts->handleExceptionRip &&
        opts->handleExceptionBreakpoint &&
        opts->handleExceptionWx86Breakpoint &&
        opts->handleExceptionGuardPageViolation;
#elif defined(OLLY2)
    auto check = opts->handleExceptionNoncontinuableException &&
        opts->handleExceptionPrint &&
        opts->handleExceptionRip;

#elif defined(__IDP__)
    auto check = opts->handleExceptionNoncontinuableException &&
        opts->handleExceptionPrint &&
        opts->handleExceptionAssertionFailure &&
        opts->handleExceptionRip;

#elif defined(X64DBG)
    auto check = true;
#endif

    CheckDlgButton(hWnd, IDC_EXCEPTION_ALL, check ? BST_CHECKED : BST_UNCHECKED);
}

static void UpdateOptions(HWND hWnd, const scl::Settings *settings)
{
    auto opts = &settings->opts();

    CheckDlgButton(hWnd, IDC_PEBBEINGDEBUGGED, opts->fixPebBeingDebugged);
    CheckDlgButton(hWnd, IDC_PEBHEAPFLAGS, opts->fixPebHeapFlags);
    CheckDlgButton(hWnd, IDC_PEBNTGLOBALFLAG, opts->fixPebNtGlobalFlag);
    CheckDlgButton(hWnd, IDC_PEBSTARTUPINFO, opts->fixPebStartupInfo);

    BOOL peb_state = opts->fixPebBeingDebugged && opts->fixPebHeapFlags && opts->fixPebNtGlobalFlag && opts->fixPebStartupInfo;
    CheckDlgButton(hWnd, IDC_PEB, peb_state);

    CheckDlgButton(hWnd, IDC_NTSETINFORMATIONTHREAD, opts->hookNtSetInformationThread);
    CheckDlgButton(hWnd, IDC_NTSETINFORMATIONPROCESS, opts->hookNtSetInformationProcess);
    CheckDlgButton(hWnd, IDC_NTQUERYSYSTEMINFORMATION, opts->hookNtQuerySystemInformation);
    CheckDlgButton(hWnd, IDC_NTQUERYINFORMATIONPROCESS, opts->hookNtQueryInformationProcess);
    CheckDlgButton(hWnd, IDC_NTQUERYOBJECT, opts->hookNtQueryObject);
    CheckDlgButton(hWnd, IDC_NTYIELDEXECUTION, opts->hookNtYieldExecution);
    CheckDlgButton(hWnd, IDC_OUTPUTDEBUGSTRINGA, opts->hookOutputDebugStringA);
    CheckDlgButton(hWnd, IDC_NTGETCONTEXTTHREAD, opts->hookNtGetContextThread);
    CheckDlgButton(hWnd, IDC_NTSETCONTEXTTHREAD, opts->hookNtSetContextThread);
    CheckDlgButton(hWnd, IDC_NTCONTINUE, opts->hookNtContinue);
    CheckDlgButton(hWnd, IDC_KIUED, opts->hookKiUserExceptionDispatcher);

    BOOL drx_state = opts->hookNtGetContextThread && opts->hookNtSetContextThread && opts->hookNtContinue && opts->hookKiUserExceptionDispatcher;
    CheckDlgButton(hWnd, IDC_PROTECTDRX, drx_state);

    CheckDlgButton(hWnd, IDC_NTUSERBLOCKINPUT, opts->hookNtUserBlockInput);
    CheckDlgButton(hWnd, IDC_NTUSERFINDWINDOWEX, opts->hookNtUserFindWindowEx);
    CheckDlgButton(hWnd, IDC_NTUSERBUILDHWNDLIST, opts->hookNtUserBuildHwndList);
    CheckDlgButton(hWnd, IDC_NTUSERQUERYWINDOW, opts->hookNtUserQueryWindow);
    CheckDlgButton(hWnd, IDC_NTSETDEBUGFILTERSTATE, opts->hookNtSetDebugFilterState);
    CheckDlgButton(hWnd, IDC_NTCLOSE, opts->hookNtClose);
    CheckDlgButton(hWnd, IDC_NTCREATETHREADEX, opts->hookNtCreateThreadEx);
    CheckDlgButton(hWnd, IDC_REMOVEDEBUGPRIV, opts->removeDebugPrivileges);
    CheckDlgButton(hWnd, IDC_PREVENTTHREADCREATION, opts->preventThreadCreation);
    CheckDlgButton(hWnd, IDC_RUNPE, opts->malwareRunpeUnpacker);
    CheckDlgButton(hWnd, IDC_DLLSTEALTH, opts->dllStealth);
    CheckDlgButton(hWnd, IDC_DLLNORMAL, opts->dllNormal);
    CheckDlgButton(hWnd, IDC_DLLUNLOAD, opts->dllUnload);
    CheckDlgButton(hWnd, IDC_GETTICKCOUNT, opts->hookGetTickCount);
    CheckDlgButton(hWnd, IDC_GETTICKCOUNT64, opts->hookGetTickCount64);
    CheckDlgButton(hWnd, IDC_GETLOCALTIME, opts->hookGetLocalTime);
    CheckDlgButton(hWnd, IDC_GETSYSTEMTIME, opts->hookGetSystemTime);
    CheckDlgButton(hWnd, IDC_NTQUERYSYSTEMTIME, opts->hookNtQuerySystemTime);
    CheckDlgButton(hWnd, IDC_NTQUERYPERFCOUNTER, opts->hookNtQueryPerformanceCounter);
    CheckDlgButton(hWnd, IDC_KILLANTIATTACH, opts->killAntiAttach);

#ifdef OLLY1
    SetDlgItemTextW(hWnd, IDC_OLLYTITLE, opts->ollyWindowTitle.c_str());
    CheckDlgButton(hWnd, IDC_DELEPBREAK, opts->ollyRemoveEpBreak);
    CheckDlgButton(hWnd, IDC_FIXOLLY, opts->ollyFixBugs);
    CheckDlgButton(hWnd, IDC_X64FIX, opts->ollyX64Fix);
    CheckDlgButton(hWnd, IDC_SKIPEPOUTSIDE, opts->ollySkipEpOutsideCode);
    CheckDlgButton(hWnd, IDC_BREAKTLS, opts->ollyBreakOnTls);

    auto skip_compressed_state = opts->ollySkipCompressedDoAnalyze || opts->ollySkipCompressedDoNothing;
    CheckDlgButton(hWnd, IDC_COMPRESSED, skip_compressed_state);
    EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), skip_compressed_state);
    EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), skip_compressed_state);

    CheckDlgButton(hWnd, IDC_COMPRESSEDANALYZE, opts->ollySkipCompressedDoAnalyze);
    CheckDlgButton(hWnd, IDC_COMPRESSEDNOTHING, opts->ollySkipCompressedDoNothing);

    auto skip_load_state = opts->ollySkipLoadDllDoLoad || opts->ollySkipLoadDllDoNothing;
    CheckDlgButton(hWnd, IDC_LOADDLL, skip_load_state);
    EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLLOAD), skip_load_state);
    EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), skip_load_state);

    CheckDlgButton(hWnd, IDC_LOADDLLLOAD, opts->ollySkipLoadDllDoLoad);
    CheckDlgButton(hWnd, IDC_LOADDLLNOTHING, opts->ollySkipLoadDllDoNothing);

    CheckDlgButton(hWnd, IDC_ADVANCEDGOTO, opts->ollyAdvancedGoto);
    CheckDlgButton(hWnd, IDC_BADPEIMAGE, opts->ollyIgnoreBadPeImage);
    CheckDlgButton(hWnd, IDC_ADVANCEDINFOBAR, opts->ollyAdvancedInfobar);
    EnableWindow(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), FALSE);

#elif defined(OLLY2)
    SetDlgItemTextW(hWnd, IDC_OLLYTITLE, opts->ollyWindowTitle.c_str());

#elif defined(__IDP__)
    CheckDlgButton(hWnd, IDC_AUTOSTARTSERVER, opts->idaAutoStartServer);
    SetDlgItemTextW(hWnd, IDC_SERVERPORT, opts->idaServerPort.c_str());

#ifdef BUILD_IDA_64BIT
    EnableWindow(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), scl::IsWindows64());
#else
    EnableWindow(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), FALSE);
#endif

    EnableWindow(GetDlgItem(hWnd, IDC_INJECTDLL), (!!ProcessId));
#endif

    UpdateOptionsExceptions(hWnd, settings);
}

void SaveOptions(HWND hWnd, scl::Settings *settings)
{
    auto opts = &settings->opts();

    opts->fixPebBeingDebugged = (IsDlgButtonChecked(hWnd, IDC_PEBBEINGDEBUGGED) == BST_CHECKED);
    opts->fixPebHeapFlags = (IsDlgButtonChecked(hWnd, IDC_PEBHEAPFLAGS) == BST_CHECKED);
    opts->fixPebNtGlobalFlag = (IsDlgButtonChecked(hWnd, IDC_PEBNTGLOBALFLAG) == BST_CHECKED);
    opts->fixPebStartupInfo = (IsDlgButtonChecked(hWnd, IDC_PEBSTARTUPINFO) == BST_CHECKED);
    opts->hookNtSetInformationThread = (IsDlgButtonChecked(hWnd, IDC_NTSETINFORMATIONTHREAD) == BST_CHECKED);
    opts->hookNtSetInformationProcess = (IsDlgButtonChecked(hWnd, IDC_NTSETINFORMATIONPROCESS) == BST_CHECKED);
    opts->hookNtQuerySystemInformation = (IsDlgButtonChecked(hWnd, IDC_NTQUERYSYSTEMINFORMATION) == BST_CHECKED);
    opts->hookNtQueryInformationProcess = (IsDlgButtonChecked(hWnd, IDC_NTQUERYINFORMATIONPROCESS) == BST_CHECKED);
    opts->hookNtQueryObject = (IsDlgButtonChecked(hWnd, IDC_NTQUERYOBJECT) == BST_CHECKED);
    opts->hookNtYieldExecution = (IsDlgButtonChecked(hWnd, IDC_NTYIELDEXECUTION) == BST_CHECKED);
    opts->hookOutputDebugStringA = (IsDlgButtonChecked(hWnd, IDC_OUTPUTDEBUGSTRINGA) == BST_CHECKED);
    opts->hookNtGetContextThread = (IsDlgButtonChecked(hWnd, IDC_NTGETCONTEXTTHREAD) == BST_CHECKED);
    opts->hookNtSetContextThread = (IsDlgButtonChecked(hWnd, IDC_NTSETCONTEXTTHREAD) == BST_CHECKED);
    opts->hookNtContinue = (IsDlgButtonChecked(hWnd, IDC_NTCONTINUE) == BST_CHECKED);
    opts->hookKiUserExceptionDispatcher = (IsDlgButtonChecked(hWnd, IDC_KIUED) == BST_CHECKED);
    opts->hookNtUserFindWindowEx = (IsDlgButtonChecked(hWnd, IDC_NTUSERFINDWINDOWEX) == BST_CHECKED);
    opts->hookNtUserBlockInput = (IsDlgButtonChecked(hWnd, IDC_NTUSERBLOCKINPUT) == BST_CHECKED);
    opts->hookNtUserBuildHwndList = (IsDlgButtonChecked(hWnd, IDC_NTUSERBUILDHWNDLIST) == BST_CHECKED);
    opts->hookNtUserQueryWindow = (IsDlgButtonChecked(hWnd, IDC_NTUSERQUERYWINDOW) == BST_CHECKED);
    opts->hookNtSetDebugFilterState = (IsDlgButtonChecked(hWnd, IDC_NTSETDEBUGFILTERSTATE) == BST_CHECKED);
    opts->hookNtClose = (IsDlgButtonChecked(hWnd, IDC_NTCLOSE) == BST_CHECKED);
    opts->hookNtCreateThreadEx = (IsDlgButtonChecked(hWnd, IDC_NTCREATETHREADEX) == BST_CHECKED);
    opts->preventThreadCreation = (IsDlgButtonChecked(hWnd, IDC_PREVENTTHREADCREATION) == BST_CHECKED);
    opts->malwareRunpeUnpacker = (IsDlgButtonChecked(hWnd, IDC_RUNPE) == BST_CHECKED);
    opts->removeDebugPrivileges = (IsDlgButtonChecked(hWnd, IDC_REMOVEDEBUGPRIV) == BST_CHECKED);
    opts->dllStealth = (IsDlgButtonChecked(hWnd, IDC_DLLSTEALTH) == BST_CHECKED);
    opts->dllNormal = (IsDlgButtonChecked(hWnd, IDC_DLLNORMAL) == BST_CHECKED);
    opts->dllUnload = (IsDlgButtonChecked(hWnd, IDC_DLLUNLOAD) == BST_CHECKED);
    opts->hookGetTickCount = (IsDlgButtonChecked(hWnd, IDC_GETTICKCOUNT) == BST_CHECKED);
    opts->hookGetTickCount64 = (IsDlgButtonChecked(hWnd, IDC_GETTICKCOUNT64) == BST_CHECKED);
    opts->hookGetLocalTime = (IsDlgButtonChecked(hWnd, IDC_GETLOCALTIME) == BST_CHECKED);
    opts->hookGetSystemTime = (IsDlgButtonChecked(hWnd, IDC_GETSYSTEMTIME) == BST_CHECKED);
    opts->hookNtQuerySystemTime = (IsDlgButtonChecked(hWnd, IDC_NTQUERYSYSTEMTIME) == BST_CHECKED);
    opts->hookNtQueryPerformanceCounter = (IsDlgButtonChecked(hWnd, IDC_NTQUERYPERFCOUNTER) == BST_CHECKED);
    opts->killAntiAttach = (IsDlgButtonChecked(hWnd, IDC_KILLANTIATTACH) == BST_CHECKED);

#ifdef OLLY1
    opts->ollyRemoveEpBreak = (IsDlgButtonChecked(hWnd, IDC_DELEPBREAK) == BST_CHECKED);
    opts->ollyFixBugs = (IsDlgButtonChecked(hWnd, IDC_FIXOLLY) == BST_CHECKED);
    opts->ollyX64Fix = (IsDlgButtonChecked(hWnd, IDC_X64FIX) == BST_CHECKED);
    opts->ollyBreakOnTls = (IsDlgButtonChecked(hWnd, IDC_BREAKTLS) == BST_CHECKED);
    opts->ollySkipEpOutsideCode = (IsDlgButtonChecked(hWnd, IDC_SKIPEPOUTSIDE) == BST_CHECKED);
    opts->ollyIgnoreBadPeImage = (IsDlgButtonChecked(hWnd, IDC_BADPEIMAGE) == BST_CHECKED);
    opts->ollyAdvancedGoto = (IsDlgButtonChecked(hWnd, IDC_ADVANCEDGOTO) == BST_CHECKED);
    opts->ollySkipCompressedDoAnalyze = (IsDlgButtonChecked(hWnd, IDC_COMPRESSEDANALYZE) == BST_CHECKED);
    opts->ollySkipCompressedDoNothing = (IsDlgButtonChecked(hWnd, IDC_COMPRESSEDNOTHING) == BST_CHECKED);
    opts->ollySkipLoadDllDoLoad = (IsDlgButtonChecked(hWnd, IDC_LOADDLLLOAD) == BST_CHECKED);
    opts->ollySkipLoadDllDoNothing = (IsDlgButtonChecked(hWnd, IDC_LOADDLLNOTHING) == BST_CHECKED);
    opts->ollyAdvancedInfobar = (IsDlgButtonChecked(hWnd, IDC_ADVANCEDINFOBAR) == BST_CHECKED);

    opts->ollyWindowTitle = scl::GetDlgItemTextW(hWnd, IDC_OLLYTITLE);
    SetWindowTextW(hwmain, opts->ollyWindowTitle.c_str());

#elif defined(OLLY2)
    opts->ollyWindowTitle = scl::GetDlgItemTextW(hWnd, IDC_OLLYTITLE);
    SetWindowTextW(hwollymain, opts->ollyWindowTitle.c_str());

#elif defined(__IDP__)
    opts->idaAutoStartServer = (IsDlgButtonChecked(hWnd, IDC_AUTOSTARTSERVER) == BST_CHECKED);
    opts->idaServerPort = scl::GetDlgItemTextW(hWnd, IDC_SERVERPORT);
#endif

    settings->Save();
}

HWND CreateTooltips(HWND hDlg)
{
    static const struct
    {
        unsigned ctrl_id;
        const wchar_t *text;
    } ctrl_tips[] = {
        { IDOK, L"Apply Settings and close the dialog" },
        { IDC_PROFILES, L"Select profile" },
        { IDC_SAVEPROFILE, L"Save profile" },
        {
            IDC_PEB,
            L"The most important anti-anti-debug option.\r\n"
            L"Almost every protector checks for PEB values.\r\n"
            L"There are three important options and one minor option."
        },
        {
            IDC_PEBBEINGDEBUGGED,
            L"Very important option, should be always enabled.\r\n"
            L"IsDebuggerPresent is using this value to check for debuggers."
        },
        { IDC_PEBHEAPFLAGS, L"Very important option, a lot of protectors check for this value." },
        { IDC_PEBNTGLOBALFLAG, L"Very important option. E.g. Themida checks for heap artifacts and heap flags." },
        { IDC_PEBSTARTUPINFO, L"This is not really important, only a few protectors check for this. Maybe Enigma checks it." },
        {
            IDC_NTSETINFORMATIONTHREAD,
            L"The THREADINFOCLASS value ThreadHideFromDebugger is a well-known\r\n"
            L"anti-debug measurement. The debugger cannot handle hidden threads.\r\n"
            L"This leads to a loss of control over the target."
        },
        {
            IDC_NTSETINFORMATIONPROCESS,
            L"The PROCESSINFOCLASS value ProcessHandleTracing can be used to\r\n"
            L"detect a debugger. The PROCESSINFOCLASS value ProcessBreakOnTermination\r\n"
            L"can be used to generate a Blue Screen of Death on process termination."
        },
        {
            IDC_NTQUERYSYSTEMINFORMATION,
            L"The SYSTEM_INFORMATION_CLASS values SystemKernelDebuggerInformation,\r\n"
            L"SystemKernelDebuggerInformationEx and SystemKernelDebuggerFlags can be used\r\n"
            L"to detect kernel debuggers. The SYSTEM_INFORMATION_CLASS values SystemProcessInformation\r\n"
            L"and SystemExtendedProcessInformation are used to get a process list.\r\n"
            L"SystemHandleInformation and SystemExtendedHandleInformation are used to\r\n"
            L"enumerate system process handles to detect e.g. handles to the debuggee process.\r\n"
            L"The SYSTEM_INFORMATION_CLASS values SystemCodeIntegrityInformation and\r\n"
            L"SystemCodeIntegrityUnlockInformation can be used to detect test signing mode.\r\n"
            L"A debugger should be hidden in a process list and the debugee should have a good parent\r\n"
            L"process ID like the ID from explorer.exe."
        },
        {
            IDC_NTQUERYINFORMATIONPROCESS,
            L"A very important option. Various PROCESSINFOCLASS values can be used\r\nto detect a debugger.\r\n"
            L" ProcessDebugFlags: Should return 1 in the supplied buffer.\r\n"
            L" ProcessDebugPort: Should return 0 in the supplied buffer.\r\n"
            L" ProcessDebugObjectHandle: Should return 0 in the supplied buffer\r\nand the error STATUS_PORT_NOT_SET(0xC0000353)\r\n"
            L" ProcessBasicInformation: Reveals the parent process ID.\r\n"
            L" ProcessBreakOnTermination: Please see NtSetInformationProcess\r\n"
            L" ProcessHandleTracing: Please see NtSetInformationProcess\r\n"
            L"A lot of protectors use this to detect debuggers.\r\n"
            L"The windows API CheckRemoteDebuggerPresent uses NtQueryInformationProcess internally."
        },
        {
            IDC_NTQUERYOBJECT,
            L"The OBJECT_INFORMATION_CLASS ObjectTypesInformation and ObjectTypeInformation\r\n"
            L"can be used to detect debuggers. ScyllaHide filters DebugObject references."
        },
        {
            IDC_NTYIELDEXECUTION,
            L"A very unrealiable anti-debug method. This is only used in some UnpackMe's\r\n"
            L"or in some Proof of Concept code. Only activate this if you really need it.\r\n"
            L"Probably you will never need this option."
        },
        {
            IDC_NTCREATETHREADEX,
            L"Threads hidden from debuggers can be created with a special creation flag\r\n"
            L"THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER. ScyllaHide doesn't\r\n"
            L"allow hidden threads. The anti-debug effect is similar to NtSetInformationThread"
        },
        {
            IDC_OUTPUTDEBUGSTRINGA,
            L"OutputDebugStringW uses OutputDebugStringA internally. ScyllaHide only hooks\r\n"
            L"the ANSI version and this is therefore enough. This is a very unreliable\r\n"
            L"antidebug method, so you will not need this option very often."
        },
        {
            IDC_NTUSERBLOCKINPUT,
            L"Very effective anti-debug method. This is used e.g. in Yoda's Protector.\r\n"
            L"\"Blocks keyboard and mouse input events from reaching applications.\""
        },
        {
            IDC_NTUSERFINDWINDOWEX,
            L"This is a system call function in user32.dll.\r\n"
            L"The windows APIs FindWindowA/W and FindWindowExA/W call this internally.\r\n"
            L"The debugger window will be hidden."
        },
        {
            IDC_NTUSERBUILDHWNDLIST,
            L"This is a system call function in user32.dll.\r\n"
            L"The windows APIs EnumWindows and EnumThreadWindows call this internally.\r\n"
            L"The debugger window will be hidden."
        },
        {
            IDC_NTUSERQUERYWINDOW,
            L"This is a system call function in user32.dll.\r\n"
            L"The windows API GetWindowThreadProcessId calls this internally.\r\n"
            L"This is used to hide the debugger process."
        },
        {
            IDC_NTSETDEBUGFILTERSTATE,
            L"ScyllaHide returns always STATUS_ACCESS_DENIED.\r\n"
            L"This anti-debugn measurement isn't used very often.\r\n"
            L"Probably you will never need this option in a real world target."
        },
        {
            IDC_NTCLOSE,
            L"This is called with an invalid handle to detect a debugger.\r\n"
            L"ScyllaHide calls NtQueryObject to check the validity of the handle.\r\n"
            L"A few protectors are using this method."
        },
        {
            IDC_REMOVEDEBUGPRIV,
            L"If a debugger creates the process of the target, the target will have debug\r\n"
            L"privileges. This can be used to detect a debugger."
        },
        {
            IDC_PROTECTDRX,
            L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\n"
            L"APIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"
        },
        {
            IDC_NTGETCONTEXTTHREAD,
            L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\n"
            L"APIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"
        },
        {
            IDC_NTSETCONTEXTTHREAD,
            L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\n"
            L"APIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"
        },
        {
            IDC_NTCONTINUE,
            L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\n"
            L"APIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"
        },
        {
            IDC_KIUED,
            L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\n"
            L"APIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"
        },
        {
            IDC_GETTICKCOUNT,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!"
        },
        {
            IDC_GETTICKCOUNT64,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. Enable with care\r\n"
            L"and only if you need it!"
        },
        {
            IDC_GETLOCALTIME,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. Enable with care\r\n"
            L"and only if you need it!"
        },
        {
            IDC_GETSYSTEMTIME,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. Enable with care\r\n"
            L"and only if you need it!"
        },
        {
            IDC_NTQUERYSYSTEMTIME,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. Enable with care\r\n"
            L"and only if you need it!"
        },
        {
            IDC_NTQUERYPERFCOUNTER,
            L"There are a few windows APIs to measure the time. Timing can be used to\r\n"
            L"detect debuggers, because they slow down the execution. Enable with care\r\n"
            L"and only if you need it!"
        },
        {
            IDC_PREVENTTHREADCREATION,
            L"This option prevents the creation of new threads. This can be useful if a protector\r\n"
            L" uses a lot of protection threads. This option can be useful for EXECryptor.\r\n"
            L"Enable with care and only if you need it!\r\n"
            L"You must know what you are doing here!"
        },
        {
            IDC_RUNPE,
            L"This option hooks NtResumeThread. If the malware creates a new process,\r\n"
            L"ScyllaHide terminates and dumps any newly created process. If you are unpacking\r\n"
            L"malware, enable and try it. Should be only used inside a VM.\r\n"
            L"A typical RunPE workflow:\r\n"
            L" 1. Create a new process of any target in suspended state.\r\n"
            L"    (Process flag CREATE_SUSPENDED: 0x00000004)\r\n"
            L" 2. Replace the original process PE image with a new (malicious) PE image.\r\n"
            L"    This can involve several steps and various windows API functions.\r\n"
            L" 3. Start the process with the windows API function ResumeThread(or NtResumeThread)."
        },
        {
            IDC_DLLSTEALTH,
            L"Normal DLL injection or stealth dll injection.\r\n"
            L"You better try the normal injection first..."
        },
        {
            IDC_DLLNORMAL,
            L"Normal DLL injection or stealth dll injection.\r\n"
            L"You better try the normal injection first..."
        },
        { IDC_DLLUNLOAD, L"Unload after DLLMain" },
        { IDC_KILLANTIATTACH, L"Kill Anti-Attach" },
#ifdef OLLY1
            { IDC_OLLYTITLE, L"Olly caption" },
            {
                IDC_DELEPBREAK,
                L"Some protectors use Thread-Local-Storage (TLS) as entrypoint and check for\r\n"
                L"breakpoints at the normal PE entrypoint address. You must remove the PE\r\n"
                L"entrypoint to hide your debugger. This option is necessary for VMProtect."
            },
            {
                IDC_FIXOLLY,
                L"This option fixes various OllyDbg bugs:\r\n"
                L" - PE Fix for NumOfRvaAndSizes\r\n"
                L" - ForegroundWindow Fix\r\n"
                L" - FPU bugfix\r\n"
                L" - Format string (sprintf) bug\r\n"
                L" - NT Symbols path bug, patch by blabberer\r\n"
                L" - Faulty handle bug. Sometimes Olly does not terminate,\r\n"
                L"   error appears \"Operating system reports error ERROR_ACCESS_DENIED\""
            },
            {
                IDC_X64FIX,
                L"OllyDbg doesn't work very well on x64 operating systems.\r\n"
                L"This option fixes the most annoying bug."
            },
            { IDC_SKIPEPOUTSIDE, L"Skip \"EP outside of Code\"" },
            {
                IDC_BREAKTLS,
                L"This option sets a breakpoint to any available Thread-Local-Storage (TLS)\r\n"
                L"address. This is necessary for various protectors e.g. VMProtect."
            },
            { IDC_COMPRESSED, L"Skip compressed code" },
            { IDC_COMPRESSEDANALYZE, L"Skip compressed code and analyze" },
            { IDC_COMPRESSEDNOTHING, L"Skip compressed code and do nothing" },
            { IDC_LOADDLL, L"Skip \"Load Dll\" and" },
            { IDC_LOADDLLLOAD, L"Skip \"Load Dll\" and load DLL" },
            { IDC_LOADDLLNOTHING, L"Skip \"Load Dll\" and do nothing" },
            {
                IDC_ADVANCEDGOTO,
                L"Replaces the default OllyDbg \"Go to Address\" dialog.\r\n"
                L"Now you can enter RVA and offset values."
            },
            { IDC_ADVANCEDINFOBAR, L"Displays info about selected Bytes in CPU/Dump like Start/End address and size." },
            { IDC_BADPEIMAGE, L"Ignore bad image (WinUPack)" },
#elif defined(OLLY2)
            { IDC_OLLYTITLE, L"Olly caption" },
#elif defined(__IDP__)
            { IDC_AUTOSTARTSERVER, L"" },
            { IDC_SERVERPORT, L"" },
            { IDC_INJECTDLL, L"" },
#endif
    };

    auto hInstance = (HINSTANCE)GetWindowLongPtrW(hDlg, GWLP_HINSTANCE);
    if (!hInstance)
        return nullptr;

    // Create tooltip for main window
    auto hToolTipWnd = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASS, nullptr,
        WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        hDlg, nullptr, hInstance, nullptr);

    if (!hToolTipWnd)
        return nullptr;

    for (auto i = 0; i < _countof(ctrl_tips); i++)
    {
        auto hCtrl = GetDlgItem(hDlg, ctrl_tips[i].ctrl_id);
        if (!hCtrl)
            continue;

        TOOLINFOW ti;
        ti.cbSize = TTTOOLINFOW_V1_SIZE;
        ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
        ti.hwnd = hDlg;
        ti.uId = (UINT_PTR)hCtrl;
        ti.hinst = hInstance;
        ti.lpszText = (wchar_t *)(ctrl_tips[i].text);
        ti.lParam = 0;

        SendMessageW(hToolTipWnd, TTM_ADDTOOL, 0, (LPARAM)&ti);
    }

    SendMessageW(hToolTipWnd, TTM_SETMAXTIPWIDTH, 0, SCYLLA_MAX_TOOLTIP_WIDTH);
    SendMessageW(hToolTipWnd, TTM_ACTIVATE, TRUE, 0);

    return hToolTipWnd;
}

//options dialog proc
INT_PTR CALLBACK OptionsDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        // add current profile to options title
        auto wstrTitle = scl::fmtw(L"[ScyllaHide Options] Profile: %s", g_settings.profile_name().c_str());
        SetWindowTextW(hDlg, wstrTitle.c_str());

        // fill combobox with profiles
        for (size_t i = 0; i < g_settings.profile_names().size(); i++)
        {
            SendDlgItemMessageW(hDlg, IDC_PROFILES, CB_ADDSTRING, 0, (LPARAM)g_settings.profile_names()[i].c_str());
            if (g_settings.profile_name() == g_settings.profile_names()[i])
                SendDlgItemMessageW(hDlg, IDC_PROFILES, CB_SETCURSEL, i, 0);
        }

        UpdateOptions(hDlg, &g_settings);

#ifdef OLLY1
        EnableWindow(GetDlgItem(hDlg, IDC_X64FIX), !scl::IsWindows64());
#endif

        CreateTooltips(hDlg);

        break;
    }
    case WM_CLOSE:
    {
        EndDialog(hDlg, NULL);
    }
    break;

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_PROFILES:
        {
            if (HIWORD(wParam) != CBN_SELCHANGE)
                break;

            auto profileIdx = (int)SendDlgItemMessageW(hDlg, IDC_PROFILES, CB_GETCURSEL, 0, 0);
            g_settings.SetProfile(g_settings.profile_names()[profileIdx].c_str());

            // update options title
            auto wstrTitle = scl::fmtw(L"[ScyllaHide Options] Profile: %s", g_settings.profile_name().c_str());
            SetWindowTextW(hDlg, wstrTitle.c_str());

            UpdateOptions(hDlg, &g_settings);
            break;
        }

        case IDC_SAVEPROFILE:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            std::wstring wstrNewProfileName;

#ifdef OLLY1
            std::string strNewProfileName;
            strNewProfileName.resize(MAX_PATH);
            if (_Gettext("New profile name?", &strNewProfileName[0], 0, 0, 0) <= 0)
                break;
            wstrNewProfileName = scl::wstr_conv().from_bytes(strNewProfileName.c_str());

#elif defined(OLLY2)
            wstrNewProfileName.resize(MAX_PATH);
            if (Getstring(hDlg, L"New profile name?", &wstrNewProfileName[0], wstrNewProfileName.size(), 0, 0, 0, 0, 0, 0) <= 0)
                break;
            wstrNewProfileName.resize(lstrlenW(wstrNewProfileName.c_str()));

#elif defined(__IDP__)
            auto szNewProfileName = askstr(0, "", "New profile name?");
            if (!szNewProfileName)
                break;
            wstrNewProfileName = scl::wstr_conv().from_bytes(szNewProfileName);

#elif defined(X64DBG)
            std::string strNewProfileName;
            strNewProfileName.resize(GUI_MAX_LINE_SIZE);
            if (!GuiGetLineWindow("New profile name?", &strNewProfileName[0]))
                break;
            wstrNewProfileName = scl::wstr_conv().from_bytes(strNewProfileName.c_str());
#endif

            if (!g_settings.AddProfile(wstrNewProfileName.c_str()))
                break;
            g_settings.SetProfile(wstrNewProfileName.c_str());

            auto wstrTitle = scl::fmtw(L"[ScyllaHide Options] Profile: %s", g_settings.profile_name().c_str());
            SetWindowTextW(hDlg, wstrTitle.c_str());

            SendDlgItemMessageW(hDlg, IDC_PROFILES, CB_ADDSTRING, 0, (LPARAM)wstrNewProfileName.c_str());
            auto profileCount = (int)SendDlgItemMessageW(hDlg, IDC_PROFILES, CB_GETCOUNT, 0, 0);
            SendDlgItemMessageW(hDlg, IDC_PROFILES, CB_SETCURSEL, profileCount - 1, 0);

            UpdateOptions(hDlg, &g_settings);
            break;
        }

        case IDOK:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            SaveOptions(hDlg, &g_settings);

            if (ProcessId)
            {
#ifdef __IDP__
#ifndef BUILD_IDA_64BIT
                startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
#endif
#else
                startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
#endif
                bHooked = true;
                MessageBoxW(hDlg, L"Applied changes! Restarting target is NOT necessary!", L"[ScyllaHide Options]", MB_ICONINFORMATION);
            }
            else
            {
                MessageBoxW(hDlg, L"Please start the target to apply changes!", L"[ScyllaHide Options]", MB_ICONINFORMATION);
            }

            EndDialog(hDlg, NULL);
            break;
        }

        case IDC_APPLY:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            SaveOptions(hDlg, &g_settings);
            break;
        }

        case IDC_EXCEPTION_ALL:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            auto value = (IsDlgButtonChecked(hDlg, IDC_EXCEPTION_ALL) == BST_CHECKED);
            g_settings.opts().handleExceptionPrint = value;
            g_settings.opts().handleExceptionIllegalInstruction = value;
            g_settings.opts().handleExceptionInvalidLockSequence = value;
            g_settings.opts().handleExceptionNoncontinuableException = value;
            g_settings.opts().handleExceptionRip = value;
            g_settings.opts().handleExceptionAssertionFailure = value;
            g_settings.opts().handleExceptionBreakpoint = value;
            g_settings.opts().handleExceptionGuardPageViolation = value;
            g_settings.opts().handleExceptionWx86Breakpoint = value;
            break;
        }

        case IDC_PROTECTDRX:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            auto state = IsDlgButtonChecked(hDlg, IDC_PROTECTDRX);
            CheckDlgButton(hDlg, IDC_NTGETCONTEXTTHREAD, state);
            CheckDlgButton(hDlg, IDC_NTSETCONTEXTTHREAD, state);
            CheckDlgButton(hDlg, IDC_NTCONTINUE, state);
            CheckDlgButton(hDlg, IDC_KIUED, state);
            break;
        }

        case IDC_NTGETCONTEXTTHREAD:
        case IDC_NTSETCONTEXTTHREAD:
        case IDC_NTCONTINUE:
        case IDC_KIUED:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            auto checked = IsDlgButtonChecked(hDlg, IDC_NTGETCONTEXTTHREAD)
                || IsDlgButtonChecked(hDlg, IDC_NTSETCONTEXTTHREAD)
                || IsDlgButtonChecked(hDlg, IDC_NTCONTINUE)
                || IsDlgButtonChecked(hDlg, IDC_KIUED);

            CheckDlgButton(hDlg, IDC_PROTECTDRX, checked);
            break;
        }

        case IDC_PEB:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            auto state = IsDlgButtonChecked(hDlg, IDC_PEB);
            CheckDlgButton(hDlg, IDC_PEBBEINGDEBUGGED, state);
            CheckDlgButton(hDlg, IDC_PEBHEAPFLAGS, state);
            CheckDlgButton(hDlg, IDC_PEBNTGLOBALFLAG, state);
            CheckDlgButton(hDlg, IDC_PEBSTARTUPINFO, state);
            break;
        }

        case IDC_PEBBEINGDEBUGGED:
        case IDC_PEBHEAPFLAGS:
        case IDC_PEBNTGLOBALFLAG:
        case IDC_PEBSTARTUPINFO:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            auto checked = IsDlgButtonChecked(hDlg, IDC_PEBBEINGDEBUGGED)
                || IsDlgButtonChecked(hDlg, IDC_PEBHEAPFLAGS)
                || IsDlgButtonChecked(hDlg, IDC_PEBNTGLOBALFLAG)
                || IsDlgButtonChecked(hDlg, IDC_PEBSTARTUPINFO);

            CheckDlgButton(hDlg, IDC_PEB, checked);
            break;
        }

#ifdef OLLY1
        case IDC_COMPRESSED:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            auto checked = (IsDlgButtonChecked(hDlg, IDC_COMPRESSED) == BST_CHECKED);

            EnableWindow(GetDlgItem(hDlg, IDC_COMPRESSEDANALYZE), checked);
            EnableWindow(GetDlgItem(hDlg, IDC_COMPRESSEDNOTHING), checked);

            if (!checked) {
                CheckDlgButton(hDlg, IDC_COMPRESSEDANALYZE, BST_UNCHECKED);
                CheckDlgButton(hDlg, IDC_COMPRESSEDNOTHING, BST_UNCHECKED);
            }
            break;
        }

        case IDC_LOADDLL:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            auto checked = (IsDlgButtonChecked(hDlg, IDC_LOADDLL) == BST_CHECKED);

            EnableWindow(GetDlgItem(hDlg, IDC_LOADDLLLOAD), checked);
            EnableWindow(GetDlgItem(hDlg, IDC_LOADDLLNOTHING), checked);

            if (!checked) {
                CheckDlgButton(hDlg, IDC_LOADDLLLOAD, BST_UNCHECKED);
                CheckDlgButton(hDlg, IDC_LOADDLLNOTHING, BST_UNCHECKED);
            }
            break;
        }
#endif

#ifdef __IDP__
        case IDC_DLLNORMAL:
        case IDC_DLLSTEALTH:
        case IDC_DLLUNLOAD:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            //DLL injection options need to be updated on-the-fly coz the injection button is ON the options window
            g_settings.opts().dllStealth = (IsDlgButtonChecked(hDlg, IDC_DLLSTEALTH) == BST_CHECKED);
            g_settings.opts().dllNormal = (IsDlgButtonChecked(hDlg, IDC_DLLNORMAL) == BST_CHECKED);
            g_settings.opts().dllUnload = (IsDlgButtonChecked(hDlg, IDC_DLLUNLOAD) == BST_CHECKED);
            break;
        }

        case IDC_INJECTDLL:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            if (ProcessId)
            {
                if (scl::GetFileDialogW(DllPathForInjection, _countof(DllPathForInjection)))
                {
                    if (dbg->is_remote())
                    {
                        SendInjectToServer(ProcessId);
                    }
                    else
                    {
#ifndef BUILD_IDA_64BIT
                        injectDll(ProcessId, DllPathForInjection);
#endif
                    }

                }
            }
            break;
        }

        case IDC_ATTACH:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            EndDialog(hDlg, NULL);
            DialogBoxW(hinst, MAKEINTRESOURCE(IDD_ATTACH), (HWND)callui(ui_get_hwnd).vptr, &AttachProc);
            break;
        }

        case IDC_ABOUT:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            scl::ShowAboutBox((HWND)callui(ui_get_hwnd).vptr);
            break;
        }
#endif

        case IDC_SELECT_EXCEPTIONS:
        {
            if (HIWORD(wParam) != BN_CLICKED)
                break;

            createExceptionWindow(hDlg);
            UpdateOptionsExceptions(hDlg, &g_settings);
            break;
        }

        default:
            break;
        }

    }
    break;

    default:
    {
        return FALSE;
    }
    }

    return 0;
}



typedef struct _NAME_TOOLTIP {
    const WCHAR * name;
    WCHAR * tooltip;
    ULONG_PTR windowId;
} NAME_TOOLTIP;


enum {
    ID_EXCEPTION_PRINT = 200,
    ID_EXCEPTION_RIP,
    ID_EXCEPTION_Noncontinable,
    ID_EXCEPTION_Illegal,
    ID_EXCEPTION_InvalidLockSequence,
    ID_EXCEPTION_AssertionFailure,
    ID_EXCEPTION_GuardPage,
    ID_EXCEPTION_Breakpoint,
    ID_EXCEPTION_Wx86Breakpoint,
    ID_EXCEPTION_APPLY,
    ID_EXCEPTION_CANCEL
};

NAME_TOOLTIP exceptionNamesTooltip[] = {
    { L"Print", L"DBG_PRINTEXCEPTION_C 0x40010006", ID_EXCEPTION_PRINT },
    { L"RIP", L"DBG_RIPEXCEPTION 0x40010007", ID_EXCEPTION_RIP },
#if defined(OLLY1) || defined(OLLY2)
    { L"Non-continuable", L"STATUS_NONCONTINUABLE_EXCEPTION 0xC0000025", ID_EXCEPTION_Noncontinable },
#endif
#ifdef OLLY1
    { L"Illegal Instruction", L"STATUS_ILLEGAL_INSTRUCTION 0xC000001D", ID_EXCEPTION_Illegal },
    { L"Invalid Lock Sequence", L"STATUS_INVALID_LOCK_SEQUENCE 0xC000001E", ID_EXCEPTION_InvalidLockSequence },
    { L"Guard Page Violation", L"STATUS_GUARD_PAGE_VIOLATION 0x80000001", ID_EXCEPTION_GuardPage },
    { L"Breakpoint", L"STATUS_BREAKPOINT 0x80000003", ID_EXCEPTION_Breakpoint },
    { L"WX86 Breakpoint", L"STATUS_WX86_BREAKPOINT 0x4000001F", ID_EXCEPTION_Wx86Breakpoint },
#endif
#ifdef __IDP__
    { L"Assertion Failure", L"STATUS_ASSERTION_FAILURE 0xC0000420", ID_EXCEPTION_AssertionFailure }
#endif
};

#define HEIGHT_OF_EXCEPTION_CHECKBOX 16
#define EXCEPTION_WINDOW_BASE_HEIGHT 46
#define EXCEPTION_WINDOW_WIDTH 200
LRESULT CALLBACK ExceptionSettingsWndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    RECT rect;
    LONG height;
    HINSTANCE hInst = GetModuleHandleW(0);

    if (msg == WM_CREATE)
    {
        int numOfExceptions = _countof(exceptionNamesTooltip);

        HWND control;
        GetClientRect(hwnd, &rect);
        height = rect.bottom;
        GetWindowRect(hwnd, &rect);
        height = rect.bottom - rect.top - height + (EXCEPTION_WINDOW_BASE_HEIGHT + (numOfExceptions*(HEIGHT_OF_EXCEPTION_CHECKBOX + 5))) + 5;
        SetWindowPos(hwnd, NULL, 0, 0, rect.right - rect.left, height, SWP_NOMOVE | SWP_NOZORDER);

        HFONT hFont;
        NONCLIENTMETRICSW metric = { 0 };
        metric.cbSize = sizeof(NONCLIENTMETRICSW);
        if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &metric, 0))
        {
            hFont = CreateFontIndirectW(&metric.lfMessageFont);
        }
        else
        {
            hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        }

        HWND hwndTT = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, NULL, 0, NULL);

        for (int i = 0, j = 200; i < numOfExceptions; i++, j++)
        {
            control = CreateWindowExW(0, L"Button", exceptionNamesTooltip[i].name, WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 1, i * 20, EXCEPTION_WINDOW_WIDTH, HEIGHT_OF_EXCEPTION_CHECKBOX, hwnd, (HMENU)exceptionNamesTooltip[i].windowId, hInst, NULL);
            SendMessageW(control, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0));

            TOOLINFOW ti = { 0 };

            ti.cbSize = TTTOOLINFOW_V1_SIZE;
            ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
            ti.hwnd = hwnd;
            ti.uId = (UINT_PTR)control;
            ti.lpszText = exceptionNamesTooltip[i].tooltip;

            SendMessageW(hwndTT, TTM_ADDTOOL, 0, (LPARAM)&ti);
        }

        if (g_settings.opts().handleExceptionPrint) CheckDlgButton(hwnd, ID_EXCEPTION_PRINT, BST_CHECKED);
        if (g_settings.opts().handleExceptionIllegalInstruction) CheckDlgButton(hwnd, ID_EXCEPTION_Illegal, BST_CHECKED);
        if (g_settings.opts().handleExceptionInvalidLockSequence) CheckDlgButton(hwnd, ID_EXCEPTION_InvalidLockSequence, BST_CHECKED);
        if (g_settings.opts().handleExceptionNoncontinuableException) CheckDlgButton(hwnd, ID_EXCEPTION_Noncontinable, BST_CHECKED);
        if (g_settings.opts().handleExceptionAssertionFailure) CheckDlgButton(hwnd, ID_EXCEPTION_AssertionFailure, BST_CHECKED);
        if (g_settings.opts().handleExceptionBreakpoint) CheckDlgButton(hwnd, ID_EXCEPTION_Breakpoint, BST_CHECKED);
        if (g_settings.opts().handleExceptionGuardPageViolation) CheckDlgButton(hwnd, ID_EXCEPTION_GuardPage, BST_CHECKED);
        if (g_settings.opts().handleExceptionWx86Breakpoint) CheckDlgButton(hwnd, ID_EXCEPTION_Wx86Breakpoint, BST_CHECKED);
        if (g_settings.opts().handleExceptionRip) CheckDlgButton(hwnd, ID_EXCEPTION_RIP, BST_CHECKED);

        control = CreateWindowExW(0, L"Button", L"Apply", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 1, (numOfExceptions)* 20 + 1, 100, 25, hwnd, (HMENU)ID_EXCEPTION_APPLY, hInst, NULL);
        SendMessageW(control, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0));
        control = CreateWindowExW(0, L"Button", L"Cancel", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 1, (numOfExceptions + 1) * 20 + 5, 100, 25, hwnd, (HMENU)ID_EXCEPTION_CANCEL, hInst, NULL);
        SendMessageW(control, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0));

        //DeleteObject(hFont);

    }
    else if (msg == WM_COMMAND)
    {
        if (LOWORD(wparam) == ID_EXCEPTION_APPLY)
        {
            g_settings.opts().handleExceptionPrint = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_PRINT) == BST_CHECKED);
            g_settings.opts().handleExceptionIllegalInstruction = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Illegal) == BST_CHECKED);
            g_settings.opts().handleExceptionInvalidLockSequence = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_InvalidLockSequence) == BST_CHECKED);
            g_settings.opts().handleExceptionNoncontinuableException = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Noncontinable) == BST_CHECKED);
            g_settings.opts().handleExceptionRip = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_RIP) == BST_CHECKED);
            g_settings.opts().handleExceptionGuardPageViolation = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_GuardPage) == BST_CHECKED);
            g_settings.opts().handleExceptionBreakpoint = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Breakpoint) == BST_CHECKED);
            g_settings.opts().handleExceptionWx86Breakpoint = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Wx86Breakpoint) == BST_CHECKED);
            g_settings.opts().handleExceptionAssertionFailure = (IsDlgButtonChecked(hwnd, ID_EXCEPTION_AssertionFailure) == BST_CHECKED);
            DestroyWindow(hwnd);
        }
        else if (LOWORD(wparam) == ID_EXCEPTION_CANCEL)
        {
            DestroyWindow(hwnd);
        }
    }
    else if (msg == WM_CLOSE)
    {
        DestroyWindow(hwnd);
    }
    else if (msg == WM_DESTROY)
    {
        PostQuitMessage(0);
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}


void createExceptionWindow(HWND hwnd)
{
    WCHAR * classname = L"exception_window_config_scyllahide";
    WNDCLASSW wc = { 0 };
    HWND     wnd;
    MSG      msg;
    //wc.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
    wc.hInstance = GetModuleHandleW(0);
    wc.style = CS_PARENTDC | CS_DBLCLKS;
    wc.lpfnWndProc = ExceptionSettingsWndproc;
    wc.lpszClassName = classname;
    RegisterClassW(&wc);

    int windowHeight = EXCEPTION_WINDOW_BASE_HEIGHT + (_countof(exceptionNamesTooltip)*(HEIGHT_OF_EXCEPTION_CHECKBOX + 5));

    wnd = CreateWindowExW(0,
        classname,
        L"Exception Settings",
        WS_VISIBLE | WS_SYSMENU | WS_OVERLAPPED | DS_SYSMODAL,
        (GetSystemMetrics(SM_CXSCREEN) - EXCEPTION_WINDOW_WIDTH) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - windowHeight) / 2,
        EXCEPTION_WINDOW_WIDTH,
        windowHeight,
        hwnd,
        NULL,
        GetModuleHandleW(0),
        NULL);

    ShowWindow(wnd, SW_SHOWNORMAL);
    UpdateWindow(wnd);

    //EnableWindow(hwnd, FALSE);

    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    //EnableWindow(hwnd, TRUE);
    UnregisterClassW(classname, 0);
}
