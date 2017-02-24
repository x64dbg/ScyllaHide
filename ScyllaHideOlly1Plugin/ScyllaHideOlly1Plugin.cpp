#include <codecvt>
#include <locale>
#include <sstream>
#include <Scylla/NtApiLoader.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>
#include <Scylla/Version.h>

#include "..\PluginGeneric\Injector.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"
#include "..\PluginGeneric\CustomExceptionHandler.h"

#include "resource.h"
#include "olly1patches.h"

#pragma comment(lib, "ollydbg1\\ollydbg.lib")

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif

#define MENU_PROFILES_OFFSET 10

typedef void(__cdecl * t_AttachProcess)(DWORD dwPID);
typedef void(__cdecl * t_LogWrapper)(const WCHAR * format, ...);
typedef void(__cdecl * t_SetDebuggerBreakpoint)(DWORD_PTR address);
typedef bool(__cdecl * t_IsAddressBreakpoint)(DWORD_PTR address);

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;
extern t_AttachProcess _AttachProcess;
extern t_SetDebuggerBreakpoint _SetDebuggerBreakpoint;
extern t_IsAddressBreakpoint _IsAddressBreakpoint;

const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";

scl::Settings g_settings;
std::wstring g_scyllaHideDllPath;
std::wstring g_ntApiCollectionIniPath;
std::wstring g_scyllaHideIniPath;

//globals
HINSTANCE hinst;
DWORD ProcessId;
DWORD_PTR epaddr = 0;
bool bHooked = false;
static bool bEPBreakRemoved = false;
HWND hwmain; // Handle of main OllyDbg window
bool bHookedDumpProc = false;

HMODULE hNtdllModule = 0;
bool specialPebFix = false;
LPVOID ImageBase = 0;
bool executeOnce = false;
DEBUG_EVENT *currentDebugEvent;

static void LogErrorWrapper(const WCHAR * format, ...)
{
    va_list ap;

    va_start(ap, format);
    auto strw = scl::vfmtw(format, ap);
    va_end(ap);

    auto stra = scl::wstr_conv().to_bytes(strw);

    _Error("%s", stra.c_str());
}

static void LogWrapper(const WCHAR * format, ...)
{
    va_list ap;

    va_start(ap, format);
    auto strw = scl::vfmtw(format, ap);
    va_end(ap);

    auto stra = scl::wstr_conv().to_bytes(strw);

    _Message(0, "%s", stra.c_str());
}

static void AttachProcess(DWORD dwPID)
{
    int result = _Attachtoactiveprocess((int)dwPID);

    if (result != 0)
    {
        MessageBoxW(hwmain,
            L"Can't attach to that process !",
            L"ScyllaHide Plugin", MB_OK | MB_ICONERROR);
    }
}

static bool IsAddressBreakpoint(DWORD_PTR address)
{
    t_table* pTable = (t_table*)_Plugingetvalue(VAL_BREAKPOINTS);
    if (pTable)
    {
        t_sorted* pSorted = &(pTable->data);
        for (int i = 0; i < pTable->data.n; i++)
        {
            t_bpoint* bp = (t_bpoint*)_Getsortedbyselection(pSorted, i);
            if (bp)
            {
                //char text[100];
                //wsprintfA(text,"%X %X",bp->addr,address);
                //MessageBoxA(0,text,text,0);
                if (bp->addr == address)
                {
                    return true;
                }
            }
        }
    }

    return false;
}

static void MarkSystemDllsOnx64() {
    const char sysPath[] = "windows\\syswow64";
    char lowerCopy[MAX_PATH] = { 0 };

    int t = _Plugingetvalue(VAL_MODULES);
    if (t <= 0)  {
        _Error("Cannot get module list");
        return;
    }

    t_table* ttab = (t_table*)t;
    t_module* tmod;
    for (int i = 0; i < ttab->data.n; i++)
    {
        tmod = (t_module*)_Getsortedbyselection(&ttab->data, i);

        for (int j = 0; tmod->path[j]; j++) {
            lowerCopy[j] = tolower(tmod->path[j]);
        }

        //skip C:/
        if (strncmp(lowerCopy + 3, sysPath, sizeof(sysPath) - 1) == 0) {
            tmod->issystemdll = 1;
        }
        else {
            //MessageBoxA(0, lowerCopy, "NON",0);
        }

    }
}

static void PrepareDetach() {
    //delete breakpoints

    t_table* pTable = (t_table*)_Plugingetvalue(VAL_BREAKPOINTS);
    if (pTable)
    {
        t_sorted* pSorted = &(pTable->data);

        //IMPORTANT: Reverse index loop
        for (int i = pTable->data.n - 1; i >= 0; i--)
        {
            t_bpoint* pBreakpoint = (t_bpoint*)_Getsortedbyselection(pSorted, i);
            if (pBreakpoint)	{
                _Deletebreakpoints(pBreakpoint->addr, (pBreakpoint->addr) + 1, TRUE);   //silent
            }
        }

    }
}

static void HandleDetachProcess()
{
    t_status tStat = _Getstatus();

    if (tStat != STAT_STOPPED && tStat != STAT_RUNNING)
    {
        MessageBoxW(hwmain, L"Process must be in paused or running mode.", L"Detach Error", MB_ICONERROR);
        return;
    }

    PrepareDetach();

    tStat = _Getstatus();

    if (tStat == STAT_STOPPED) {
        if (currentDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, currentDebugEvent->dwThreadId);
            if (hThread) {
                CONTEXT context = { 0 };
                context.ContextFlags = CONTEXT_ALL;
                GetThreadContext(hThread, &context);
                context.Eip = (DWORD)currentDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;
                SetThreadContext(hThread, &context);
                CloseHandle(hThread);

                ContinueDebugEvent(currentDebugEvent->dwProcessId, currentDebugEvent->dwThreadId, DBG_CONTINUE);
            }

        }
        else if (currentDebugEvent->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
            ContinueDebugEvent(currentDebugEvent->dwProcessId, currentDebugEvent->dwThreadId, DBG_CONTINUE);
        }
        else {
            ContinueDebugEvent(currentDebugEvent->dwProcessId, currentDebugEvent->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        }
    }

    DebugSetProcessKillOnExit(FALSE);

    //terminate olly
    ExitProcess(0);
}

//register plugin with name
extern "C" int DLL_EXPORT _ODBG_Plugindata(char shortname[32])
{
    strcpy(shortname, SCYLLA_HIDE_NAME_A);
    return PLUGIN_VERSION;
};

//initialization happens in here
extern "C" int DLL_EXPORT _ODBG_Plugininit(int ollydbgversion, HWND hw, unsigned long *features)
{
    if (ollydbgversion < PLUGIN_VERSION)
        return -1;

    hwmain = hw;

    g_settings.Load(g_scyllaHideIniPath.c_str());

    _Addtolist(0, 0, "%s Plugin v%s Copyright (C) 2014 Aguila / cypher", SCYLLA_HIDE_NAME_A, SCYLLA_HIDE_VERSION_STRING_A);

    //do some Olly fixes
    if (g_settings.opts().ollyFixBugs) {
        fixBadPEBugs();
        fixForegroundWindow();
        fixFPUBug();
        fixSprintfBug();
        fixNTSymbols();
        fixFaultyHandleOnExit();
    }
    if (g_settings.opts().ollyX64Fix && scl::IsWindows64()) {
        fixX64Bug();
    }
    if (g_settings.opts().ollySkipEpOutsideCode) {
        patchEPOutsideCode();
    }

    if (g_settings.opts().killAntiAttach) {
        InstallAntiAttachHook();
    }

    if (g_settings.opts().ollyIgnoreBadPeImage) {
        fixBadPEImage();
    }

    if (g_settings.opts().ollyAdvancedGoto) {
        advcancedCtrlG();
    };

    if (g_settings.opts().ollySkipCompressedDoAnalyze || g_settings.opts().ollySkipCompressedDoNothing) {
        skipCompressedCode();
    }

    if (g_settings.opts().ollySkipLoadDllDoLoad || g_settings.opts().ollySkipLoadDllDoNothing) {
        skipLoadDll();
    }
    return 0;
};

// OllyDbg calls this optional function when user wants to terminate OllyDbg.
// All MDI windows created by plugins still exist. Function must return 0 if
// it is safe to terminate. Any non-zero return will stop closing sequence. Do
// not misuse this possibility! Always inform user about the reasons why
// termination is not good and ask for his decision!
extern "C" int DLL_EXPORT _ODBG_Pluginclose(void)
{
    //RestoreAllHooks();
    return 0;
}

//add menu entries
extern "C" int DLL_EXPORT _ODBG_Pluginmenu(int origin, char data[4096], void *item)
{
    switch (origin)
    {
    case PM_MAIN:
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wstr2str;
        std::stringstream ssMenu;
        ssMenu << "0 & Options, 4 & Load Profile{";
        for (size_t i = 0; i < g_settings.profile_names().size(); i++)
        {
            ssMenu << (i + MENU_PROFILES_OFFSET) << ' ' << wstr2str.to_bytes(g_settings.profile_names()[i].c_str()) << ",";
        }
        ssMenu << "},|2 &Inject DLL|5 &Attach process, 6 &Detach process|1 &About";
        strncpy(data, ssMenu.str().c_str(), min(4096, ssMenu.str().size()));

        //also patch olly title
        SetWindowTextW(hwmain, g_settings.opts().ollyWindowTitle.c_str());
        return 1;
    }
    case PM_THREADS:
    {
        strcpy(data, "0 &Resume all Threads, 1 &Suspend all Threads");
        return 1;
    }

    default:
        break;
    }


    return 0;
}

//handle plugin actions
extern "C" void DLL_EXPORT _ODBG_Pluginaction(int origin, int action, void *item)
{
    if (origin == PM_MAIN) {
        switch (action)
        {
        case 0:
        {
            DialogBoxW(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwmain, &OptionsDlgProc);
            break;
        }
        case 1:
        {
            scl::ShowAboutBox(hwmain);

            break;
        }
        case 2:
        {
            if (ProcessId) {
                wchar_t dllPath[MAX_PATH] = {};
                if (scl::GetFileDialogW(dllPath, _countof(dllPath)))
                    injectDll(ProcessId, dllPath);
            }
            break;
        }
        case 5:
        {
            DialogBox(hinst, MAKEINTRESOURCE(IDD_ATTACH), hwmain, &AttachProc);
            break;
        }
        case 6:
        {
            HandleDetachProcess();
            break;
        }

        default: {
            //profile names/count is dynamic so we catch loading them with default case
            g_settings.SetProfile(g_settings.profile_names()[action - MENU_PROFILES_OFFSET].c_str());

            if (ProcessId)
            {
                startInjection(ProcessId, g_scyllaHideDllPath.c_str(), true);
                bHooked = true;
                MessageBoxA(hwmain, "Applied changes! Restarting target is NOT necessary!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                MessageBoxA(hwmain, "Please start the target to apply changes!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
            }
        }
                 break;
        }
    }
    else if (origin == PM_THREADS) {
        t_table* threadWindow = (t_table*)_Plugingetvalue(VAL_THREADS);
        int threadCount = threadWindow->data.n;
        int threadSize = threadWindow->data.itemsize;
        t_thread* thread = (t_thread*)threadWindow->data.data;

        switch (action)
        {
        case 0:
        {
            //resume
            for (int i = 0; i < threadCount; i++) {
                ResumeThread(thread->thread);

                //yup this is super-hacky-pointer-kungfu but thread++ wont work coz there
                //is 0x20bytes extra data between thread elements
                thread = reinterpret_cast<t_thread*>((DWORD)thread + threadSize);
            }
            break;
        }
        case 1:
        {
            //suspend
            for (int i = 0; i < threadCount; i++) {
                SuspendThread(thread->thread);

                //yup this is super-hacky-pointer-kungfu but thread++ wont work coz there
                //is 0x20bytes extra data between thread elements
                thread = reinterpret_cast<t_thread*>((DWORD)thread + threadSize);
            }
            break;
        }
        }
    }
}

//called for every debugloop pass
extern "C" void DLL_EXPORT _ODBG_Pluginmainloop(DEBUG_EVENT *debugevent)
{
    if (!debugevent)
        return;

    if (g_settings.opts().fixPebHeapFlags)
    {
        if (specialPebFix)
        {
            StartFixBeingDebugged(ProcessId, false);
            specialPebFix = false;
        }

        if (debugevent->u.LoadDll.lpBaseOfDll == hNtdllModule)
        {
            StartFixBeingDebugged(ProcessId, true);
            specialPebFix = true;
        }
    }

    switch (debugevent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {

        if (g_settings.opts().handleExceptionPrint ||
            g_settings.opts().handleExceptionRip ||
            g_settings.opts().handleExceptionIllegalInstruction ||
            g_settings.opts().handleExceptionInvalidLockSequence ||
            g_settings.opts().handleExceptionNoncontinuableException ||
            g_settings.opts().handleExceptionBreakpoint ||
            g_settings.opts().handleExceptionWx86Breakpoint ||
            g_settings.opts().handleExceptionGuardPageViolation
            )
        {
            if (executeOnce == false)
            {
                HookDebugLoop();
                executeOnce = true;
            }
        }

        ImageBase = debugevent->u.CreateProcessInfo.lpBaseOfImage;
        ProcessId = debugevent->dwProcessId;
        bHooked = false;
        epaddr = (DWORD_PTR)debugevent->u.CreateProcessInfo.lpStartAddress;

        if (epaddr == NULL)
        {
            //ATTACH to an existing process!
            //Apply anti-anti-attach
            if (g_settings.opts().killAntiAttach)
            {
                if (!ApplyAntiAntiAttach(ProcessId))
                {
                    MessageBoxW(hwmain, L"Anti-Anti-Attach failed", L"Error", MB_ICONERROR);
                }
            }
        }

        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

        //change olly caption again !
        SetWindowTextW(hwmain, g_settings.opts().ollyWindowTitle.c_str());

        if (!bHookedDumpProc) {
            hookOllyWindowProcs();
            bHookedDumpProc = true;
        }
        hookOllyBreakpoints();
    }
    break;

    case LOAD_DLL_DEBUG_EVENT:
    {
        if (bHooked)
        {
            if (g_settings.opts().ollyFixBugs && scl::IsWindows64()) {
                MarkSystemDllsOnx64();
            }

            startInjection(ProcessId, g_scyllaHideDllPath.c_str(), false);
        }
        break;
    }
    case EXCEPTION_DEBUG_EVENT:
    {
        currentDebugEvent = debugevent;

        switch (debugevent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (!bHooked)
            {
                ReadNtApiInformation(g_ntApiCollectionIniPath.c_str(), &DllExchangeLoader);

                bHooked = true;
                startInjection(ProcessId, g_scyllaHideDllPath.c_str(), true);
            }

            break;
        }

        case STATUS_ILLEGAL_INSTRUCTION:
        {
            //THEMIDA
            break;
        }
        }

        break;
    }
    }
}

//reset variables. new target started or restarted
extern "C" void DLL_EXPORT _ODBG_Pluginreset(void)
{
    ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
    bHooked = false;
    bEPBreakRemoved = false;
    ProcessId = 0;
}

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        _AttachProcess = AttachProcess;
        LogWrap = LogWrapper;
        LogErrorWrap = LogErrorWrapper;
        _IsAddressBreakpoint = IsAddressBreakpoint;
        hNtdllModule = GetModuleHandleW(L"ntdll.dll");

        hNtdllModule = GetModuleHandleW(L"ntdll.dll");

        auto wstrPath = scl::GetModuleFileNameW(hInstDll);
        wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);

        g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
        g_ntApiCollectionIniPath = wstrPath + scl::NtApiLoader::kFileName;
        g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;

        hinst = hInstDll;
    }

    return TRUE;
};
