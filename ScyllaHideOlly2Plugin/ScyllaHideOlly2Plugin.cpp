#include <windows.h>
#include <cstdio>
#pragma pack(push)
#include <ollydbg2/plugin.h>
#pragma pack(pop)
#include <Scylla/Logger.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>
#include <Scylla/Version.h>

#include "..\PluginGeneric\Injector.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"
#include "..\PluginGeneric\OllyExceptionHandler.h"

#include "resource.h"

#pragma comment(lib, "ollydbg2\\ollydbg.lib")

#define OLLY201_Attachtoactiveprocess_VA 0x44B108
#define OLLY201_Attachtoactiveprocess_CHECKVALUE 0x55 // PUSH EBP

#define MAX_PROFILES 128

typedef int(__cdecl * t_Attachtoactiveprocess)(int newprocessid);
typedef void(__cdecl * t_AttachProcess)(DWORD dwPID);

extern t_AttachProcess _AttachProcess;

const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";

scl::Settings g_settings;
scl::Logger g_log;
std::wstring g_scyllaHideDllPath;
std::wstring g_scyllaHideIniPath;

HOOK_DLL_DATA g_hdd;

HINSTANCE hinst;
HMODULE hNtdllModule = 0;
bool specialPebFix = false;
bool debugLoopHooked = false;
DWORD ProcessId = 0;
bool bHooked = false;

static t_menu profilemenu[MAX_PROFILES];

static void LogCallback(const wchar_t *msg)
{
    Message(0, L"[%s] %s", SCYLLA_HIDE_NAME_W, msg);
}

static void LogErrorCallback(const wchar_t *msg)
{
    Error(L"[%s] %s", SCYLLA_HIDE_NAME_W, msg);
}

static void AttachProcess(DWORD dwPID)
{
    t_Attachtoactiveprocess _Attachtoactiveprocess = (t_Attachtoactiveprocess)OLLY201_Attachtoactiveprocess_VA;
    BYTE * pCheck = (BYTE *)OLLY201_Attachtoactiveprocess_VA;

    if (*pCheck == OLLY201_Attachtoactiveprocess_CHECKVALUE)
    {
        int result = _Attachtoactiveprocess((int)dwPID);
        if (result == 0)
        {
            Setstatus(STAT_ATTACHING);
        }
        else
        {
            //Olly displays an error message
            //MessageBoxW(hwollymain,
            //	L"Can't attach to that process !",
            //	L"ScyllaHide Plugin",MB_OK|MB_ICONERROR);
        }
    }
    else
    {
        MessageBoxW(hwollymain, L"Your Olly Version is not supported! Please use version 201 http://www.ollydbg.de/odbg201.zip", L"ERROR", MB_ICONERROR);
    }
}

//Menu->Options
static int Moptions(t_table *pt, wchar_t *name, ulong index, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode == MENU_EXECUTE)
    {
        DialogBoxW(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwollymain, &OptionsDlgProc);
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->Load Profile
static int Mprofiles(t_table *pt, wchar_t *name, ulong index, int mode)
{
    if (mode == MENU_VERIFY) {
        if (name == g_settings.profile_name())
            return MENU_CHECKED;

        return MENU_NORMAL;
    }
    else if (mode == MENU_EXECUTE)
    {
        g_settings.SetProfile(g_settings.profile_names()[index].c_str());

        if (ProcessId)
        {
            startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
            bHooked = true;
            MessageBoxA(hwollymain, "Applied changes! Restarting target is NOT necessary!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxA(hwollymain, "Please start the target to apply changes!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
        }

        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->Inject DLL
static int MinjectDll(t_table *pt, wchar_t *name, ulong index, int mode)
{
    if (mode == MENU_VERIFY)
        if (!ProcessId) return MENU_GRAYED;
        else return MENU_NORMAL;
    else if (mode == MENU_EXECUTE)
    {
        wchar_t dllPath[MAX_PATH] = {};
        if (scl::GetFileDialogW(dllPath, _countof(dllPath)))
            injectDll(ProcessId, dllPath);

        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->Attach Process
static int MattachProcess(t_table *pt, wchar_t *name, ulong index, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode == MENU_EXECUTE)
    {
        DialogBox(hinst, MAKEINTRESOURCE(IDD_ATTACH), hwollymain, &AttachProc);
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Context Menu in Thread window -> Suspend/Resume all Threads
static int Mthreads(t_table *pt, wchar_t *name, ulong index, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode == MENU_EXECUTE)
    {
        t_table threadWindow = thread;
        int threadCount = threadWindow.sorted.n;
        int threadSize = threadWindow.sorted.itemsize;
        t_thread* threadData = (t_thread*)threadWindow.sorted.data;

        switch (index)
        {
        case 0:
        {
            //Resumeallthreads(); doesnt work as expected
            for (int i = 0; i < threadCount; i++) {
                ResumeThread(threadData->thread);

                //yup this is super-hacky-pointer-kungfu but threadData++ wont work coz there
                //is 0x20bytes extra data between thread elements
                threadData = reinterpret_cast<t_thread*>((DWORD)threadData + threadSize);
            }
            break;
        }
        case 1:
        {
            //Suspendallthreads(); doesnt work as expected
            for (int i = 0; i < threadCount; i++) {
                SuspendThread(threadData->thread);

                //yup this is super-hacky-pointer-kungfu but threadData++ wont work coz there
                //is 0x20bytes extra data between thread elements
                threadData = reinterpret_cast<t_thread*>((DWORD)threadData + threadSize);
            }
            break;
        }
        }
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->About
static int Mabout(t_table *pt, wchar_t *name, ulong index, int mode)
{
    if (mode == MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode == MENU_EXECUTE)
    {
        // Debuggee should continue execution while message box is displayed.
        Resumeallthreads();

        scl::ShowAboutBox(hwollymain);

        // Suspendallthreads() and Resumeallthreads() must be paired, even if they
        // are called in inverse order!
        Suspendallthreads();
        return MENU_NOREDRAW;
    };
    return MENU_ABSENT;
}

static t_menu mainmenu[] =
{
    {
        L"Options",
        L"Select Hiding Options",
        K_NONE, Moptions, NULL, 0
    },
    {
        L"Load Profile",
        L"Load a saved profile",
        K_NONE, NULL, profilemenu, 0
    },
    {
        L"|Inject DLL",
        L"Inject a DLL into the debugged process",
        K_NONE, MinjectDll, NULL, 0
    },
    {
        L"|Attach process",
        L"Attach to a process by window finder or PID",
        K_NONE, MattachProcess, NULL, 0
    },
    {
        L"|About",
        L"About ScyllaHide plugin",
        K_NONE, Mabout, NULL, 0
    },
    { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

static t_menu threadmenu[] =
{
    {
        L"Resume all Threads",
        L"Resume all Threads",
        K_NONE, Mthreads, NULL, 0
    },
    {
        L"Suspend all Threads",
        L"Suspend all Threads",
        K_NONE, Mthreads, NULL, 1
    },
    { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

//register plugin
extc int ODBG2_Pluginquery(int ollydbgversion, ulong *features, wchar_t pluginname[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
    if (ollydbgversion < 201)
        return 0;

    wcscpy(pluginname, SCYLLA_HIDE_NAME_W);
    wcscpy(pluginversion, SCYLLA_HIDE_VERSION_STRING_W);

    return PLUGIN_VERSION;
};

//initialization happens in here
extc int ODBG2_Plugininit(void)
{
    g_settings.Load(g_scyllaHideIniPath.c_str());

    Addtolist(0, 0, SCYLLA_HIDE_NAME_W L" Plugin v" SCYLLA_HIDE_VERSION_STRING_W);
    Addtolist(0, 2, L"  Copyright (C) 2014 Aguila / cypher");
    Addtolist(0, 2, L"  Operating System: %S", scl::GetWindowsVersionNameA());

    //change olly caption
    SetWindowTextW(hwollymain, g_settings.opts().ollyWindowTitle.c_str());

    if (g_settings.opts().killAntiAttach) {
        InstallAntiAttachHook();
    }

    return 0;
}

//setup menus
extc t_menu* ODBG2_Pluginmenu(wchar_t *type)
{
    if (wcscmp(type, PWM_MAIN) == 0) {
        // add profiles to menu
        for (size_t i = 0; i < g_settings.profile_names().size(); i++)
        {
            profilemenu[i] = {
                (wchar_t *)&g_settings.profile_names()[i][0], (wchar_t *)&g_settings.profile_names()[i][0], K_NONE, Mprofiles, NULL, { i }
            };
        }
        t_menu menu_end = { NULL, NULL, K_NONE, NULL, NULL, 0 };
        profilemenu[g_settings.profile_names().size()] = menu_end;

        return mainmenu;
    }
    else if (wcscmp(type, PWM_THREADS) == 0)
        return threadmenu;

    return NULL;
}

//called for every debugloop pass
extc void ODBG2_Pluginmainloop(DEBUG_EVENT *debugevent)
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
        // TODO // FIXME // WTF
        // This is copied from the Olly v1 plugin since at least some (all?) of its exception handling problems seem to have carried over to v2.
        // 1. Figure out which of these are still relevant. At the very least this includes debug prints (https://github.com/x64dbg/ScyllaHide/issues/44)
        // 2. Add v2 version of IsAddressBreakPoint() for handleExceptionBreakpoint / handleExceptionWx86Breakpoint (currently ignored)
        if (g_settings.opts().handleExceptionPrint ||
            g_settings.opts().handleExceptionRip ||
            g_settings.opts().handleExceptionIllegalInstruction ||
            g_settings.opts().handleExceptionInvalidLockSequence ||
            g_settings.opts().handleExceptionNoncontinuableException ||
            g_settings.opts().handleExceptionGuardPageViolation
            )
        {
            if (!debugLoopHooked)
            {
                HookDebugLoop();
                debugLoopHooked = true;
            }
        }

        ProcessId = debugevent->dwProcessId;
        bHooked = false;
        ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));

        if (debugevent->u.CreateProcessInfo.lpStartAddress == NULL)
        {
            //ATTACH
            if (g_settings.opts().killAntiAttach)
            {
                if (!ApplyAntiAntiAttach(ProcessId))
                {
                    MessageBoxW(hwollymain, L"Anti-Anti-Attach failed", L"Error", MB_ICONERROR);
                }
            }
        }

        //change olly caption again !
        SetWindowTextW(hwollymain, g_settings.opts().ollyWindowTitle.c_str());
    }
    break;
    case LOAD_DLL_DEBUG_EVENT:
    {
        if (bHooked)
        {
            startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), false);
        }
        break;
    }
    case EXCEPTION_DEBUG_EVENT:
    {
        switch (debugevent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (!bHooked)
            {
                ReadNtApiInformation(&g_hdd);

                bHooked = true;
                startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
            }
        }
        break;
        }
    }
    break;
    }
}

//reset variables. new target started or restarted
extc void ODBG2_Pluginreset(void)
{
    bHooked = false;
    ProcessId = 0;
}

BOOL WINAPI DllMain(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        hinst = hi;
        _AttachProcess = AttachProcess;
        hNtdllModule = GetModuleHandleW(L"ntdll.dll");

        auto wstrPath = scl::GetModuleFileNameW(hi);
        wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);

        g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
        g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;

        auto log_file = wstrPath + scl::Logger::kFileName;
        g_log.SetLogFile(log_file.c_str());
        g_log.SetLogCb(scl::Logger::Info, LogCallback);
        g_log.SetLogCb(scl::Logger::Error, LogErrorCallback);
    }
    return TRUE;
};
