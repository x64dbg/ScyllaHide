#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include "plugin.h"
#include "Injector.h"

#include "..\InjectorCLI\ReadNtConfig.h"

//scyllaHide definitions
struct HideOptions pHideOptions;

#define PLUGINNAME     L"ScyllaHide"
#define VERSION        L"0.2"

const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};

extern HOOK_DLL_EXCHANGE DllExchangeLoader;

//forward definitions
static int Moptions(t_table *pt,wchar_t *name,ulong index,int mode);
static int Mabout(t_table *pt,wchar_t *name,ulong index,int mode);

//globals
HINSTANCE hinst;

//menus
static t_menu mainmenu[] =
{
    {
        L"Options",
        L"Select Hiding Options",
        K_NONE, Moptions, NULL, 0
    },
    {
        L"|About",
        L"About ScyllaHide plugin",
        K_NONE, Mabout, NULL, 0
    },
    { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

//I'd rather directly use pHideOptions.PEB but these control
//variables need to be static which pHideOptions cannot be because
//Injector.cpp externs it :/
static int opt_peb;
static int opt_NtSetInformationThread;
static int opt_NtQuerySystemInformation;
static int opt_NtQueryInformationProcess;
static int opt_NtQueryObject;
static int opt_NtYieldExecution;
static int opt_GetTickCount;
static int opt_OutputDebugStringA;
static int opt_BlockInput;
static int opt_ProtectDRx;
static int opt_NtUserFindWindowEx;
static int opt_NtUserBuildHwndList;
static int opt_NtUserQueryWindow;
static int opt_NtSetDebugFilterState;
static int opt_NtClose;
static WCHAR opt_ollyTitle[TEXTLEN] = {};

static t_control scyllahideoptions[] =
{
    {
        CA_COMMENT, -1, 0, 0, 0, 0, NULL,
        PLUGINNAME,
        NULL
    },
    {
        CA_TITLE, OPT_TITLE, 80, 4, 160, 15, NULL,
        PLUGINNAME,
        NULL
    },
    {
        CA_CHECK, OPT_1, 90, 30, 80, 10, &opt_peb,
        L"Hide from PEB",
        L"BeingDebugged, NtGlobalFlag, Heap Flags"
    },
    {
        CA_CHECK, OPT_2, 90, 42, 80, 10, &opt_NtSetInformationThread,
        L"NtSetInformationThread",
        L"ThreadHideFromDebugger"
    },
    {
        CA_CHECK, OPT_3, 90, 54, 80, 10, &opt_NtQuerySystemInformation,
        L"NtQuerySystemInformation",
        L"SystemKernelDebuggerInformation, SystemProcessInformation"
    },
    {
        CA_CHECK, OPT_4, 90, 66, 80, 10, &opt_NtQueryInformationProcess,
        L"NtQueryInformationProcess",
        L"ProcessDebugFlags, ProcessDebugObjectHandle, ProcessDebugPort, ProcessBasicInformation"
    },
    {
        CA_CHECK, OPT_5, 90, 78, 80, 10, &opt_NtQueryObject,
        L"NtQueryObject",
        L"ObjectTypesInformation, ObjectTypeInformation"
    },
    {
        CA_CHECK, OPT_6, 90, 90, 80, 10, &opt_NtYieldExecution,
        L"NtYieldExecution",
        L"NtYieldExecution"
    },
    {
        CA_CHECK, OPT_7, 90, 102, 80, 10, &opt_GetTickCount,
        L"GetTickCount",
        L"GetTickCount"
    },
    {
        CA_CHECK, OPT_8, 90, 114, 80, 10, &opt_OutputDebugStringA,
        L"OutputDebugStringA",
        L"OutputDebugStringA"
    },
    {
        CA_CHECK, OPT_9, 90, 126, 80, 10, &opt_BlockInput,
        L"BlockInput",
        L"BlockInput"
    },
    {
        CA_CHECK, OPT_10, 90, 138, 80, 10, &opt_NtUserFindWindowEx,
        L"NtUserFindWindowEx",
        L"NtUserFindWindowEx"
    },
    {
        CA_CHECK, OPT_11, 90, 150, 80, 10, &opt_NtUserBuildHwndList,
        L"NtUserBuildHwndList",
        L"NtUserBuildHwndList"
    },
    {
        CA_CHECK, OPT_12, 90, 162, 80, 10, &opt_NtUserQueryWindow,
        L"NtUserQueryWindow",
        L"NtUserQueryWindow"
    },
    {
        CA_CHECK, OPT_13, 90, 174, 80, 10, &opt_NtSetDebugFilterState,
        L"NtSetDebugFilterState",
        L"NtSetDebugFilterState"
    },
    {
        CA_CHECK, OPT_14, 90, 186, 80, 10, &opt_NtClose,
        L"NtClose",
        L"NtClose"
    },
    {
        CA_GROUP, -1, 85, 20, 85, 178, NULL,
        L"Debugger Hiding",
        NULL
    },
    {
        CA_CHECK, OPT_15, 90, 212, 80, 10, &opt_ProtectDRx,
        L"Protect DRx",
        L"NtGetContextThread, NtSetContextThread, NtContinue"
    },
    {
        CA_GROUP, -1, 85, 202, 85, 25, NULL,
        L"DRx Protection",
        NULL
    },
    //second column
    {
        CA_TEXT, NULL, 180, 30, 30, 10, NULL,
        L"Olly title",
        L"Olly title"
    },
    {
        CA_EDIT, OPT_16, 200, 30, 40, 10, NULL,
        opt_ollyTitle,
        L"Olly title"
    },
    {
        CA_GROUP, -1, 175, 20, 70, 25, NULL,
        L"Misc",
        NULL
    },
    {
        CA_END, -1, 0, 0, 0, 0, NULL,
        NULL,
        NULL
    }
};

//Menu->Options
static int Moptions(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        Pluginshowoptions(scyllahideoptions);
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->About
static int Mabout(t_table *pt,wchar_t *name,ulong index,int mode)
{
    int n;
    wchar_t s[TEXTLEN];
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        // Debuggee should continue execution while message box is displayed.
        Resumeallthreads();

        n=StrcopyW(s,TEXTLEN,L"ScyllaHide plugin v");
        n+=StrcopyW(s+n,TEXTLEN-n,VERSION);
        n+=StrcopyW(s+n,TEXTLEN-n,L"\n(Anti-Anti-Debug in usermode)\n\n");
        n+=StrcopyW(s+n,TEXTLEN-n,L"\nCopyright (C) 2014 Aguila / cypher");

        MessageBox(hwollymain,s,
                   L"ScyllaHide plugin",MB_OK|MB_ICONINFORMATION);

        // Suspendallthreads() and Resumeallthreads() must be paired, even if they
        // are called in inverse order!
        Suspendallthreads();
        return MENU_NOREDRAW;
    };
    return MENU_ABSENT;
}
//menus

void UpdateHideOptions()
{
    pHideOptions.PEB = opt_peb;
    pHideOptions.NtSetInformationThread = opt_NtSetInformationThread;
    pHideOptions.NtQueryInformationProcess = opt_NtQueryInformationProcess;
    pHideOptions.NtQuerySystemInformation = opt_NtQuerySystemInformation;
    pHideOptions.NtQueryObject = opt_NtQueryObject;
    pHideOptions.NtYieldExecution = opt_NtYieldExecution;
    pHideOptions.GetTickCount = opt_GetTickCount;
    pHideOptions.OutputDebugStringA = opt_OutputDebugStringA;
    pHideOptions.BlockInput = opt_BlockInput;
    pHideOptions.ProtectDrx = opt_ProtectDRx;
    pHideOptions.NtUserFindWindowEx = opt_NtUserFindWindowEx;
    pHideOptions.NtUserBuildHwndList = opt_NtUserBuildHwndList;
    pHideOptions.NtUserQueryWindow = opt_NtUserQueryWindow;
    pHideOptions.NtSetDebugFilterState = opt_NtSetDebugFilterState;
    pHideOptions.NtClose = opt_NtClose;
    wcscpy(pHideOptions.ollyTitle, opt_ollyTitle);

    //change olly caption
    SetWindowTextW(hwollymain, pHideOptions.ollyTitle);
}

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{
    if (reason==DLL_PROCESS_ATTACH)
    {
        GetModuleFileNameW(hi, NtApiIniPath, _countof(NtApiIniPath));
        WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
        if (temp)
        {
            temp++;
            *temp = 0;
            wcscpy(ScyllaHideDllPath, NtApiIniPath);
            wcscat(ScyllaHideDllPath, ScyllaHideDllFilename);
            wcscat(NtApiIniPath, NtApiIniFilename);
        }

        hinst=hi;
    }
    return TRUE;
};

//register plugin
extc int ODBG2_Pluginquery(int ollydbgversion,ulong *features, wchar_t pluginname[SHORTNAME],wchar_t pluginversion[SHORTNAME])
{
    if (ollydbgversion<201)
        return 0;

    wcscpy(pluginname,PLUGINNAME);
    wcscpy(pluginversion,VERSION);

    return PLUGIN_VERSION;
};

//initialization happens in here
extc int __cdecl ODBG2_Plugininit(void)
{
    //we cant read them directly to pHideOptions
    //because control vars need to be static and pHideOptions to be extern
    Getfromini(NULL,PLUGINNAME,L"PEB",L"%i",&opt_peb);
    Getfromini(NULL,PLUGINNAME,L"NtSetInformationThread",L"%i",&opt_NtSetInformationThread);
    Getfromini(NULL,PLUGINNAME,L"NtQuerySystemInformation",L"%i",&opt_NtQuerySystemInformation);
    Getfromini(NULL,PLUGINNAME,L"NtQueryInformationProcess",L"%i",&opt_NtQueryInformationProcess);
    Getfromini(NULL,PLUGINNAME,L"NtQueryObject",L"%i",&opt_NtQueryObject);
    Getfromini(NULL,PLUGINNAME,L"NtYieldExecution",L"%i",&opt_NtYieldExecution);
    Getfromini(NULL,PLUGINNAME,L"GetTickCount",L"%i",&opt_GetTickCount);
    Getfromini(NULL,PLUGINNAME,L"OutputDebugStringA",L"%i",&opt_OutputDebugStringA);
    Getfromini(NULL,PLUGINNAME,L"BlockInput",L"%i",&opt_BlockInput);
    Getfromini(NULL,PLUGINNAME,L"ProtectDRx",L"%i",&opt_ProtectDRx);
    Getfromini(NULL,PLUGINNAME,L"NtUserFindWindowEx",L"%i",&opt_NtUserFindWindowEx);
    Getfromini(NULL,PLUGINNAME,L"NtUserBuildHwndList",L"%i",&opt_NtUserBuildHwndList);
    Getfromini(NULL,PLUGINNAME,L"NtUserQueryWindow",L"%i",&opt_NtUserQueryWindow);
    Getfromini(NULL,PLUGINNAME,L"NtSetDebugFilterState",L"%i",&opt_NtSetDebugFilterState);
    Getfromini(NULL,PLUGINNAME,L"NtClose",L"%i",&opt_NtClose);
    Getfromini(NULL, PLUGINNAME, L"ollyTitle", L"%s", &opt_ollyTitle);

    UpdateHideOptions();

    //change olly caption
    SetWindowTextW(hwollymain, pHideOptions.ollyTitle);

    return 0;
}

//setup menus
extc t_menu* ODBG2_Pluginmenu(wchar_t *type)
{
    if (wcscmp(type,PWM_MAIN)==0)
        return mainmenu;

    return NULL;
};

//options dialogproc
extc t_control* ODBG2_Pluginoptions(UINT msg,WPARAM wp,LPARAM lp)
{
    if(msg==WM_COMMAND) {
        WORD bla = LOWORD(wp);
        if(LOWORD(wp)==OPT_16) {
            //yes this is hacky but for some reason CA_EDIT wont update its buffer
            //so we need to get changes somehow else
            HWND options = FindWindow(L"OD_EMPTY", L"Plugin options");
            if(options) {
                GetDlgItemTextW(options, OPT_16, opt_ollyTitle, 256);
            }
        }
    }
    if (msg==WM_CLOSE && wp!=0)
    {
        // User pressed OK in the Plugin options dialog. Options are updated, save them to the .ini file.
        Writetoini(NULL,PLUGINNAME,L"PEB",L"%i",opt_peb);
        Writetoini(NULL,PLUGINNAME,L"NtSetInformationThread",L"%i",opt_NtSetInformationThread);
        Writetoini(NULL,PLUGINNAME,L"NtQuerySystemInformation",L"%i",opt_NtQuerySystemInformation);
        Writetoini(NULL,PLUGINNAME,L"NtQueryInformationProcess",L"%i",opt_NtQueryInformationProcess);
        Writetoini(NULL,PLUGINNAME,L"NtQueryObject",L"%i",opt_NtQueryObject);
        Writetoini(NULL,PLUGINNAME,L"NtYieldExecution",L"%i",opt_NtYieldExecution);
        Writetoini(NULL,PLUGINNAME,L"GetTickCount",L"%i",opt_GetTickCount);
        Writetoini(NULL,PLUGINNAME,L"OutputDebugStringA",L"%i",opt_OutputDebugStringA);
        Writetoini(NULL,PLUGINNAME,L"BlockInput",L"%i",opt_BlockInput);
        Writetoini(NULL,PLUGINNAME,L"ProtectDRx",L"%i",opt_ProtectDRx);
        Writetoini(NULL,PLUGINNAME,L"NtUserFindWindowEx",L"%i",opt_NtUserFindWindowEx);
        Writetoini(NULL,PLUGINNAME,L"NtUserBuildHwndList",L"%i",opt_NtUserBuildHwndList);
        Writetoini(NULL,PLUGINNAME,L"NtUserQueryWindow",L"%i",opt_NtUserQueryWindow);
        Writetoini(NULL,PLUGINNAME,L"NtSetDebugFilterState",L"%i",opt_NtSetDebugFilterState);
        Writetoini(NULL,PLUGINNAME,L"NtClose",L"%i",opt_NtClose);
        Writetoini(NULL,PLUGINNAME,L"ollyTitle", L"%s",opt_ollyTitle);

        UpdateHideOptions();

        MessageBoxW(hwollymain, L"Please restart the target to apply changes !", L"[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
    };
    // It makes no harm to return page descriptor on all messages.
    return scyllahideoptions;
};

//called for every debugloop pass
extc void ODBG2_Pluginmainloop(DEBUG_EVENT *debugevent)
{
    static DWORD ProcessId;
    static bool bHooked;

    if(!debugevent)
        return;
    switch(debugevent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        ProcessId = debugevent->dwProcessId;
        bHooked = false;
		ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
    }
    break;
    case LOAD_DLL_DEBUG_EVENT:
    {
        if (bHooked)
        {
            startInjection(ProcessId, ScyllaHideDllPath, false);
        }
        break;
    }
    case EXCEPTION_DEBUG_EVENT:
    {
        switch(debugevent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (!bHooked)
            {
                bHooked = true;
                Message(0, L"[ScyllaHide] Reading NT API Information %s", NtApiIniPath);
                ReadNtApiInformation();
                startInjection(ProcessId, ScyllaHideDllPath, true);
            }
        }
        break;
        }
    }
    break;
    }
}
