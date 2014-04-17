#pragma once
#include "plugin.h"

#define PLUGINNAME     L"ScyllaHide"
#define VERSION        L"0.3"

static int Moptions(t_table *pt,wchar_t *name,ulong index,int mode);
static int Mthreads(t_table *pt,wchar_t *name,ulong index,int mode);
static int Mabout(t_table *pt,wchar_t *name,ulong index,int mode);

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
static int opt_NtGetContextThread;
static int opt_NtSetContextThread;
static int opt_NtContinue;
static int opt_KiUserExceptionDispatcher;
static int opt_NtUserFindWindowEx;
static int opt_NtUserBuildHwndList;
static int opt_NtUserQueryWindow;
static int opt_NtSetDebugFilterState;
static int opt_NtClose;
static WCHAR opt_ollyTitle[TEXTLEN] = {};

//NOTE: if you change OPT_X make sure to also adjust them in ODBG2_Pluginoptions
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
    //second column
    {
        CA_CHECK, OPT_15, 180, 30, 40, 10, &opt_NtGetContextThread,
        L"NtGetContextThread",
        L"NtGetContextThread"
    },
    {
        CA_CHECK, OPT_16, 180, 42, 40, 10, &opt_NtSetContextThread,
        L"NtSetContextThread",
        L"NtSetContextThread"
    },
    {
        CA_CHECK, OPT_17, 180, 54, 40, 10, &opt_NtContinue,
        L"NtContinue",
        L"NtContinue"
    },
    {
        CA_CHECK, OPT_18, 180, 66, 40, 10, &opt_KiUserExceptionDispatcher,
        L"KiUserExceptionDisp.",
        L"KiUserExceptionDispatcher"
    },
    {
        CA_CHECK, OPT_19, 220, 20, 5, 10, &opt_ProtectDRx,
        L"",
        L"Protect DRx"
    },
    {
        CA_GROUP, -1, 175, 20, 70, 60, NULL,
        L"DRx Protection",
        NULL
    },
    {
        CA_TEXT, NULL, 180, 95, 40, 10, NULL,
        L"Olly title",
        L"Olly title"
    },
    {
        CA_EDIT, OPT_20, 200, 95, 40, 10, NULL,
        opt_ollyTitle,
        L"Olly title"
    },
    {
        CA_GROUP, -1, 175, 85, 70, 25, NULL,
        L"Misc",
        NULL
    },
    {
        CA_END, -1, 0, 0, 0, 0, NULL,
        NULL,
        NULL
    }
};
