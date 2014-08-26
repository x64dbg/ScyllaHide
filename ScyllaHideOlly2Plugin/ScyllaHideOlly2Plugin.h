#pragma once
#include "plugin.h"
#include "..\PluginGeneric\ScyllaHideVersion.h"

#define PLUGINNAME     L"ScyllaHide"
#define MAX_PROFILES 128

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
void LogWrapper(const WCHAR * format, ...);
void LogErrorWrapper(const WCHAR * format, ...);

static int Moptions(t_table *pt,wchar_t *name,ulong index,int mode);
static int Mprofiles(t_table *pt,wchar_t *name,ulong index,int mode);
static int Mthreads(t_table *pt,wchar_t *name,ulong index,int mode);
static int Mupdate(t_table *pt,wchar_t *name,ulong index,int mode);
static int Mabout(t_table *pt,wchar_t *name,ulong index,int mode);
static int MinjectDll(t_table *pt,wchar_t *name,ulong index,int mode);
static int MattachProcess(t_table *pt,wchar_t *name,ulong index,int mode);

//menus
static t_menu profilemenu[MAX_PROFILES];

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
        L"|Update-Check",
        L"Check for Updates",
        K_NONE, Mupdate, NULL, 0
    },
    {
        L"About",
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
