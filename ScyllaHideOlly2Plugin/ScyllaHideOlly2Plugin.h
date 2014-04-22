#pragma once
#include "plugin.h"

#define PLUGINNAME     L"ScyllaHide"
#define VERSION        L"0.4"

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
