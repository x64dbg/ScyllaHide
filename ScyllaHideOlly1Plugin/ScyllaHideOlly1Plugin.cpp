#include <windows.h>
#include "Injector.h"

#define SCYLLAHIDE_VERSION "0.1"

//olly definitions
#define PLUGIN_VERSION 110

//globals
HINSTANCE hinst;
static DWORD ProcessId;
HWND hwmain; // Handle of main OllyDbg window

static void ScyllaHide(DWORD ProcessId) {
    WCHAR * dllPath = 0;

#ifdef _WIN64
    dllPath = L".\\HookLibrary.dll";
#else
    dllPath = L".\\HookLibrary.dll";
#endif

    SetDebugPrivileges();
    startInjection(ProcessId, dllPath);
}

BOOL WINAPI DllEntryPoint(HINSTANCE hi,DWORD reason,LPVOID reserved) {
    if (reason==DLL_PROCESS_ATTACH)
        hinst=hi;
    return 1;
};

//register plugin with name
extern "C" int __declspec(dllexport) _ODBG_Plugindata(char shortname[32]) {
    strcpy(shortname,"ScyllaHide");
    return PLUGIN_VERSION;
};

//initialization happens in here
extern "C" int __declspec(dllexport) _ODBG_Plugininit(int ollydbgversion,HWND hw,unsigned long *features) {
    if (ollydbgversion<PLUGIN_VERSION)
        return -1;

    hwmain=hw;

    _Addtolist(0,0,"ScyllaHide Plugin v"SCYLLAHIDE_VERSION);
    _Addtolist(0,-1,"  Copyright (C) 2014 Aguila / cypher");

    return 0;
};

//called for every debugloop pass
extern "C" void __declspec(dllexport) _ODBG_Pluginmainloop(DEBUG_EVENT *debugevent) {
    static HANDLE hProcess;
    static ULONG_PTR startAddress;

    if(!debugevent)
        return;
    switch(debugevent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        hProcess=debugevent->u.CreateProcessInfo.hProcess;
        ProcessId=debugevent->dwProcessId;
        startAddress = (ULONG_PTR)debugevent->u.CreateProcessInfo.lpStartAddress;
    }
    break;

    case EXCEPTION_DEBUG_EVENT:
    {
        switch(debugevent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            //are we at EP ?
            if(debugevent->u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)startAddress) {
                ScyllaHide(ProcessId);
            }
        }
        break;
        }
    }
    break;


    break;
    }
};