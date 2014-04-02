#include <windows.h>
#include "resource.h"
#include "Injector.h"

//scyllaHide definitions
struct HideOptions pHideOptions;

#define SCYLLAHIDE_VERSION "0.1"

//olly definitions
#define PLUGIN_VERSION 110
#define PM_MAIN 0

//globals
static HINSTANCE hinst;
static DWORD ProcessId;
HWND hwmain; // Handle of main OllyDbg window

static void ScyllaHide(DWORD ProcessId) {
    WCHAR * dllPath = 0;

    dllPath = L".\\HookLibrary.dll";

    SetDebugPrivileges();
    startInjection(ProcessId, dllPath);
}

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved) {
    if (reason==DLL_PROCESS_ATTACH)
        hinst=hi;
    return 1;
};

void SaveOptions(HWND hWnd) {
    //read all checkboxes
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_GETCHECK, 0, 0)) {
        pHideOptions.PEB = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONTHREAD), BM_GETCHECK, 0, 0)) {
        pHideOptions.NtSetInformationThread = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMINFORMATION), BM_GETCHECK, 0, 0)) {
        pHideOptions.NtQuerySystemInformation = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYINFORMATIONPROCESS), BM_GETCHECK, 0, 0)) {
        pHideOptions.NtQueryInformationProcess = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYOBJECT), BM_GETCHECK, 0, 0)) {
        pHideOptions.NtQueryObject = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTYIELDEXECUTION), BM_GETCHECK, 0, 0)) {
        pHideOptions.NtYieldExecution = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_GETCHECK, 0, 0)) {
        pHideOptions.GetTickCount = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), BM_GETCHECK, 0, 0)) {
        pHideOptions.OutputDebugStringA = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_BLOCKINPUT), BM_GETCHECK, 0, 0)) {
        pHideOptions.BlockInput = 1;
    }
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_GETCHECK, 0, 0)) {
        pHideOptions.ProtectDrx = 1;
    }

    //save all options
    _Pluginwriteinttoini(hinst, "PEB", pHideOptions.PEB);
    _Pluginwriteinttoini(hinst, "NtSetInformationThread", pHideOptions.NtSetInformationThread);
    _Pluginwriteinttoini(hinst, "NtQuerySystemInformation", pHideOptions.NtQuerySystemInformation);
    _Pluginwriteinttoini(hinst, "NtQueryInformationProcess", pHideOptions.NtQueryInformationProcess);
    _Pluginwriteinttoini(hinst, "NtQueryObject", pHideOptions.NtQueryObject);
    _Pluginwriteinttoini(hinst, "NtYieldExecution", pHideOptions.NtYieldExecution);
    _Pluginwriteinttoini(hinst, "GetTickCount", pHideOptions.GetTickCount);
    _Pluginwriteinttoini(hinst, "OutputDebugStringA", pHideOptions.OutputDebugStringA);
    _Pluginwriteinttoini(hinst, "BlockInput", pHideOptions.BlockInput);
    _Pluginwriteinttoini(hinst, "ProtectDrx", pHideOptions.ProtectDrx);
}

void LoadOptions(HWND hWnd) {
    //load all options
    pHideOptions.PEB = _Pluginreadintfromini(hinst, "PEB", pHideOptions.PEB);
    pHideOptions.NtSetInformationThread = _Pluginreadintfromini(hinst, "NtSetInformationThread", pHideOptions.NtSetInformationThread);
    pHideOptions.NtQuerySystemInformation = _Pluginreadintfromini(hinst, "NtQuerySystemInformation", pHideOptions.NtQuerySystemInformation);
    pHideOptions.NtQueryInformationProcess = _Pluginreadintfromini(hinst, "NtQueryInformationProcess", pHideOptions.NtQueryInformationProcess);
    pHideOptions.NtQueryObject = _Pluginreadintfromini(hinst, "NtQueryObject", pHideOptions.NtQueryObject);
    pHideOptions.NtYieldExecution = _Pluginreadintfromini(hinst, "NtYieldExecution", pHideOptions.NtYieldExecution);
    pHideOptions.GetTickCount = _Pluginreadintfromini(hinst, "GetTickCount", pHideOptions.GetTickCount);
    pHideOptions.OutputDebugStringA = _Pluginreadintfromini(hinst, "OutputDebugStringA", pHideOptions.OutputDebugStringA);
    pHideOptions.BlockInput = _Pluginreadintfromini(hinst, "BlockInput", pHideOptions.BlockInput);
    pHideOptions.ProtectDrx = _Pluginreadintfromini(hinst, "ProtectDrx", pHideOptions.ProtectDrx);

    //set all options in GUI
    SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, pHideOptions.PEB, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONTHREAD), BM_SETCHECK, pHideOptions.NtSetInformationThread, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMINFORMATION), BM_SETCHECK, pHideOptions.NtQuerySystemInformation, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYINFORMATIONPROCESS), BM_SETCHECK, pHideOptions.NtQueryInformationProcess, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYOBJECT), BM_SETCHECK, pHideOptions.NtQueryObject, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTYIELDEXECUTION), BM_SETCHECK, pHideOptions.NtYieldExecution, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_SETCHECK, pHideOptions.GetTickCount, 0);
    SendMessage(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), BM_SETCHECK, pHideOptions.OutputDebugStringA, 0);
    SendMessage(GetDlgItem(hWnd, IDC_BLOCKINPUT), BM_SETCHECK, pHideOptions.BlockInput, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, pHideOptions.ProtectDrx, 0);
}

//options dialog proc
INT_PTR CALLBACK OptionsProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG: {
        LoadOptions(hWnd);
        break;
    }
    case WM_CLOSE: {
        EndDialog(hWnd, NULL);
    }
    break;

    case WM_COMMAND: {
        switch(LOWORD(wParam)) {
        case IDOK: {
            //save options to ini
            SaveOptions(hWnd);
            MessageBoxA(hWnd, "Please restart Olly to apply changes !", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
            EndDialog(hWnd, NULL);
            break;
        }
        }
    }
    break;

    default: {
        return FALSE;
    }
    }

    return 0;
}

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

    HideOptions pHideOptions = {};

    _Addtolist(0,0,"ScyllaHide Plugin v"SCYLLAHIDE_VERSION);
    _Addtolist(0,-1,"  Copyright (C) 2014 Aguila / cypher");

    return 0;
};

//add menu entries
extern "C" int __declspec(dllexport) _ODBG_Pluginmenu(int origin,char data[4096],void *item) {
    switch(origin) {
    case PM_MAIN: {
        strcpy(data, "0 &Options|1 &About");
        return 1;
    }

    default:
        break;
    }

    return 0;
}

//handle plugin actions
extern "C" void __declspec(dllexport) _ODBG_Pluginaction(int origin,int action,void *item) {
    if(origin==PM_MAIN) {
        switch(action) {
        case 0: {
            DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwmain, &OptionsProc);
            break;
        }
        case 1: {
            MessageBoxA(hwmain,
                        "ScyllaHide Plugin v"SCYLLAHIDE_VERSION"\n"
                        "(Anti-Anti-Debug in usermode)\n\n"
                        "Copyright (C) 2014 Aguila / cypher",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
            break;
        }
        default:
            break;
        }
    }
}

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