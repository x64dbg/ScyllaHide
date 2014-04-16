#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include "ScyllaHideOlly2Plugin.h"
#include "Injector.h"

#include "..\InjectorCLI\ReadNtConfig.h"

//scyllaHide definitions
struct HideOptions pHideOptions = {0};

const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};

extern HOOK_DLL_EXCHANGE DllExchangeLoader;

//globals
HINSTANCE hinst;

HMODULE hNtdll = 0;
bool specialPebFix = false;


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

static int Mthreads(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        t_table threadWindow = thread;
        int threadCount = threadWindow.sorted.n;
        int threadSize = threadWindow.sorted.itemsize;
        t_thread* threadData = (t_thread*)threadWindow.sorted.data;

        switch(index)
        {
        case 0:
        {
            //Resumeallthreads(); doesnt work as expected
            for(int i=0; i<threadCount; i++) {
                ResumeThread(threadData->thread);

                //yup this is super-hacky-pointer-kungfu but threadData++ wont work coz there
                //is 0x20bytes extra data between thread elements
                threadData = reinterpret_cast<t_thread*>((DWORD)threadData+threadSize);
            }
            break;
        }
        case 1:
        {
            //Suspendallthreads(); doesnt work as expected
            for(int i=0; i<threadCount; i++) {
                SuspendThread(threadData->thread);

                //yup this is super-hacky-pointer-kungfu but threadData++ wont work coz there
                //is 0x20bytes extra data between thread elements
                threadData = reinterpret_cast<t_thread*>((DWORD)threadData+threadSize);
            }
            break;
        }
        }
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
    pHideOptions.NtGetContextThread = opt_NtGetContextThread;
    pHideOptions.NtSetContextThread = opt_NtSetContextThread;
    pHideOptions.NtContinue = opt_NtContinue;
    pHideOptions.KiUserExceptionDispatcher = opt_KiUserExceptionDispatcher;
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
        hNtdll = GetModuleHandleW(L"ntdll.dll");
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
    Getfromini(NULL,PLUGINNAME,L"NtGetContextThread",L"%i",&opt_NtGetContextThread);
    Getfromini(NULL,PLUGINNAME,L"NtSetContextThread",L"%i",&opt_NtSetContextThread);
    Getfromini(NULL,PLUGINNAME,L"NtContinue",L"%i",&opt_NtContinue);
    Getfromini(NULL,PLUGINNAME,L"KiUserExceptionDispatcher",L"%i",&opt_KiUserExceptionDispatcher);
    Getfromini(NULL,PLUGINNAME,L"NtUserFindWindowEx",L"%i",&opt_NtUserFindWindowEx);
    Getfromini(NULL,PLUGINNAME,L"NtUserBuildHwndList",L"%i",&opt_NtUserBuildHwndList);
    Getfromini(NULL,PLUGINNAME,L"NtUserQueryWindow",L"%i",&opt_NtUserQueryWindow);
    Getfromini(NULL,PLUGINNAME,L"NtSetDebugFilterState",L"%i",&opt_NtSetDebugFilterState);
    Getfromini(NULL,PLUGINNAME,L"NtClose",L"%i",&opt_NtClose);
    Getfromini(NULL, PLUGINNAME, L"ollyTitle", L"%s", &opt_ollyTitle);

    if(opt_NtGetContextThread && opt_NtSetContextThread && opt_NtContinue && opt_KiUserExceptionDispatcher) opt_ProtectDRx = 1;

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
    else if(wcscmp(type, PWM_THREADS)==0)
        return threadmenu;

    return NULL;
};

//options dialogproc
extc t_control* ODBG2_Pluginoptions(UINT msg,WPARAM wp,LPARAM lp)
{
    if(msg==WM_COMMAND) {
        switch(LOWORD(wp)) {
        case OPT_20: //olly title edit
        {
            //yes this is hacky but for some reason CA_EDIT wont update its buffer
            //so we need to get changes somehow else
            HWND options = FindWindow(L"OD_EMPTY", L"Plugin options");
            if(options) {
                GetDlgItemTextW(options, OPT_16, opt_ollyTitle, 256);
            }
            break;
        }
        case OPT_19: //protect drx groupbox checkbox
        {
            WPARAM state;
            HWND options = FindWindow(L"OD_EMPTY", L"Plugin options");
            if(!options) break;

            (BST_CHECKED == SendMessage(GetDlgItem(options, OPT_19), BM_GETCHECK, 0, 0))?state=1:state=0;

            //trigger child checkboxes
            SendMessage(GetDlgItem(options, OPT_15), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(options, OPT_16), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(options, OPT_17), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(options, OPT_18), BM_SETCHECK, state, 0);
            opt_NtGetContextThread = state;
            opt_NtSetContextThread = state;
            opt_NtContinue = state;
            opt_KiUserExceptionDispatcher = state;

            break;
        }
        case OPT_15:
        case OPT_16:
        case OPT_17:
        case OPT_18:
        {   //this is just for GUI continuity
            HWND options = FindWindow(L"OD_EMPTY", L"Plugin options");
            if(!options) break;

            int allChecked = 1;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(options, OPT_15), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(options, OPT_16), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(options, OPT_17), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(options, OPT_18), BM_GETCHECK, 0, 0)) allChecked--;

            if(allChecked<1) SendMessage(GetDlgItem(options, OPT_19), BM_SETCHECK, 0, 0);
            else SendMessage(GetDlgItem(options, OPT_19), BM_SETCHECK, 1, 0);

            break;
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
        Writetoini(NULL,PLUGINNAME,L"NtGetContextThread",L"%i",opt_NtGetContextThread);
        Writetoini(NULL,PLUGINNAME,L"NtSetContextThread",L"%i",opt_NtSetContextThread);
        Writetoini(NULL,PLUGINNAME,L"NtContinue",L"%i",opt_NtContinue);
        Writetoini(NULL,PLUGINNAME,L"KiUserExceptionDispatcher",L"%i",opt_KiUserExceptionDispatcher);
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


    if (pHideOptions.PEB)
    {
        if (specialPebFix)
        {
            StartFixBeingDebugged(ProcessId, false);
            specialPebFix = false;
        }

        if (debugevent->u.LoadDll.lpBaseOfDll == hNtdll)
        {
            StartFixBeingDebugged(ProcessId, true);
            specialPebFix = true;
        }
    }

    switch(debugevent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        ProcessId = debugevent->dwProcessId;
        bHooked = false;
        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

        //change olly caption again !
        SetWindowTextW(hwollymain, pHideOptions.ollyTitle);
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
