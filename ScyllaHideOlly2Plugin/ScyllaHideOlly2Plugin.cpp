#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "resource.h"
#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include "..\PluginGeneric\Injector.h"
#include "ScyllaHideOlly2Plugin.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\UpdateCheck.h"
#include "..\PluginGeneric\IniSettings.h"


//scyllaHide definitions
struct HideOptions pHideOptions = {0};

const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};
WCHAR ScyllaHideIniPath[MAX_PATH] = {0};

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;

//globals
HINSTANCE hinst;

HMODULE hNtdllModule = 0;
bool specialPebFix = false;
static DWORD ProcessId = 0;
static bool bHooked = false;

bool GetFileDialog(TCHAR Buffer[MAX_PATH])
{
    OPENFILENAME sOpenFileName = {0};
    const TCHAR szFilterString[] = L"DLL \0*.dll\0\0";
    const TCHAR szDialogTitle[] = L"ScyllaHide";

    Buffer[0] = 0;

    sOpenFileName.lStructSize = sizeof(sOpenFileName);
    sOpenFileName.lpstrFilter = szFilterString;
    sOpenFileName.lpstrFile = Buffer;
    sOpenFileName.nMaxFile = MAX_PATH;
    sOpenFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
    sOpenFileName.lpstrTitle = szDialogTitle;

    return (!!GetOpenFileName(&sOpenFileName));
}

void SaveOptions(HWND hWnd)
{
    //read all checkboxes
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_GETCHECK, 0, 0))
    {
        pHideOptions.PEBBeingDebugged = 1;
    }
    else
        pHideOptions.PEBBeingDebugged = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_GETCHECK, 0, 0))
    {
        pHideOptions.PEBHeapFlags = 1;
    }
    else
        pHideOptions.PEBHeapFlags = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_GETCHECK, 0, 0))
    {
        pHideOptions.PEBNtGlobalFlag = 1;
    }
    else
        pHideOptions.PEBNtGlobalFlag = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_GETCHECK, 0, 0))
    {
        pHideOptions.PEBStartupInfo = 1;
    }
    else
        pHideOptions.PEBStartupInfo = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONTHREAD), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtSetInformationThread = 1;
    }
    else
        pHideOptions.NtSetInformationThread = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMINFORMATION), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtQuerySystemInformation = 1;
    }
    else
        pHideOptions.NtQuerySystemInformation = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYINFORMATIONPROCESS), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtQueryInformationProcess = 1;
    }
    else
        pHideOptions.NtQueryInformationProcess = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYOBJECT), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtQueryObject = 1;
    }
    else
        pHideOptions.NtQueryObject = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTYIELDEXECUTION), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtYieldExecution = 1;
    }
    else
        pHideOptions.NtYieldExecution = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), BM_GETCHECK, 0, 0))
    {
        pHideOptions.OutputDebugStringA = 1;
    }
    else
        pHideOptions.OutputDebugStringA = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_BLOCKINPUT), BM_GETCHECK, 0, 0))
    {
        pHideOptions.BlockInput = 1;
    }
    else
        pHideOptions.BlockInput = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTGETCONTEXTTHREAD), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtGetContextThread = 1;
    }
    else
        pHideOptions.NtGetContextThread = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETCONTEXTTHREAD), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtSetContextThread = 1;
    }
    else
        pHideOptions.NtSetContextThread = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCONTINUE), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtContinue = 1;
    }
    else
        pHideOptions.NtContinue = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_KIUED), BM_GETCHECK, 0, 0))
    {
        pHideOptions.KiUserExceptionDispatcher = 1;
    }
    else
        pHideOptions.KiUserExceptionDispatcher = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTUSERFINDWINDOWEX), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtUserFindWindowEx = 1;
    }
    else
        pHideOptions.NtUserFindWindowEx = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTUSERBUILDHWNDLIST), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtUserBuildHwndList = 1;
    }
    else
        pHideOptions.NtUserBuildHwndList = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTUSERQUERYWINDOW), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtUserQueryWindow = 1;
    }
    else
        pHideOptions.NtUserQueryWindow = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETDEBUGFILTERSTATE), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtSetDebugFilterState = 1;
    }
    else
        pHideOptions.NtSetDebugFilterState = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCLOSE), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtClose = 1;
    }
    else
        pHideOptions.NtClose = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCREATETHREADEX), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtCreateThreadEx = 1;
    }
    else
        pHideOptions.NtCreateThreadEx = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_REMOVEDEBUGPRIV), BM_GETCHECK, 0, 0))
    {
        pHideOptions.removeDebugPrivileges = 1;
    }
    else
        pHideOptions.removeDebugPrivileges = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PREVENTTHREADCREATION), BM_GETCHECK, 0, 0))
    {
        pHideOptions.preventThreadCreation = 1;
    }
    else
        pHideOptions.preventThreadCreation = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLSTEALTH), BM_GETCHECK, 0, 0))
    {
        pHideOptions.DLLStealth = 1;
    }
    else
        pHideOptions.DLLStealth = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLNORMAL), BM_GETCHECK, 0, 0))
    {
        pHideOptions.DLLNormal = 1;
    }
    else
        pHideOptions.DLLNormal = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLUNLOAD), BM_GETCHECK, 0, 0))
    {
        pHideOptions.DLLUnload = 1;
    }
    else
        pHideOptions.DLLUnload = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_GETCHECK, 0, 0))
    {
        pHideOptions.GetTickCount = 1;
    }
    else
        pHideOptions.GetTickCount = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT64), BM_GETCHECK, 0, 0))
    {
        pHideOptions.GetTickCount64 = 1;
    }
    else
        pHideOptions.GetTickCount64 = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETLOCALTIME), BM_GETCHECK, 0, 0))
    {
        pHideOptions.GetLocalTime = 1;
    }
    else
        pHideOptions.GetLocalTime = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETSYSTEMTIME), BM_GETCHECK, 0, 0))
    {
        pHideOptions.GetSystemTime = 1;
    }
    else
        pHideOptions.GetSystemTime = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMTIME), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtQuerySystemTime = 1;
    }
    else
        pHideOptions.NtQuerySystemTime = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYPERFCOUNTER), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtQueryPerformanceCounter = 1;
    }
    else
        pHideOptions.NtQueryPerformanceCounter = 0;

    GetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle, 33);
    SetWindowTextW(hwollymain, pHideOptions.ollyTitle);

    //save all options
	SaveSettings();
}


//options dialog proc
INT_PTR CALLBACK OptionsProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        ReadSettings();

        SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_SETCHECK, pHideOptions.PEBBeingDebugged, 0);
        SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_SETCHECK, pHideOptions.PEBHeapFlags, 0);
        SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_SETCHECK, pHideOptions.PEBNtGlobalFlag, 0);
        SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_SETCHECK, pHideOptions.PEBStartupInfo, 0);
        if(pHideOptions.PEBBeingDebugged && pHideOptions.PEBHeapFlags && pHideOptions.PEBNtGlobalFlag && pHideOptions.PEBStartupInfo)
            SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 1, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONTHREAD), BM_SETCHECK, pHideOptions.NtSetInformationThread, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMINFORMATION), BM_SETCHECK, pHideOptions.NtQuerySystemInformation, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTQUERYINFORMATIONPROCESS), BM_SETCHECK, pHideOptions.NtQueryInformationProcess, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTQUERYOBJECT), BM_SETCHECK, pHideOptions.NtQueryObject, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTYIELDEXECUTION), BM_SETCHECK, pHideOptions.NtYieldExecution, 0);
        SendMessage(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), BM_SETCHECK, pHideOptions.OutputDebugStringA, 0);
        SendMessage(GetDlgItem(hWnd, IDC_BLOCKINPUT), BM_SETCHECK, pHideOptions.BlockInput, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTGETCONTEXTTHREAD), BM_SETCHECK, pHideOptions.NtGetContextThread, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTSETCONTEXTTHREAD), BM_SETCHECK, pHideOptions.NtSetContextThread, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTCONTINUE), BM_SETCHECK, pHideOptions.NtContinue, 0);
        SendMessage(GetDlgItem(hWnd, IDC_KIUED), BM_SETCHECK, pHideOptions.KiUserExceptionDispatcher, 0);
        if(pHideOptions.NtGetContextThread && pHideOptions.NtSetContextThread && pHideOptions.NtContinue && pHideOptions.KiUserExceptionDispatcher)
            SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 1, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTUSERFINDWINDOWEX), BM_SETCHECK, pHideOptions.NtUserFindWindowEx, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTUSERBUILDHWNDLIST), BM_SETCHECK, pHideOptions.NtUserBuildHwndList, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTUSERQUERYWINDOW), BM_SETCHECK, pHideOptions.NtUserQueryWindow, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTSETDEBUGFILTERSTATE), BM_SETCHECK, pHideOptions.NtSetDebugFilterState, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTCLOSE), BM_SETCHECK, pHideOptions.NtClose, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTCREATETHREADEX), BM_SETCHECK, pHideOptions.NtCreateThreadEx, 0);
        SendMessage(GetDlgItem(hWnd, IDC_REMOVEDEBUGPRIV), BM_SETCHECK, pHideOptions.removeDebugPrivileges, 0);
        SendMessage(GetDlgItem(hWnd, IDC_PREVENTTHREADCREATION), BM_SETCHECK, pHideOptions.preventThreadCreation, 0);
        SetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle);
        SendMessage(GetDlgItem(hWnd, IDC_DLLSTEALTH), BM_SETCHECK, pHideOptions.DLLStealth, 0);
        SendMessage(GetDlgItem(hWnd, IDC_DLLNORMAL), BM_SETCHECK, pHideOptions.DLLNormal, 0);
        SendMessage(GetDlgItem(hWnd, IDC_DLLUNLOAD), BM_SETCHECK, pHideOptions.DLLUnload, 0);
        SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_SETCHECK, pHideOptions.GetTickCount, 0);
        SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT64), BM_SETCHECK, pHideOptions.GetTickCount64, 0);
        SendMessage(GetDlgItem(hWnd, IDC_GETLOCALTIME), BM_SETCHECK, pHideOptions.GetLocalTime, 0);
        SendMessage(GetDlgItem(hWnd, IDC_GETSYSTEMTIME), BM_SETCHECK, pHideOptions.GetSystemTime, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMTIME), BM_SETCHECK, pHideOptions.NtQuerySystemTime, 0);
        SendMessage(GetDlgItem(hWnd, IDC_NTQUERYPERFCOUNTER), BM_SETCHECK, pHideOptions.NtQueryPerformanceCounter, 0);

        break;
    }
    case WM_CLOSE:
    {
        EndDialog(hWnd, NULL);
    }
    break;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
        case IDOK:
        {
            //save options to ini
            SaveOptions(hWnd);

            if (ProcessId)
            {
                startInjection(ProcessId, ScyllaHideDllPath, true);
                bHooked = true;
                MessageBoxA(hWnd, "Applied changes! Restarting target is NOT necessary!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                MessageBoxA(hWnd, "Please start the target to apply changes!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
            }

            EndDialog(hWnd, NULL);
            break;
        }
        case IDC_PROTECTDRX:
        {
            WPARAM state;
            (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_GETCHECK, 0, 0))?state=1:state=0;

            //trigger child checkboxes
            SendMessage(GetDlgItem(hWnd, IDC_NTGETCONTEXTTHREAD), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(hWnd, IDC_NTSETCONTEXTTHREAD), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(hWnd, IDC_NTCONTINUE), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(hWnd, IDC_KIUED), BM_SETCHECK, state, 0);

            break;
        }
        case IDC_NTGETCONTEXTTHREAD:
        case IDC_NTSETCONTEXTTHREAD:
        case IDC_NTCONTINUE:
        case IDC_KIUED:
        {   //this is just for GUI continuity
            int allChecked = 1;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTGETCONTEXTTHREAD), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETCONTEXTTHREAD), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCONTINUE), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_KIUED), BM_GETCHECK, 0, 0)) allChecked--;

            if(allChecked<1) SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 0, 0);
            else SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 1, 0);

            break;
        }
        case IDC_PEB:
        {
            WPARAM state;
            (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_GETCHECK, 0, 0))?state=1:state=0;

            //trigger child checkboxes
            SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_SETCHECK, state, 0);
            SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_SETCHECK, state, 0);

            break;
        }
        case IDC_PEBBEINGDEBUGGED:
        case IDC_PEBHEAPFLAGS:
        case IDC_PEBNTGLOBALFLAG:
        case IDC_PEBSTARTUPINFO:
        {
            int allChecked = 1;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_GETCHECK, 0, 0)) allChecked--;
            if(BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_GETCHECK, 0, 0)) allChecked--;

            if(allChecked<1) SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 0, 0);
            else SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 1, 0);
            break;
        }
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

//Menu->Options
static int Moptions(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwollymain, &OptionsProc);
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

static int MinjectDll(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        if(!ProcessId) return MENU_GRAYED;
        else return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        wchar_t dllPath[MAX_PATH] = {};
        if(GetFileDialog(dllPath))
            injectDll(ProcessId, dllPath);

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

//Menu->Update-Check
static int Mupdate(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        if(isNewVersionAvailable()) {
            MessageBoxA(hwollymain,
                        "There is a new version of ScyllaHide available !\n\n"
                        "Check out https://bitbucket.org/NtQuery/scyllahide/downloads \n"
                        "or some RCE forums !",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
        } else {
            MessageBoxA(hwollymain,
                        "You already have the latest version of ScyllaHide !",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
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
        n+=StrcopyW(s+n,TEXTLEN-n, SCYLLA_HIDE_VERSION_STRING_W);
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

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{
    if (reason==DLL_PROCESS_ATTACH)
    {
        LogWrap = LogWrapper;
        LogErrorWrap = LogErrorWrapper;

        hNtdllModule = GetModuleHandleW(L"ntdll.dll");
        GetModuleFileNameW(hi, NtApiIniPath, _countof(NtApiIniPath));
        WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
        if (temp)
        {
            temp++;
            *temp = 0;
            wcscpy(ScyllaHideDllPath, NtApiIniPath);
            wcscat(ScyllaHideDllPath, ScyllaHideDllFilename);
			wcscpy(ScyllaHideIniPath, NtApiIniPath);
			wcscat(ScyllaHideIniPath, ScyllaHideIniFilename);
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
    wcscpy(pluginversion,SCYLLA_HIDE_VERSION_STRING_W);

    return PLUGIN_VERSION;
};

//initialization happens in here
extc int __cdecl ODBG2_Plugininit(void)
{
    CreateSettings();
	ReadSettings();

    Addtolist(0,0,L"ScyllaHide Plugin v"SCYLLA_HIDE_VERSION_STRING_W);
    Addtolist(0,2,L"  Copyright (C) 2014 Aguila / cypher");

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

//called for every debugloop pass
extc void ODBG2_Pluginmainloop(DEBUG_EVENT *debugevent)
{

    if(!debugevent)
        return;


    if (pHideOptions.PEBHeapFlags)
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
                Message(0, L"[ScyllaHide] Reading NT API Information %s", NtApiIniPath);
                ReadNtApiInformation();

                bHooked = true;
                startInjection(ProcessId, ScyllaHideDllPath, true);
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

void LogErrorWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    Error(L"%s",text);
}

void LogWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    Message(0,L"%s", text);
}