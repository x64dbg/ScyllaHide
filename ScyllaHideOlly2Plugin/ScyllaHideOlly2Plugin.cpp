#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "resource.h"
#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include "Injector.h"
#include "ScyllaHideOlly2Plugin.h"
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

    return (TRUE == GetOpenFileName(&sOpenFileName));
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
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_GETCHECK, 0, 0))
    {
        pHideOptions.GetTickCount = 1;
    }
    else
        pHideOptions.GetTickCount = 0;
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

    GetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle, 33);
    SetWindowTextW(hwollymain, pHideOptions.ollyTitle);

    //save all options
    Writetoini(NULL,PLUGINNAME,L"PEBBeingDebugged",L"%i",pHideOptions.PEBBeingDebugged);
    Writetoini(NULL,PLUGINNAME,L"PEBHeapFlags",L"%i",pHideOptions.PEBHeapFlags);
    Writetoini(NULL,PLUGINNAME,L"PEBNtGlobalFlag",L"%i",pHideOptions.PEBNtGlobalFlag);
    Writetoini(NULL,PLUGINNAME,L"PEBStartupInfo",L"%i",pHideOptions.PEBStartupInfo);
    Writetoini(NULL,PLUGINNAME,L"NtSetInformationThread",L"%i",pHideOptions.NtSetInformationThread);
    Writetoini(NULL,PLUGINNAME,L"NtQuerySystemInformation",L"%i",pHideOptions.NtQuerySystemInformation);
    Writetoini(NULL,PLUGINNAME,L"NtQueryInformationProcess",L"%i",pHideOptions.NtQueryInformationProcess);
    Writetoini(NULL,PLUGINNAME,L"NtQueryObject",L"%i",pHideOptions.NtQueryObject);
    Writetoini(NULL,PLUGINNAME,L"NtYieldExecution",L"%i",pHideOptions.NtYieldExecution);
    Writetoini(NULL,PLUGINNAME,L"GetTickCount",L"%i",pHideOptions.GetTickCount);
    Writetoini(NULL,PLUGINNAME,L"OutputDebugStringA",L"%i",pHideOptions.OutputDebugStringA);
    Writetoini(NULL,PLUGINNAME,L"BlockInput",L"%i",pHideOptions.BlockInput);
    Writetoini(NULL,PLUGINNAME,L"NtGetContextThread",L"%i",pHideOptions.NtGetContextThread);
    Writetoini(NULL,PLUGINNAME,L"NtSetContextThread",L"%i",pHideOptions.NtSetContextThread);
    Writetoini(NULL,PLUGINNAME,L"NtContinue",L"%i",pHideOptions.NtContinue);
    Writetoini(NULL,PLUGINNAME,L"KiUserExceptionDispatcher",L"%i",pHideOptions.KiUserExceptionDispatcher);
    Writetoini(NULL,PLUGINNAME,L"NtUserFindWindowEx",L"%i",pHideOptions.NtUserFindWindowEx);
    Writetoini(NULL,PLUGINNAME,L"NtUserBuildHwndList",L"%i",pHideOptions.NtUserBuildHwndList);
    Writetoini(NULL,PLUGINNAME,L"NtUserQueryWindow",L"%i",pHideOptions.NtUserQueryWindow);
    Writetoini(NULL,PLUGINNAME,L"NtSetDebugFilterState",L"%i",pHideOptions.NtSetDebugFilterState);
    Writetoini(NULL,PLUGINNAME,L"NtClose",L"%i",pHideOptions.NtClose);
    Writetoini(NULL,PLUGINNAME,L"NtCreateThreadEx",L"%i",pHideOptions.NtCreateThreadEx);
    Writetoini(NULL,PLUGINNAME,L"preventThreadCreation",L"%i",pHideOptions.preventThreadCreation);
    Writetoini(NULL,PLUGINNAME,L"ollyTitle", L"%s",pHideOptions.ollyTitle);
    Writetoini(NULL,PLUGINNAME,L"DLLStealth", L"%i",pHideOptions.DLLStealth);
    Writetoini(NULL,PLUGINNAME,L"DLLNormal", L"%i",pHideOptions.DLLNormal);
    Writetoini(NULL,PLUGINNAME,L"DLLUnload", L"%i",pHideOptions.DLLUnload);
}

void LoadOptions()
{
    //load all options
    Getfromini(NULL,PLUGINNAME,L"PEBBeingDebugged",L"%i",&pHideOptions.PEBBeingDebugged);
    Getfromini(NULL,PLUGINNAME,L"PEBHeapFlags",L"%i",&pHideOptions.PEBHeapFlags);
    Getfromini(NULL,PLUGINNAME,L"PEBNtGlobalFlag",L"%i",&pHideOptions.PEBNtGlobalFlag);
    Getfromini(NULL,PLUGINNAME,L"PEBStartupInfo",L"%i",&pHideOptions.PEBStartupInfo);
    Getfromini(NULL,PLUGINNAME,L"NtSetInformationThread",L"%i",&pHideOptions.NtSetInformationThread);
    Getfromini(NULL,PLUGINNAME,L"NtQuerySystemInformation",L"%i",&pHideOptions.NtQuerySystemInformation);
    Getfromini(NULL,PLUGINNAME,L"NtQueryInformationProcess",L"%i",&pHideOptions.NtQueryInformationProcess);
    Getfromini(NULL,PLUGINNAME,L"NtQueryObject",L"%i",&pHideOptions.NtQueryObject);
    Getfromini(NULL,PLUGINNAME,L"NtYieldExecution",L"%i",&pHideOptions.NtYieldExecution);
    Getfromini(NULL,PLUGINNAME,L"GetTickCount",L"%i",&pHideOptions.GetTickCount);
    Getfromini(NULL,PLUGINNAME,L"OutputDebugStringA",L"%i",&pHideOptions.OutputDebugStringA);
    Getfromini(NULL,PLUGINNAME,L"BlockInput",L"%i",&pHideOptions.BlockInput);
    Getfromini(NULL,PLUGINNAME,L"NtGetContextThread",L"%i",&pHideOptions.NtGetContextThread);
    Getfromini(NULL,PLUGINNAME,L"NtSetContextThread",L"%i",&pHideOptions.NtSetContextThread);
    Getfromini(NULL,PLUGINNAME,L"NtContinue",L"%i",&pHideOptions.NtContinue);
    Getfromini(NULL,PLUGINNAME,L"KiUserExceptionDispatcher",L"%i",&pHideOptions.KiUserExceptionDispatcher);
    Getfromini(NULL,PLUGINNAME,L"NtUserFindWindowEx",L"%i",&pHideOptions.NtUserFindWindowEx);
    Getfromini(NULL,PLUGINNAME,L"NtUserBuildHwndList",L"%i",&pHideOptions.NtUserBuildHwndList);
    Getfromini(NULL,PLUGINNAME,L"NtUserQueryWindow",L"%i",&pHideOptions.NtUserQueryWindow);
    Getfromini(NULL,PLUGINNAME,L"NtSetDebugFilterState",L"%i",&pHideOptions.NtSetDebugFilterState);
    Getfromini(NULL,PLUGINNAME,L"NtClose",L"%i",&pHideOptions.NtClose);
    Getfromini(NULL,PLUGINNAME,L"NtCreateThreadEx",L"%i",&pHideOptions.NtCreateThreadEx);
    Getfromini(NULL,PLUGINNAME,L"preventThreadCreation",L"%i",&pHideOptions.preventThreadCreation);
    Getfromini(NULL, PLUGINNAME, L"ollyTitle", L"%s", &pHideOptions.ollyTitle);
    Getfromini(NULL,PLUGINNAME,L"DLLStealth", L"%i",&pHideOptions.DLLStealth);
    Getfromini(NULL,PLUGINNAME,L"DLLNormal", L"%i",&pHideOptions.DLLNormal);
    Getfromini(NULL,PLUGINNAME,L"DLLUnload", L"%i",&pHideOptions.DLLUnload);
}

//options dialog proc
INT_PTR CALLBACK OptionsProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        LoadOptions();

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
        SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_SETCHECK, pHideOptions.GetTickCount, 0);
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
        SendMessage(GetDlgItem(hWnd, IDC_PREVENTTHREADCREATION), BM_SETCHECK, pHideOptions.preventThreadCreation, 0);
        SetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle);
        SendMessage(GetDlgItem(hWnd, IDC_DLLSTEALTH), BM_SETCHECK, pHideOptions.DLLStealth, 0);
        SendMessage(GetDlgItem(hWnd, IDC_DLLNORMAL), BM_SETCHECK, pHideOptions.DLLNormal, 0);
        SendMessage(GetDlgItem(hWnd, IDC_DLLUNLOAD), BM_SETCHECK, pHideOptions.DLLUnload, 0);

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

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{
    if (reason==DLL_PROCESS_ATTACH)
    {
        hNtdllModule = GetModuleHandleW(L"ntdll.dll");
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
    LoadOptions();

    Addtolist(0,0,L"ScyllaHide Plugin v"VERSION);
    Addtolist(0,2,L"  Copyright (C) 2014 Aguila / cypher");

    Message(0, L"[ScyllaHide] Reading NT API Information %s", NtApiIniPath);
    ReadNtApiInformation();

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
