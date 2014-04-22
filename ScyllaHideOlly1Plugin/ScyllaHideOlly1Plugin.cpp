#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "resource.h"
#include "Injector.h"
#include "ollyplugindefinitions.h"
#include "olly1patches.h"
#include "..\InjectorCLI\RemotePebHider.h"
#include "..\InjectorCLI\ReadNtConfig.h"

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
void LogWrapper(const WCHAR * format, ...);

//scyllaHide definitions
struct HideOptions pHideOptions = {0};

#define SCYLLAHIDE_VERSION "0.5"
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

//globals
static HINSTANCE hinst;
static DWORD ProcessId;
static DWORD_PTR epaddr;
static bool bHooked = false;
static bool bEPBreakRemoved = false;
static bool bOnceTls = false;
HWND hwmain; // Handle of main OllyDbg window


WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;

HMODULE hNtdllModule = 0;
bool specialPebFix = false;
LPVOID ImageBase = 0;
void ReadTlsAndSetBreakpoints(DWORD dwProcessId, LPVOID baseOfImage);

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{
    if (reason==DLL_PROCESS_ATTACH)
    {
		LogWrap = LogWrapper;

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
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DELEPBREAK), BM_GETCHECK, 0, 0))
    {
        pHideOptions.removeEPBreak = 1;
    }
    else
        pHideOptions.removeEPBreak = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_FIXOLLY), BM_GETCHECK, 0, 0))
    {
        pHideOptions.fixOllyBugs = 1;
    }
    else
        pHideOptions.fixOllyBugs = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_X64FIX), BM_GETCHECK, 0, 0))
    {
        pHideOptions.x64Fix = 1;
    }
    else
        pHideOptions.x64Fix = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_BREAKTLS), BM_GETCHECK, 0, 0))
    {
        pHideOptions.breakTLS = 1;
    }
    else
        pHideOptions.breakTLS = 0;
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

    GetDlgItemTextA(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle, 33);
    SetWindowTextA(hwmain, pHideOptions.ollyTitle);

    //save all options
    _Pluginwriteinttoini(hinst, "PEBBeingDebugged", pHideOptions.PEBBeingDebugged);
    _Pluginwriteinttoini(hinst, "PEBHeapFlags", pHideOptions.PEBHeapFlags);
    _Pluginwriteinttoini(hinst, "PEBNtGlobalFlag", pHideOptions.PEBNtGlobalFlag);
    _Pluginwriteinttoini(hinst, "PEBStartupInfo", pHideOptions.PEBStartupInfo);
    _Pluginwriteinttoini(hinst, "NtSetInformationThread", pHideOptions.NtSetInformationThread);
    _Pluginwriteinttoini(hinst, "NtQuerySystemInformation", pHideOptions.NtQuerySystemInformation);
    _Pluginwriteinttoini(hinst, "NtQueryInformationProcess", pHideOptions.NtQueryInformationProcess);
    _Pluginwriteinttoini(hinst, "NtQueryObject", pHideOptions.NtQueryObject);
    _Pluginwriteinttoini(hinst, "NtYieldExecution", pHideOptions.NtYieldExecution);
    _Pluginwriteinttoini(hinst, "GetTickCount", pHideOptions.GetTickCount);
    _Pluginwriteinttoini(hinst, "OutputDebugStringA", pHideOptions.OutputDebugStringA);
    _Pluginwriteinttoini(hinst, "BlockInput", pHideOptions.BlockInput);
    _Pluginwriteinttoini(hinst, "NtGetContextThread", pHideOptions.NtGetContextThread);
    _Pluginwriteinttoini(hinst, "NtSetContextThread", pHideOptions.NtSetContextThread);
    _Pluginwriteinttoini(hinst, "NtContinue", pHideOptions.NtContinue);
    _Pluginwriteinttoini(hinst, "KiUserExceptionDispatcher", pHideOptions.KiUserExceptionDispatcher);
    _Pluginwriteinttoini(hinst, "NtUserFindWindowEx", pHideOptions.NtUserFindWindowEx);
    _Pluginwriteinttoini(hinst, "NtUserBuildHwndList", pHideOptions.NtUserBuildHwndList);
    _Pluginwriteinttoini(hinst, "NtUserQueryWindow", pHideOptions.NtUserQueryWindow);
    _Pluginwriteinttoini(hinst, "NtSetDebugFilterState", pHideOptions.NtSetDebugFilterState);
    _Pluginwriteinttoini(hinst, "NtClose", pHideOptions.NtClose);
    _Pluginwriteinttoini(hinst, "NtCreateThreadEx", pHideOptions.NtCreateThreadEx);
    _Pluginwriteinttoini(hinst, "preventThreadCreation", pHideOptions.preventThreadCreation);
    _Pluginwriteinttoini(hinst, "removeEPBreak", pHideOptions.removeEPBreak);
    _Pluginwritestringtoini(hinst, "ollyTitle", pHideOptions.ollyTitle);
    _Pluginwriteinttoini(hinst, "fixOllyBugs", pHideOptions.fixOllyBugs);
    _Pluginwriteinttoini(hinst, "x64Fix", pHideOptions.x64Fix);
    _Pluginwriteinttoini(hinst, "breakTLS", pHideOptions.breakTLS);
    _Pluginwriteinttoini(hinst, "DLLStealth", pHideOptions.DLLStealth);
    _Pluginwriteinttoini(hinst, "DLLNormal", pHideOptions.DLLNormal);
    _Pluginwriteinttoini(hinst, "DLLUnload", pHideOptions.DLLUnload);
}

void LoadOptions()
{
    //load all options
    pHideOptions.PEBBeingDebugged = _Pluginreadintfromini(hinst, "PEBBeingDebugged", pHideOptions.PEBBeingDebugged);
    pHideOptions.PEBHeapFlags = _Pluginreadintfromini(hinst, "PEBHeapFlags", pHideOptions.PEBHeapFlags);
    pHideOptions.PEBNtGlobalFlag = _Pluginreadintfromini(hinst, "PEBNtGlobalFlag", pHideOptions.PEBNtGlobalFlag);
    pHideOptions.PEBStartupInfo = _Pluginreadintfromini(hinst, "PEBStartupInfo", pHideOptions.PEBStartupInfo);
    pHideOptions.NtSetInformationThread = _Pluginreadintfromini(hinst, "NtSetInformationThread", pHideOptions.NtSetInformationThread);
    pHideOptions.NtQuerySystemInformation = _Pluginreadintfromini(hinst, "NtQuerySystemInformation", pHideOptions.NtQuerySystemInformation);
    pHideOptions.NtQueryInformationProcess = _Pluginreadintfromini(hinst, "NtQueryInformationProcess", pHideOptions.NtQueryInformationProcess);
    pHideOptions.NtQueryObject = _Pluginreadintfromini(hinst, "NtQueryObject", pHideOptions.NtQueryObject);
    pHideOptions.NtYieldExecution = _Pluginreadintfromini(hinst, "NtYieldExecution", pHideOptions.NtYieldExecution);
    pHideOptions.GetTickCount = _Pluginreadintfromini(hinst, "GetTickCount", pHideOptions.GetTickCount);
    pHideOptions.OutputDebugStringA = _Pluginreadintfromini(hinst, "OutputDebugStringA", pHideOptions.OutputDebugStringA);
    pHideOptions.BlockInput = _Pluginreadintfromini(hinst, "BlockInput", pHideOptions.BlockInput);
    pHideOptions.NtGetContextThread = _Pluginreadintfromini(hinst, "NtGetContextThread", pHideOptions.NtGetContextThread);
    pHideOptions.NtSetContextThread = _Pluginreadintfromini(hinst, "NtSetContextThread", pHideOptions.NtSetContextThread);
    pHideOptions.NtContinue = _Pluginreadintfromini(hinst, "NtContinue", pHideOptions.NtContinue);
    pHideOptions.KiUserExceptionDispatcher = _Pluginreadintfromini(hinst, "KiUserExceptionDispatcher", pHideOptions.KiUserExceptionDispatcher);
    pHideOptions.NtUserFindWindowEx = _Pluginreadintfromini(hinst, "NtUserFindWindowEx", pHideOptions.NtUserFindWindowEx);
    pHideOptions.NtUserBuildHwndList = _Pluginreadintfromini(hinst, "NtUserBuildHwndList", pHideOptions.NtUserBuildHwndList);
    pHideOptions.NtUserQueryWindow = _Pluginreadintfromini(hinst, "NtUserQueryWindow", pHideOptions.NtUserQueryWindow);
    pHideOptions.NtSetDebugFilterState = _Pluginreadintfromini(hinst, "NtSetDebugFilterState", pHideOptions.NtSetDebugFilterState);
    pHideOptions.NtClose = _Pluginreadintfromini(hinst, "NtClose", pHideOptions.NtClose);
    pHideOptions.NtCreateThreadEx = _Pluginreadintfromini(hinst, "NtCreateThreadEx", pHideOptions.NtCreateThreadEx);
    pHideOptions.preventThreadCreation = _Pluginreadintfromini(hinst, "preventThreadCreation", pHideOptions.preventThreadCreation);
    pHideOptions.removeEPBreak = _Pluginreadintfromini(hinst, "removeEPBreak", pHideOptions.removeEPBreak);
    _Pluginreadstringfromini(hinst, "ollyTitle", pHideOptions.ollyTitle, "I can haz crack?");
    pHideOptions.fixOllyBugs = _Pluginreadintfromini(hinst, "fixOllyBugs", pHideOptions.fixOllyBugs);
    pHideOptions.x64Fix = _Pluginreadintfromini(hinst, "x64Fix", pHideOptions.x64Fix);
    pHideOptions.breakTLS = _Pluginreadintfromini(hinst, "breakTLS", pHideOptions.breakTLS);
    pHideOptions.DLLStealth = _Pluginreadintfromini(hinst, "DLLStealth", pHideOptions.DLLStealth);
    pHideOptions.DLLNormal = _Pluginreadintfromini(hinst, "DLLNormal", pHideOptions.DLLNormal);
    pHideOptions.DLLUnload = _Pluginreadintfromini(hinst, "DLLUnload", pHideOptions.DLLUnload);
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
        SendMessage(GetDlgItem(hWnd, IDC_DELEPBREAK), BM_SETCHECK, pHideOptions.removeEPBreak, 0);
        SetDlgItemTextA(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle);
        SendMessage(GetDlgItem(hWnd, IDC_FIXOLLY), BM_SETCHECK, pHideOptions.fixOllyBugs, 0);
        SendMessage(GetDlgItem(hWnd, IDC_X64FIX), BM_SETCHECK, pHideOptions.x64Fix, 0);
        SendMessage(GetDlgItem(hWnd, IDC_BREAKTLS), BM_SETCHECK, pHideOptions.breakTLS, 0);
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

//register plugin with name
extern "C" int __declspec(dllexport) _ODBG_Plugindata(char shortname[32])
{
    strcpy(shortname,"ScyllaHide");
    return PLUGIN_VERSION;
};

//initialization happens in here
extern "C" int __declspec(dllexport) _ODBG_Plugininit(int ollydbgversion,HWND hw,unsigned long *features)
{
    if (ollydbgversion<PLUGIN_VERSION)
        return -1;

    hwmain=hw;

    LoadOptions();

    _Addtolist(0,0,"ScyllaHide Plugin v"SCYLLAHIDE_VERSION);
    _Addtolist(0,-1,"  Copyright (C) 2014 Aguila / cypher");

    _Message(0, "[ScyllaHide] Reading NT API Information %S", NtApiIniPath);
    ReadNtApiInformation();

    //do some Olly fixes
    if(pHideOptions.fixOllyBugs) {
        fixBadPEBugs();
        fixForegroundWindow();
        fixFPUBug();
    }
    if(pHideOptions.x64Fix) {
        fixX64Bug();
    }

    return 0;
};

//add menu entries
extern "C" int __declspec(dllexport) _ODBG_Pluginmenu(int origin,char data[4096],void *item)
{
    switch(origin)
    {
    case PM_MAIN:
    {
        strcpy(data, "0 &Options|2 &Inject DLL| 1 &About");

        //also patch olly title
        SetWindowTextA(hwmain, pHideOptions.ollyTitle);
        return 1;
    }
    case PM_THREADS:
    {
        strcpy(data, "0 &Resume all Threads, 1 &Suspend all Threads");
        return 1;
    }

    default:
        break;
    }


    return 0;
}

//handle plugin actions
extern "C" void __declspec(dllexport) _ODBG_Pluginaction(int origin,int action,void *item)
{
    if(origin==PM_MAIN) {
        switch(action)
        {
        case 0:
        {
            DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwmain, &OptionsProc);
            break;
        }
        case 1:
        {
            MessageBoxA(hwmain,
                        "ScyllaHide Plugin v"SCYLLAHIDE_VERSION"\n"
                        "(Anti-Anti-Debug in usermode)\n\n"
                        "Copyright (C) 2014 Aguila / cypher",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
            break;
        }
        case 2:
        {
            if(ProcessId) {
                wchar_t dllPath[MAX_PATH] = {};
                if(GetFileDialog(dllPath))
                    injectDll(ProcessId, dllPath);
            }
            break;
        }
        default:
            break;
        }
    } else if(origin==PM_THREADS) {
        t_table* threadWindow = (t_table*)_Plugingetvalue(VAL_THREADS);
        int threadCount = threadWindow->data.n;
        int threadSize = threadWindow->data.itemsize;
        t_thread* thread = (t_thread*)threadWindow->data.data;

        switch(action)
        {
        case 0:
        {
            //resume
            for(int i=0; i<threadCount; i++) {
                ResumeThread(thread->thread);

                //yup this is super-hacky-pointer-kungfu but thread++ wont work coz there
                //is 0x20bytes extra data between thread elements
                thread = reinterpret_cast<t_thread*>((DWORD)thread+threadSize);
            }
            break;
        }
        case 1:
        {
            //suspend
            for(int i=0; i<threadCount; i++) {
                SuspendThread(thread->thread);

                //yup this is super-hacky-pointer-kungfu but thread++ wont work coz there
                //is 0x20bytes extra data between thread elements
                thread = reinterpret_cast<t_thread*>((DWORD)thread+threadSize);
            }
            break;
        }
        }
    }
}

//called for every debugloop pass
extern "C" void __declspec(dllexport) _ODBG_Pluginmainloop(DEBUG_EVENT *debugevent)
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
        ImageBase = debugevent->u.CreateProcessInfo.lpBaseOfImage;
        ProcessId=debugevent->dwProcessId;
        bHooked = false;
        bOnceTls = false;
        epaddr = (DWORD_PTR)debugevent->u.CreateProcessInfo.lpStartAddress;
        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

        //change olly caption again !
        SetWindowTextA(hwmain, pHideOptions.ollyTitle);
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

            break;
        }

        case STATUS_ILLEGAL_INSTRUCTION:
        {
            //THEMIDA
            break;
        }
        }

        break;
    }
    }
}

extern "C" int __declspec(dllexport) _ODBG_Pausedex(int reason, int extdata, void* reg, DEBUG_EVENT *debugevent)
{

    if(!bEPBreakRemoved && pHideOptions.removeEPBreak) {
        _Deletebreakpoints(epaddr,epaddr+1, 0);
        bEPBreakRemoved = true;
    }
    if (!bOnceTls && pHideOptions.breakTLS)
    {
        ReadTlsAndSetBreakpoints(ProcessId, ImageBase);
        bOnceTls = true;
    }

    return 0;
}

//reset variables. new target started or restarted
extern "C" void __declspec(dllexport) _ODBG_Pluginreset(void)
{
    ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
    bHooked = false;
    bEPBreakRemoved = false;
    bOnceTls = false;
    ProcessId = 0;
}

void ReadTlsAndSetBreakpoints(DWORD dwProcessId, LPVOID baseOfImage)
{
    BYTE memory[0x1000] = {0};
    IMAGE_TLS_DIRECTORY tlsDir = {0};
    PVOID callbacks[64] = {0};

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, dwProcessId);

    if (!hProcess)
        return;

    ReadProcessMemory(hProcess, baseOfImage, memory, sizeof(memory), 0);

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)memory;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);
    if (pNt->Signature == IMAGE_NT_SIGNATURE)
    {
        if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
        {
            //_Message(0, "[ScyllaHide] TLS directory %X found", pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

            ReadProcessMemory(hProcess, (PVOID)((DWORD_PTR)baseOfImage + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), &tlsDir, sizeof(IMAGE_TLS_DIRECTORY), 0);

            if (tlsDir.AddressOfCallBacks)
            {
                //_Message(0, "[ScyllaHide] TLS AddressOfCallBacks %X found", tlsDir.AddressOfCallBacks);

                ReadProcessMemory(hProcess, (PVOID)tlsDir.AddressOfCallBacks, callbacks, sizeof(callbacks), 0);

                for (int i = 0; i < _countof(callbacks); i++)
                {
                    if (callbacks[i])
                    {
                        _Message(0, "[ScyllaHide] TLS callback found: Index %d Address %X", i, callbacks[i]);
                        _Tempbreakpoint((DWORD)callbacks[i], TY_ONESHOT);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);
}

void LogWrapper(const WCHAR * format, ...)
{
	WCHAR text[2000];
	CHAR textA[2000];
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfW(text, format, va_alist);

	WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

	_Message(0, textA);
}