#include "OptionsDialog.h"
#include <codecvt>
#include <locale>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>
#include <Scylla/Version.h>

#include "..\PluginGeneric\Injector.h"

#ifdef OLLY1
#pragma pack(push)
#include <ollydbg1/ollyplugindefinitions.h>
#pragma pack(pop)
#include "..\ScyllaHideOlly1Plugin\resource.h"

#elif OLLY2
#pragma pack(push)
#include <ollydbg2/plugin.h>
#pragma pack(pop)
#include "..\ScyllaHideOlly2Plugin\resource.h"

#elif __IDP__
//#define BUILD_IDA_64BIT 1
#include <idasdk/ida.hpp>
#include <idasdk/idp.hpp>
#include <idasdk/dbg.hpp>
#include "..\ScyllaHideIDAProPlugin\IdaServerClient.h"
#include "..\PluginGeneric\AttachDialog.h"
#include "..\ScyllaHideIDAProPlugin\resource.h"

#elif X64DBG
#include <x64dbg/bridgemain.h>
#include "..\ScyllaHideX64DBGPlugin\resource.h"
#define IDC_EXCEPTION_ALL 123432
#define IDC_SELECT_EXCEPTIONS 23949
#endif

extern scl::Settings g_settings;

extern WCHAR ScyllaHideIniPath[MAX_PATH];
extern WCHAR ScyllaHideDllPath[MAX_PATH];
extern DWORD ProcessId;
extern bool bHooked;

#ifdef OLLY1
extern HWND hwmain;
#elif __IDP__
extern HINSTANCE hinst;
wchar_t DllPathForInjection[MAX_PATH] = {0};
#endif

void createExceptionWindow(HWND hwnd);
void ResetAllExceptions();
void HandleGuiException(HWND hwnd);

void ShowAbout(HWND hWnd)
{
    MessageBoxA(hWnd,
        SCYLLA_HIDE_NAME_A " Plugin v" SCYLLA_HIDE_VERSION_STRING_A " (" __DATE__ ")\n\n"
        "Copyright (C) 2014 Aguila / cypher\n\n"
        "Special thanks to:\n"
        "- What for his POISON assembler source code\n"
        "- waliedassar for his blog posts\n"
        "- Peter Ferrie for his Anti-Debug PDFs\n"
        "- MaRKuS-DJM for OllyAdvanced assembler source code\n"
        "- Steve Micallef for his IDA SDK doc\n"
        "- Authors of PhantOm and StrongOD\n"
        "- Tuts4You, Exetools, Exelab community for testing\n"
        "- last but not least deepzero & mr.exodia for tech chats",
        "ScyllaHide Plugin", MB_OK | MB_ICONINFORMATION);
}

bool GetFileDialog(TCHAR Buffer[MAX_PATH])
{
    OPENFILENAME sOpenFileName = { 0 };
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

void UpdateOptions(HWND hWnd)
{
    SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_SETCHECK, g_settings.opts().fixPebBeingDebugged, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_SETCHECK, g_settings.opts().fixPebHeapFlags, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_SETCHECK, g_settings.opts().fixPebNtGlobalFlag, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_SETCHECK, g_settings.opts().fixPebStartupInfo, 0);
    if (g_settings.opts().fixPebBeingDebugged && g_settings.opts().fixPebHeapFlags && g_settings.opts().fixPebNtGlobalFlag && g_settings.opts().fixPebStartupInfo)
        SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 1, 0);
    else
        SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 0, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONTHREAD), BM_SETCHECK, g_settings.opts().hookNtSetInformationThread, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONPROCESS), BM_SETCHECK, g_settings.opts().hookNtSetInformationProcess, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMINFORMATION), BM_SETCHECK, g_settings.opts().hookNtQuerySystemInformation, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYINFORMATIONPROCESS), BM_SETCHECK, g_settings.opts().hookNtQueryInformationProcess, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYOBJECT), BM_SETCHECK, g_settings.opts().hookNtQueryObject, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTYIELDEXECUTION), BM_SETCHECK, g_settings.opts().hookNtYieldExecution, 0);
    SendMessage(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), BM_SETCHECK, g_settings.opts().hookOutputDebugStringA, 0);
    SendMessage(GetDlgItem(hWnd, IDC_BLOCKINPUT), BM_SETCHECK, g_settings.opts().hookBlockInput, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTGETCONTEXTTHREAD), BM_SETCHECK, g_settings.opts().hookNtGetContextThread, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETCONTEXTTHREAD), BM_SETCHECK, g_settings.opts().hookNtSetContextThread, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTCONTINUE), BM_SETCHECK, g_settings.opts().hookNtContinue, 0);
    SendMessage(GetDlgItem(hWnd, IDC_KIUED), BM_SETCHECK, g_settings.opts().hookKiUserExceptionDispatcher, 0);
    if (g_settings.opts().hookNtGetContextThread && g_settings.opts().hookNtSetContextThread && g_settings.opts().hookNtContinue && g_settings.opts().hookKiUserExceptionDispatcher)
        SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 1, 0);
    else
        SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 0, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTUSERFINDWINDOWEX), BM_SETCHECK, g_settings.opts().hookNtUserFindWindowEx, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTUSERBUILDHWNDLIST), BM_SETCHECK, g_settings.opts().hookNtUserBuildHwndList, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTUSERQUERYWINDOW), BM_SETCHECK, g_settings.opts().hookNtUserQueryWindow, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETDEBUGFILTERSTATE), BM_SETCHECK, g_settings.opts().hookNtSetDebugFilterState, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTCLOSE), BM_SETCHECK, g_settings.opts().hookNtClose, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTCREATETHREADEX), BM_SETCHECK, g_settings.opts().hookNtCreateThreadEx, 0);
    SendMessage(GetDlgItem(hWnd, IDC_REMOVEDEBUGPRIV), BM_SETCHECK, g_settings.opts().removeDebugPrivileges, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PREVENTTHREADCREATION), BM_SETCHECK, g_settings.opts().preventThreadCreation, 0);
    SendMessage(GetDlgItem(hWnd, IDC_RUNPE), BM_SETCHECK, g_settings.opts().malwareRunpeUnpacker, 0);
    SendMessage(GetDlgItem(hWnd, IDC_DLLSTEALTH), BM_SETCHECK, g_settings.opts().dllStealth, 0);
    SendMessage(GetDlgItem(hWnd, IDC_DLLNORMAL), BM_SETCHECK, g_settings.opts().dllNormal, 0);
    SendMessage(GetDlgItem(hWnd, IDC_DLLUNLOAD), BM_SETCHECK, g_settings.opts().dllUnload, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_SETCHECK, g_settings.opts().hookGetTickCount, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT64), BM_SETCHECK, g_settings.opts().hookGetTickCount64, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETLOCALTIME), BM_SETCHECK, g_settings.opts().hookGetLocalTime, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETSYSTEMTIME), BM_SETCHECK, g_settings.opts().hookGetSystemTime, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMTIME), BM_SETCHECK, g_settings.opts().hookNtQuerySystemTime, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYPERFCOUNTER), BM_SETCHECK, g_settings.opts().hookNtQueryPerformanceCounter, 0);
    SendMessage(GetDlgItem(hWnd, IDC_KILLANTIATTACH), BM_SETCHECK, g_settings.opts().killAntiAttach, 0);


#ifdef OLLY1
    SetDlgItemTextW(hWnd, IDC_OLLYTITLE, g_settings.opts().ollyWindowTitle.c_str());
    SendMessage(GetDlgItem(hWnd, IDC_DELEPBREAK), BM_SETCHECK, g_settings.opts().ollyRemoveEpBreak, 0);
    SendMessage(GetDlgItem(hWnd, IDC_FIXOLLY), BM_SETCHECK, g_settings.opts().ollyFixBugs, 0);
    SendMessage(GetDlgItem(hWnd, IDC_X64FIX), BM_SETCHECK, g_settings.opts().ollyX64Fix, 0);
    SendMessage(GetDlgItem(hWnd, IDC_SKIPEPOUTSIDE), BM_SETCHECK, g_settings.opts().ollySkipEpOutsideCode, 0);
    SendMessage(GetDlgItem(hWnd, IDC_BREAKTLS), BM_SETCHECK, g_settings.opts().ollyBreakOnTls, 0);

    if (g_settings.opts().ollySkipCompressedDoAnalyze || g_settings.opts().ollySkipCompressedDoNothing) {
        SendMessage(GetDlgItem(hWnd, IDC_COMPRESSED), BM_SETCHECK, 1, 0);
        EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), TRUE);
        EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), TRUE);
    }
    SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), BM_SETCHECK, g_settings.opts().ollySkipCompressedDoAnalyze, 0);
    SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), BM_SETCHECK, g_settings.opts().ollySkipCompressedDoNothing, 0);
    if (g_settings.opts().ollySkipLoadDllDoLoad || g_settings.opts().ollySkipLoadDllDoNothing) {
        SendMessage(GetDlgItem(hWnd, IDC_LOADDLL), BM_SETCHECK, 1, 0);
        EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLLOAD), TRUE);
        EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), TRUE);
    }
    SendMessage(GetDlgItem(hWnd, IDC_LOADDLLLOAD), BM_SETCHECK, g_settings.opts().ollySkipLoadDllDoLoad, 0);
    SendMessage(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), BM_SETCHECK, g_settings.opts().ollySkipLoadDllDoNothing, 0);
    SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDGOTO), BM_SETCHECK, g_settings.opts().ollyAdvancedGoto, 0);
    SendMessage(GetDlgItem(hWnd, IDC_BADPEIMAGE), BM_SETCHECK, g_settings.opts().ollyIgnoreBadPeImage, 0);
    SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDINFOBAR), BM_SETCHECK, g_settings.opts().ollyAdvancedInfobar, 0);
    EnableWindow(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), FALSE);
#elif OLLY2
    SetDlgItemTextW(hWnd, IDC_OLLYTITLE, g_settings.opts().ollyWindowTitle.c_str());
#elif __IDP__
    SendMessage(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), BM_SETCHECK, g_settings.opts().idaAutoStartServer, 0);
    SetDlgItemTextW(hWnd, IDC_SERVERPORT, g_settings.opts().idaServerPort.c_str());

#ifdef BUILD_IDA_64BIT
    if(isWindows64()) EnableWindow(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), TRUE);
    else EnableWindow(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), FALSE);
#else
    EnableWindow(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), FALSE);
#endif

    if(ProcessId) EnableWindow(GetDlgItem(hWnd, IDC_INJECTDLL), TRUE);
    else EnableWindow(GetDlgItem(hWnd, IDC_INJECTDLL), FALSE);
#endif


    HandleGuiException(hWnd);
}

void SaveOptions(HWND hWnd)
{
    //read all checkboxes
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().fixPebBeingDebugged = 1;
    }
    else
        g_settings.opts().fixPebBeingDebugged = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().fixPebHeapFlags = 1;
    }
    else
        g_settings.opts().fixPebHeapFlags = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().fixPebNtGlobalFlag = 1;
    }
    else
        g_settings.opts().fixPebNtGlobalFlag = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().fixPebStartupInfo = 1;
    }
    else
        g_settings.opts().fixPebStartupInfo = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONTHREAD), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtSetInformationThread = 1;
    }
    else
        g_settings.opts().hookNtSetInformationThread = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONPROCESS), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtSetInformationProcess = 1;
    }
    else
        g_settings.opts().hookNtSetInformationProcess = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMINFORMATION), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtQuerySystemInformation = 1;
    }
    else
        g_settings.opts().hookNtQuerySystemInformation = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYINFORMATIONPROCESS), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtQueryInformationProcess = 1;
    }
    else
        g_settings.opts().hookNtQueryInformationProcess = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYOBJECT), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtQueryObject = 1;
    }
    else
        g_settings.opts().hookNtQueryObject = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTYIELDEXECUTION), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtYieldExecution = 1;
    }
    else
        g_settings.opts().hookNtYieldExecution = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookOutputDebugStringA = 1;
    }
    else
        g_settings.opts().hookOutputDebugStringA = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_BLOCKINPUT), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookBlockInput = 1;
    }
    else
        g_settings.opts().hookBlockInput = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTGETCONTEXTTHREAD), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtGetContextThread = 1;
    }
    else
        g_settings.opts().hookNtGetContextThread = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETCONTEXTTHREAD), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtSetContextThread = 1;
    }
    else
        g_settings.opts().hookNtSetContextThread = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCONTINUE), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtContinue = 1;
    }
    else
        g_settings.opts().hookNtContinue = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_KIUED), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookKiUserExceptionDispatcher = 1;
    }
    else
        g_settings.opts().hookKiUserExceptionDispatcher = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTUSERFINDWINDOWEX), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtUserFindWindowEx = 1;
    }
    else
        g_settings.opts().hookNtUserFindWindowEx = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTUSERBUILDHWNDLIST), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtUserBuildHwndList = 1;
    }
    else
        g_settings.opts().hookNtUserBuildHwndList = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTUSERQUERYWINDOW), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtUserQueryWindow = 1;
    }
    else
        g_settings.opts().hookNtUserQueryWindow = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETDEBUGFILTERSTATE), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtSetDebugFilterState = 1;
    }
    else
        g_settings.opts().hookNtSetDebugFilterState = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCLOSE), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtClose = 1;
    }
    else
        g_settings.opts().hookNtClose = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCREATETHREADEX), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtCreateThreadEx = 1;
    }
    else
        g_settings.opts().hookNtCreateThreadEx = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PREVENTTHREADCREATION), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().preventThreadCreation = 1;
    }
    else
        g_settings.opts().preventThreadCreation = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_RUNPE), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().malwareRunpeUnpacker = 1;
    }
    else
        g_settings.opts().malwareRunpeUnpacker = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_REMOVEDEBUGPRIV), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().removeDebugPrivileges = 1;
    }
    else
        g_settings.opts().removeDebugPrivileges = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLSTEALTH), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().dllStealth = 1;
    }
    else
        g_settings.opts().dllStealth = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLNORMAL), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().dllNormal = 1;
    }
    else
        g_settings.opts().dllNormal = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLUNLOAD), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().dllUnload = 1;
    }
    else
        g_settings.opts().dllUnload = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookGetTickCount = 1;
    }
    else
        g_settings.opts().hookGetTickCount = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT64), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookGetTickCount64 = 1;
    }
    else
        g_settings.opts().hookGetTickCount64 = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETLOCALTIME), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookGetLocalTime = 1;
    }
    else
        g_settings.opts().hookGetLocalTime = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_GETSYSTEMTIME), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookGetSystemTime = 1;
    }
    else
        g_settings.opts().hookGetSystemTime = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMTIME), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtQuerySystemTime = 1;
    }
    else
        g_settings.opts().hookNtQuerySystemTime = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTQUERYPERFCOUNTER), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().hookNtQueryPerformanceCounter = 1;
    }
    else
        g_settings.opts().hookNtQueryPerformanceCounter = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_KILLANTIATTACH), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().killAntiAttach = 1;
    }
    else
        g_settings.opts().killAntiAttach = 0;

#ifdef OLLY1
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DELEPBREAK), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollyRemoveEpBreak = 1;
    }
    else
        g_settings.opts().ollyRemoveEpBreak = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_FIXOLLY), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollyFixBugs = 1;
    }
    else
        g_settings.opts().ollyFixBugs = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_X64FIX), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollyX64Fix = 1;
    }
    else
        g_settings.opts().ollyX64Fix = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_BREAKTLS), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollyBreakOnTls = 1;
    }
    else
        g_settings.opts().ollyBreakOnTls = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_SKIPEPOUTSIDE), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollySkipEpOutsideCode = 1;
    }
    else
        g_settings.opts().ollySkipEpOutsideCode = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_BADPEIMAGE), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollyIgnoreBadPeImage = 1;
    }
    else
        g_settings.opts().ollyIgnoreBadPeImage = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDGOTO), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollyAdvancedGoto = 1;
    }
    else
        g_settings.opts().ollyAdvancedGoto = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollySkipCompressedDoAnalyze = 1;
    }
    else
        g_settings.opts().ollySkipCompressedDoAnalyze = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollySkipCompressedDoNothing = 1;
    }
    else
        g_settings.opts().ollySkipCompressedDoNothing = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_LOADDLLLOAD), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollySkipLoadDllDoLoad = 1;
    }
    else
        g_settings.opts().ollySkipLoadDllDoLoad = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollySkipLoadDllDoNothing = 1;
    }
    else
        g_settings.opts().ollySkipLoadDllDoNothing = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDINFOBAR), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().ollyAdvancedInfobar = 1;
    }
    else
        g_settings.opts().ollyAdvancedInfobar = 0;
#elif __IDP__
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), BM_GETCHECK, 0, 0))
    {
        g_settings.opts().idaAutoStartServer = 1;
    }
    else
        g_settings.opts().idaAutoStartServer = 0;

    g_settings.opts().idaServerPort = scl::GetDlgItemTextW(hWnd, IDC_SERVERPORT);
#endif

#ifdef OLLY1
    g_settings.opts().ollyWindowTitle = scl::GetDlgItemTextW(hWnd, IDC_OLLYTITLE);
    SetWindowTextW(hwmain, g_settings.opts().ollyWindowTitle.c_str());
#elif OLLY2
    g_settings.opts().ollyWindowTitle = scl::GetDlgItemTextW(hWnd, IDC_OLLYTITLE);
    SetWindowTextW(hwollymain, g_settings.opts().ollyWindowTitle.c_str());
#endif

    //save all options
    g_settings.Save();
}

HWND CreateTooltips(HWND hwndDlg)
{
    HWND      hwndTT;
    HINSTANCE hInstance;

    static const struct _CtrlTips
    {
        UINT    uId;
        LPCWSTR lpszText;
    } CtrlTips[] = {
        { IDOK, L"Apply Settings and close the dialog" },
        { IDC_PROFILES, L"Select profile" },
        { IDC_SAVEPROFILE, L"Save profile" },
        { IDC_PEB, L"The most important anti-anti-debug option. Almost every protector checks for\r\nPEB values. There are three important options and one minor option." },
        { IDC_PEBBEINGDEBUGGED, L"Very important option, should be always enabled.\r\nIsDebuggerPresent is using this value to check for debuggers." },
        { IDC_PEBHEAPFLAGS, L"Very important option, a lot of protectors check for this value." },
        { IDC_PEBNTGLOBALFLAG, L"Very important option. E.g. Themida checks for heap artifacts and heap flags." },
        { IDC_PEBSTARTUPINFO, L"This is not really important, only a few protectors check for this. Maybe Enigma checks it." },
        { IDC_NTSETINFORMATIONTHREAD, L"The THREADINFOCLASS value ThreadHideFromDebugger is a well-known\r\nanti-debug measurement. The debugger cannot handle hidden threads.\r\nThis leads to a loss of control over the target." },
        { IDC_NTSETINFORMATIONPROCESS, L"The PROCESSINFOCLASS value ProcessHandleTracing can be used to\r\ndetect a debugger. The PROCESSINFOCLASS value ProcessBreakOnTermination\r\ncan be used to generate a Blue Screen of Death on process termination." },
        { IDC_NTQUERYSYSTEMINFORMATION, L"The SYSTEM_INFORMATION_CLASS value SystemKernelDebuggerInformation\r\ncan be used to detect kernel debuggers. The SYSTEM_INFORMATION_CLASS\r\nvalue SystemProcessInformation is used to get a process list. A debugger\r\nshould be hidden in a process list and the debugee should have a good parent\r\nprocess ID like the ID from explorer.exe." },
        { IDC_NTQUERYINFORMATIONPROCESS, L"A very important option. Various PROCESSINFOCLASS values can be used\r\nto detect a debugger.\r\n\
                                              ProcessDebugFlags: Should return 1 in the supplied buffer.\r\n\
                                                  ProcessDebugPort: Should return 0 in the supplied buffer.\r\n\
                                                      ProcessDebugObjectHandle: Should return 0 in the supplied buffer\r\nand the error STATUS_PORT_NOT_SET (0xC0000353)\r\n\
                                                          ProcessBasicInformation: Reveals the parent process ID.\r\n\
                                                              ProcessBreakOnTermination: Please see NtSetInformationProcess\r\n\
                                                                  ProcessHandleTracing: Please see NtSetInformationProcess\r\n\
                                                                  A lot of protectors use this to detect debuggers. The windows API CheckRemoteDebuggerPresent uses NtQueryInformationProcess internally."
        },
        { IDC_NTQUERYOBJECT, L"The OBJECT_INFORMATION_CLASS ObjectTypesInformation and ObjectTypeInformation\r\ncan be used to detect debuggers. ScyllaHide filters DebugObject references." },
        { IDC_NTYIELDEXECUTION, L"A very unrealiable anti-debug method. This is only used in some UnpackMe's\r\nor in some Proof of Concept code. Only activate this if you really need it.\r\nProbably you will never need this option." },
        { IDC_NTCREATETHREADEX, L"Threads hidden from debuggers can be created with a special creation flag\r\nTHREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER. ScyllaHide doesn't\r\nallow hidden threads. The anti-debug effect is similar to NtSetInformationThread" },
        { IDC_OUTPUTDEBUGSTRINGA, L"OutputDebugStringW uses OutputDebugStringA internally. ScyllaHide only hooks\r\nthe ANSI version and this is therefore enough. This is a very unreliable\r\nantidebug method, so you will not need this option very often." },
        { IDC_BLOCKINPUT, L"Very effective anti-debug method. This is used e.g. in Yoda's Protector. \r\n\"Blocks keyboard and mouse input events from reaching applications.\"" },
        { IDC_NTUSERFINDWINDOWEX, L"This is a system call function in user32.dll. The windows APIs FindWindowA/W\r\n and FindWindowExA/W call this internally. The debugger window will be hidden." },
        { IDC_NTUSERBUILDHWNDLIST, L"This is a system call function in user32.dll. The windows APIs EnumWindows\r\nand EnumThreadWindows call this internally. The debugger window will be hidden." },
        { IDC_NTUSERQUERYWINDOW, L"This is a system call function in user32.dll. The windows API GetWindowThreadProcessId\r\n calls this internally. This is used to hide the debugger process." },
        { IDC_NTSETDEBUGFILTERSTATE, L"ScyllaHide returns always STATUS_ACCESS_DENIED. This anti-debugn measurement\r\nisn't used very often. Probably you will never need this option in a real world target." },
        { IDC_NTCLOSE, L"This is called with an invalid handle to detect a debugger. ScyllaHide calls\r\nNtQueryObject to check the validity of the handle. A few protectors are using\r\nthis method." },
        { IDC_REMOVEDEBUGPRIV, L"If a debugger creates the process of the target, the target will have debug\r\nprivileges. This can be used to detect a debugger." },
        { IDC_PROTECTDRX, L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!" },
        { IDC_NTGETCONTEXTTHREAD, L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!" },
        { IDC_NTSETCONTEXTTHREAD, L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!" },
        { IDC_NTCONTINUE, L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!" },
        { IDC_KIUED, L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!" },
        { IDC_GETTICKCOUNT, L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!" },
        { IDC_GETTICKCOUNT64, L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!" },
        { IDC_GETLOCALTIME, L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!" },
        { IDC_GETSYSTEMTIME, L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!" },
        { IDC_NTQUERYSYSTEMTIME, L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!" },
        { IDC_NTQUERYPERFCOUNTER, L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!" },
        { IDC_PREVENTTHREADCREATION, L"This option prevents the creation of new threads. This can be useful if a protector\r\n uses a lot of protection threads. This option can be useful for EXECryptor.\r\nEnable with care and only if you need it!\r\nYou must know what you are doing here!" },
        { IDC_RUNPE, L"This option hooks NtResumeThread. If the malware creates a new process,\r\nScyllaHide terminates and dumps any newly created process. If you are unpacking\r\nmalware, enable and try it. Should be only used inside a VM.\r\n\
                      A typical RunPE workflow:\r\n\
                          1. Create a new process of any target in suspended state (Process flag\r\nCREATE_SUSPENDED: 0x00000004)\r\n\
                              2. Replace the original process PE image with a new (malicious) PE image.\r\nThis can involve several steps and various windows API functions.\r\n\
                                  3. Start the process with the windows API function ResumeThread (or NtResumeThread)."
        },
        { IDC_DLLSTEALTH, L"Normal DLL injection or stealth dll injection. You better try the normal\r\ninjection first..." },
        { IDC_DLLNORMAL, L"Normal DLL injection or stealth dll injection. You better try the normal\r\ninjection first..." },
        { IDC_DLLUNLOAD, L"Unload after DLLMain" },
        { IDC_KILLANTIATTACH, L"Kill Anti-Attach" },
#ifdef OLLY1
        { IDC_OLLYTITLE,                 L"Olly caption"                          },
        { IDC_DELEPBREAK,                L"Some protectors use Thread-Local-Storage (TLS) as entrypoint and check for\r\nbreakpoints at the normal PE entrypoint address. You must remove the PE\r\nentrypoint to hide your debugger. This option is necessary for VMProtect."},
        {   IDC_FIXOLLY,                   L"This option fixes various OllyDbg bugs:\r\n\
                                                - PE Fix for NumOfRvaAndSizes\r\n\
                                                    - ForegroundWindow Fix\r\n\
                                                        - FPU bugfix\r\n\
                                                            - Format string (sprintf) bug\r\n\
                                                                - NT Symbols path bug, patch by blabberer\r\n\
                                                                    - Faulty handle bug. Sometimes Olly does not terminate,\r\n\
                                                                        error appears \"Operating system reports error ERROR_ACCESS_DENIED\""
        },
        { IDC_X64FIX,                    L"OllyDbg doesn't work very well on x64 operating systems.\r\nThis option fixes the most annoying bug."},
        { IDC_SKIPEPOUTSIDE,             L"Skip\"EP outside of Code\""            },
        { IDC_BREAKTLS,                  L"This option sets a breakpoint to any available Thread-Local-Storage (TLS)\r\naddress. This is necessary for various protectors e.g. VMProtect."},
        { IDC_COMPRESSED,                L"Skip compressed code"                  },
        { IDC_COMPRESSEDANALYZE,         L"Skip compressed code and analyze"      },
        { IDC_COMPRESSEDNOTHING,         L"Skip compressed code and do nothing"   },
        { IDC_LOADDLL,                   L"Skip \"Load Dll\" and"                 },
        { IDC_LOADDLLLOAD,               L"Skip \"Load Dll\" and load DLL"        },
        { IDC_LOADDLLNOTHING,            L"Skip \"Load Dll\" and do nothing"      },
        { IDC_ADVANCEDGOTO,              L"Replaces the default OllyDbg \"Go to Address\" dialog. Now you can enter\r\nRVA and offset values. "},
        { IDC_ADVANCEDINFOBAR,           L"Displays info about selected Bytes in CPU/Dump like Start/End address and size."},
        { IDC_BADPEIMAGE,                L"Ignore bad image (WinUPack)"           },
#elif OLLY2
        { IDC_OLLYTITLE,                 L"Olly caption"                          },
#elif __IDP__
        { IDC_AUTOSTARTSERVER,           L""                                      },
        { IDC_SERVERPORT,                L""                                      },
        { IDC_INJECTDLL,                 L""                                      },
#endif
    };

    if (!IsWindow(hwndDlg))
        return NULL;

    hInstance = (HINSTANCE)GetWindowLongPtr(hwndDlg, GWLP_HINSTANCE);
    if (hInstance == NULL)
        return NULL;

    // Create tooltip for main window
    hwndTT = CreateWindowEx(WS_EX_TOPMOST,
        TOOLTIPS_CLASS,
        NULL,
        WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        hwndDlg,
        NULL,
        hInstance,
        NULL
        );

    if (hwndTT)
    {
        int count = 0;
        size_t i;

        //	Add tooltips to every control (above)
        for (i = 0; i < sizeof(CtrlTips) / sizeof(CtrlTips[0]); ++i)
        {
            LPCWSTR lpszText = CtrlTips[i].lpszText;
            if (lpszText && *lpszText)
            {
                HWND hwnd = GetDlgItem(hwndDlg, CtrlTips[i].uId);
                if (hwnd)
                {
                    TOOLINFO ti;

                    ti.cbSize = TTTOOLINFO_V1_SIZE;
                    ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
                    ti.hwnd = hwndDlg;
                    ti.uId = (UINT_PTR)hwnd;
                    ti.hinst = hInstance;
                    ti.lpszText = (LPWSTR)lpszText;
                    ti.lParam = 0;

                    if ((BOOL)SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM)&ti))
                        ++count;
                }
            }
        }

        if (count) {
            SendMessage(hwndTT, TTM_SETMAXTIPWIDTH, 0, 500);
            SendMessage(hwndTT, TTM_ACTIVATE, TRUE, 0);
        }
    }
    return hwndTT;
}

//options dialog proc
INT_PTR CALLBACK OptionsProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        // add current profile to options title
        auto wstrTitle = scl::fmtw(L"[ScyllaHide Options] Profile: %s", g_settings.profile_name().c_str());
        SetWindowTextW(hWnd, wstrTitle.c_str());

        // fill combobox with profiles
        for (size_t i = 0; i < g_settings.profile_names().size(); i++)
        {
            SendDlgItemMessageW(hWnd, IDC_PROFILES, CB_ADDSTRING, 0, (LPARAM)g_settings.profile_names()[i].c_str());
            if (g_settings.profile_name() == g_settings.profile_names()[i])
                SendDlgItemMessageW(hWnd, IDC_PROFILES, CB_SETCURSEL, i, 0);
        }

        UpdateOptions(hWnd);

#ifdef OLLY1
        if (scl::IsWindows64())
        {
            EnableWindow(GetDlgItem(hWnd, IDC_X64FIX), FALSE);
        }
#endif

        CreateTooltips(hWnd);

        break;
    }
    case WM_CLOSE:
    {
        EndDialog(hWnd, NULL);
    }
    break;

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_PROFILES:
        {
            if (HIWORD(wParam) == CBN_SELCHANGE)
            {
                auto profileIdx = (int)SendDlgItemMessageW(hWnd, IDC_PROFILES, (UINT)CB_GETCURSEL, 0, 0);
                g_settings.SetProfile(g_settings.profile_names()[profileIdx].c_str());

                // update options title
                auto wstrTitle = scl::fmtw(L"[ScyllaHide Options] Profile: %s", g_settings.profile_name().c_str());
                SetWindowTextW(hWnd, wstrTitle.c_str());

                UpdateOptions(hWnd);
            }
            break;
        }
        case IDC_SAVEPROFILE:
        {
            std::wstring wstrNewProfileName;

#ifdef OLLY1
            std::string strNewProfileName;
            strNewProfileName.resize(MAX_PATH);
            if (_Gettext("New profile name?", &strNewProfileName[0], 0, 0, 0) <= 0)
                break;
            wstrNewProfileName = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(strNewProfileName.c_str());

#elif OLLY2
            wstrNewProfileName.resize(MAX_PATH);
            if (Getstring(hWnd, L"New profile name?", &wstrNewProfileName[0], wstrNewProfileName.size(), 0, 0, 0, 0, 0, 0) <= 0)
                break;
            wstrNewProfileName.resize(lstrlenW(wstrNewProfileName.c_str()));

#elif __IDP__
            auto szNewProfileName = askstr(0, "", "New profile name?");
            if (!szNewProfileName)
                break;
            wstrNewProfileName = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(szNewProfileName);

#elif X64DBG
            std::string strNewProfileName;
            strNewProfileName.resize(GUI_MAX_LINE_SIZE);
            if (!GuiGetLineWindow("New profile name?", &strNewProfileName[0]))
                break;
            wstrNewProfileName = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(strNewProfileName.c_str());
#endif

            if (!g_settings.AddProfile(wstrNewProfileName.c_str()))
                break;
            g_settings.SetProfile(wstrNewProfileName.c_str());

            auto wstrTitle = scl::fmtw(L"[ScyllaHide Options] Profile: %s", g_settings.profile_name().c_str());
            SetWindowTextW(hWnd, wstrTitle.c_str());

            SendDlgItemMessageW(hWnd, IDC_PROFILES, CB_ADDSTRING, 0, (LPARAM)wstrNewProfileName.c_str());
            auto profileCount = (int)SendDlgItemMessageW(hWnd, IDC_PROFILES, CB_GETCOUNT, 0, 0);
            SendDlgItemMessageW(hWnd, IDC_PROFILES, CB_SETCURSEL, profileCount - 1, 0);

            UpdateOptions(hWnd);
            break;
        }
        case IDOK:
        {
            //save options to ini
            SaveOptions(hWnd);

            if (ProcessId)
            {
#ifdef __IDP__
#ifndef BUILD_IDA_64BIT
                startInjection(ProcessId, ScyllaHideDllPath, true);
#endif
#else
                startInjection(ProcessId, ScyllaHideDllPath, true);
#endif
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
        case IDC_APPLY:
        {
            SaveOptions(hWnd);
            break;
        }
        case IDC_EXCEPTION_ALL:
        {
            ResetAllExceptions();
            if (IsDlgButtonChecked(hWnd, IDC_EXCEPTION_ALL) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionPrint = 1;
                g_settings.opts().handleExceptionIllegalInstruction = 1;
                g_settings.opts().handleExceptionInvalidLockSequence = 1;
                g_settings.opts().handleExceptionNoncontinuableException = 1;
                g_settings.opts().handleExceptionRip = 1;
                g_settings.opts().handleExceptionAssertionFailure = 1;
                g_settings.opts().handleExceptionBreakpoint = 1;
                g_settings.opts().handleExceptionGuardPageViolation = 1;
                g_settings.opts().handleExceptionWx86Breakpoint = 1;
            }
        }
        case IDC_PROTECTDRX:
        {
            WPARAM state;
            (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_GETCHECK, 0, 0)) ? state = 1 : state = 0;

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
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTGETCONTEXTTHREAD), BM_GETCHECK, 0, 0)) allChecked--;
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETCONTEXTTHREAD), BM_GETCHECK, 0, 0)) allChecked--;
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTCONTINUE), BM_GETCHECK, 0, 0)) allChecked--;
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_KIUED), BM_GETCHECK, 0, 0)) allChecked--;

            if (allChecked < 1) SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 0, 0);
            else SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 1, 0);

            break;
        }
        case IDC_PEB:
        {
            WPARAM state;
            (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_GETCHECK, 0, 0)) ? state = 1 : state = 0;

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
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_GETCHECK, 0, 0)) allChecked--;
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_GETCHECK, 0, 0)) allChecked--;
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_GETCHECK, 0, 0)) allChecked--;
            if (BST_UNCHECKED == SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_GETCHECK, 0, 0)) allChecked--;

            if (allChecked < 1) SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 0, 0);
            else SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 1, 0);
            break;
        }
#ifdef OLLY1
        case IDC_COMPRESSED:
        {
            WPARAM state;
            (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_COMPRESSED), BM_GETCHECK, 0, 0))?state=1:state=0;

            EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), state);
            EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), state);

            if(state == BST_UNCHECKED) {
                SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), BM_SETCHECK, 0, 0);
                SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), BM_SETCHECK, 0, 0);
            }

            break;
        }
        case IDC_LOADDLL:
        {
            WPARAM state;
            (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_LOADDLL), BM_GETCHECK, 0, 0))?state=1:state=0;

            EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLLOAD), state);
            EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), state);

            if(state == BST_UNCHECKED) {
                SendMessage(GetDlgItem(hWnd, IDC_LOADDLLLOAD), BM_SETCHECK, 0, 0);
                SendMessage(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), BM_SETCHECK, 0, 0);
            }

            break;
        }
#endif
#ifdef __IDP__
        case IDC_DLLNORMAL:
        case IDC_DLLSTEALTH:
        case IDC_DLLUNLOAD:
        {   //DLL injection options need to be updated on-the-fly coz the injection button is ON the options window
            if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLSTEALTH), BM_GETCHECK, 0, 0))
            {
                g_settings.opts().dllStealth = 1;
            }
            else
                g_settings.opts().dllStealth = 0;
            if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLNORMAL), BM_GETCHECK, 0, 0))
            {
                g_settings.opts().dllNormal = 1;
            }
            else
                g_settings.opts().dllNormal = 0;
            if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_DLLUNLOAD), BM_GETCHECK, 0, 0))
            {
                g_settings.opts().dllUnload = 1;
            }
            else
                g_settings.opts().dllUnload = 0;


            break;
        }
        case IDC_INJECTDLL:
        {
            if(ProcessId)
            {
                if(GetFileDialog(DllPathForInjection))
                {
                    if (dbg->is_remote())
                    {
                        SendInjectToServer(ProcessId);
                    }
                    else
                    {
#ifndef BUILD_IDA_64BIT
                        injectDll(ProcessId, DllPathForInjection);
#endif
                    }

                }
            }
            break;
        }
        case IDC_ATTACH:
        {
            EndDialog(hWnd, NULL);
            DialogBox(hinst, MAKEINTRESOURCE(IDD_ATTACH), (HWND)callui(ui_get_hwnd).vptr, &AttachProc);
            break;
        }
        case IDC_ABOUT:
        {
            ShowAbout((HWND)callui(ui_get_hwnd).vptr);
            break;
        }
#endif
        case IDC_SELECT_EXCEPTIONS:
        {
            createExceptionWindow(hWnd);
            HandleGuiException(hWnd);
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

void HandleGuiException(HWND hwnd)
{
#ifdef OLLY1
    if (g_settings.opts().handleExceptionIllegalInstruction &&
        g_settings.opts().handleExceptionInvalidLockSequence &&
        g_settings.opts().handleExceptionNoncontinuableException &&
        g_settings.opts().handleExceptionPrint &&
        g_settings.opts().handleExceptionRip &&
        g_settings.opts().handleExceptionBreakpoint &&
        g_settings.opts().handleExceptionWx86Breakpoint &&
        g_settings.opts().handleExceptionGuardPageViolation
        )
#endif
#ifdef OLLY2
        if (g_settings.opts().handleExceptionNoncontinuableException &&
            g_settings.opts().handleExceptionPrint &&
            g_settings.opts().handleExceptionRip
            )
#endif
#ifdef __IDP__
            if (g_settings.opts().handleExceptionNoncontinuableException &&
                g_settings.opts().handleExceptionPrint &&
                g_settings.opts().handleExceptionAssertionFailure &&
                g_settings.opts().handleExceptionRip
                )
#endif
#ifdef X64DBG
                if (1)
#endif
                {
                    CheckDlgButton(hwnd, IDC_EXCEPTION_ALL, BST_CHECKED);
                }
                else
                {
                    CheckDlgButton(hwnd, IDC_EXCEPTION_ALL, 0);
                }
}

typedef struct _NAME_TOOLTIP {
    const WCHAR * name;
    WCHAR * tooltip;
    int windowId;
} NAME_TOOLTIP;


enum {
    ID_EXCEPTION_PRINT = 200,
    ID_EXCEPTION_RIP,
    ID_EXCEPTION_Noncontinable,
    ID_EXCEPTION_Illegal,
    ID_EXCEPTION_InvalidLockSequence,
    ID_EXCEPTION_AssertionFailure,
    ID_EXCEPTION_GuardPage,
    ID_EXCEPTION_Breakpoint,
    ID_EXCEPTION_Wx86Breakpoint,
    ID_EXCEPTION_APPLY,
    ID_EXCEPTION_CANCEL
};

NAME_TOOLTIP exceptionNamesTooltip[] = {
    {
        L"Print", L"DBG_PRINTEXCEPTION_C 0x40010006", ID_EXCEPTION_PRINT
    },
    {
        L"RIP", L"DBG_RIPEXCEPTION 0x40010007", ID_EXCEPTION_RIP
    }
#if defined(OLLY1) || defined(OLLY2)
    ,{
        L"Non-continuable", L"STATUS_NONCONTINUABLE_EXCEPTION 0xC0000025", ID_EXCEPTION_Noncontinable
    }
#endif
#ifdef OLLY1
    ,{
        L"Illegal Instruction", L"STATUS_ILLEGAL_INSTRUCTION 0xC000001D", ID_EXCEPTION_Illegal
    },
    {
        L"Invalid Lock Sequence", L"STATUS_INVALID_LOCK_SEQUENCE 0xC000001E", ID_EXCEPTION_InvalidLockSequence
    },
    {
        L"Guard Page Violation", L"STATUS_GUARD_PAGE_VIOLATION 0x80000001", ID_EXCEPTION_GuardPage
    },
    {
        L"Breakpoint", L"STATUS_BREAKPOINT 0x80000003", ID_EXCEPTION_Breakpoint
    },
    {
        L"WX86 Breakpoint", L"STATUS_WX86_BREAKPOINT 0x4000001F", ID_EXCEPTION_Wx86Breakpoint
    }
#endif
#ifdef __IDP__
    ,{
        L"Assertion Failure", L"STATUS_ASSERTION_FAILURE 0xC0000420", ID_EXCEPTION_AssertionFailure
    }
#endif
};

void ResetAllExceptions()
{
    g_settings.opts().handleExceptionPrint = 0;
    g_settings.opts().handleExceptionIllegalInstruction = 0;
    g_settings.opts().handleExceptionInvalidLockSequence = 0;
    g_settings.opts().handleExceptionNoncontinuableException = 0;
    g_settings.opts().handleExceptionRip = 0;
    g_settings.opts().handleExceptionAssertionFailure = 0;
    g_settings.opts().handleExceptionBreakpoint = 0;
    g_settings.opts().handleExceptionGuardPageViolation = 0;
    g_settings.opts().handleExceptionWx86Breakpoint = 0;
}

#define HEIGHT_OF_EXCEPTION_CHECKBOX 16
#define EXCEPTION_WINDOW_BASE_HEIGHT 46
#define EXCEPTION_WINDOW_WIDTH 200
LRESULT CALLBACK ExceptionSettingsWndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    RECT rect;
    LONG height;
    HINSTANCE hInst = GetModuleHandleW(0);

    if (msg == WM_CREATE)
    {
        int numOfExceptions = _countof(exceptionNamesTooltip);

        HWND control;
        GetClientRect(hwnd, &rect);
        height = rect.bottom;
        GetWindowRect(hwnd, &rect);
        height = rect.bottom - rect.top - height + (EXCEPTION_WINDOW_BASE_HEIGHT + (numOfExceptions*(HEIGHT_OF_EXCEPTION_CHECKBOX + 5))) + 5;
        SetWindowPos(hwnd, NULL, 0, 0, rect.right - rect.left, height, SWP_NOMOVE | SWP_NOZORDER);

        HFONT hFont;
        NONCLIENTMETRICSW metric = { 0 };
        metric.cbSize = sizeof(NONCLIENTMETRICSW);
        if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &metric, 0))
        {
            hFont = CreateFontIndirectW(&metric.lfMessageFont);
        }
        else
        {
            hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        }

        HWND hwndTT = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, NULL, 0, NULL);

        for (int i = 0, j = 200; i < numOfExceptions; i++, j++)
        {
            control = CreateWindowExW(0, L"Button", exceptionNamesTooltip[i].name, WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 1, i * 20, EXCEPTION_WINDOW_WIDTH, HEIGHT_OF_EXCEPTION_CHECKBOX, hwnd, (HMENU)exceptionNamesTooltip[i].windowId, hInst, NULL);
            SendMessage(control, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0));

            TOOLINFO ti = { 0 };

            ti.cbSize = TTTOOLINFO_V1_SIZE;
            ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND;
            ti.hwnd = hwnd;
            ti.uId = (UINT_PTR)control;
            ti.lpszText = exceptionNamesTooltip[i].tooltip;

            SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM)&ti);
        }

        if (g_settings.opts().handleExceptionPrint) CheckDlgButton(hwnd, ID_EXCEPTION_PRINT, BST_CHECKED);
        if (g_settings.opts().handleExceptionIllegalInstruction) CheckDlgButton(hwnd, ID_EXCEPTION_Illegal, BST_CHECKED);
        if (g_settings.opts().handleExceptionInvalidLockSequence) CheckDlgButton(hwnd, ID_EXCEPTION_InvalidLockSequence, BST_CHECKED);
        if (g_settings.opts().handleExceptionNoncontinuableException) CheckDlgButton(hwnd, ID_EXCEPTION_Noncontinable, BST_CHECKED);
        if (g_settings.opts().handleExceptionAssertionFailure) CheckDlgButton(hwnd, ID_EXCEPTION_AssertionFailure, BST_CHECKED);
        if (g_settings.opts().handleExceptionBreakpoint) CheckDlgButton(hwnd, ID_EXCEPTION_Breakpoint, BST_CHECKED);
        if (g_settings.opts().handleExceptionGuardPageViolation) CheckDlgButton(hwnd, ID_EXCEPTION_GuardPage, BST_CHECKED);
        if (g_settings.opts().handleExceptionWx86Breakpoint) CheckDlgButton(hwnd, ID_EXCEPTION_Wx86Breakpoint, BST_CHECKED);
        if (g_settings.opts().handleExceptionRip) CheckDlgButton(hwnd, ID_EXCEPTION_RIP, BST_CHECKED);

        control = CreateWindowExW(0, L"Button", L"Apply", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 1, (numOfExceptions)* 20 + 1, 100, 25, hwnd, (HMENU)ID_EXCEPTION_APPLY, hInst, NULL);
        SendMessage(control, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0));
        control = CreateWindowExW(0, L"Button", L"Cancel", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 1, (numOfExceptions + 1) * 20 + 5, 100, 25, hwnd, (HMENU)ID_EXCEPTION_CANCEL, hInst, NULL);
        SendMessage(control, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0));

        //DeleteObject(hFont);

    }
    else if (msg == WM_COMMAND)
    {
        if (LOWORD(wparam) == ID_EXCEPTION_APPLY)
        {

            ResetAllExceptions();

            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_PRINT) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionPrint = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Illegal) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionIllegalInstruction = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_InvalidLockSequence) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionInvalidLockSequence = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Noncontinable) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionNoncontinuableException = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_RIP) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionRip = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_GuardPage) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionGuardPageViolation = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Breakpoint) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionBreakpoint = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Wx86Breakpoint) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionWx86Breakpoint = 1;
            }
            if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_AssertionFailure) == BST_CHECKED)
            {
                g_settings.opts().handleExceptionAssertionFailure = 1;
            }
            DestroyWindow(hwnd);
        }
        else if (LOWORD(wparam) == ID_EXCEPTION_CANCEL)
        {
            DestroyWindow(hwnd);
        }
    }
    else if (msg == WM_CLOSE)
    {
        DestroyWindow(hwnd);
    }
    else if (msg == WM_DESTROY)
    {
        PostQuitMessage(0);
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

void createExceptionWindow(HWND hwnd)
{
    WCHAR * classname = L"exception_window_config_scyllahide";
    WNDCLASSW wc = { 0 };
    HWND     wnd;
    MSG      msg;
    //wc.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
    wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
    wc.hInstance = GetModuleHandleW(0);
    wc.style = CS_PARENTDC | CS_DBLCLKS;
    wc.lpfnWndProc = ExceptionSettingsWndproc;
    wc.lpszClassName = classname;
    RegisterClassW(&wc);

    int windowHeight = EXCEPTION_WINDOW_BASE_HEIGHT + (_countof(exceptionNamesTooltip)*(HEIGHT_OF_EXCEPTION_CHECKBOX + 5));

    wnd = CreateWindowExW(0,
        classname,
        L"Exception Settings",
        WS_VISIBLE | WS_SYSMENU | WS_OVERLAPPED | DS_SYSMODAL,
        (GetSystemMetrics(SM_CXSCREEN) - EXCEPTION_WINDOW_WIDTH) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - windowHeight) / 2,
        EXCEPTION_WINDOW_WIDTH,
        windowHeight,
        hwnd,
        NULL,
        GetModuleHandleW(0),
        NULL);

    ShowWindow(wnd, SW_SHOWNORMAL);
    UpdateWindow(wnd);

    //EnableWindow(hwnd, FALSE);

    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    //EnableWindow(hwnd, TRUE);
    UnregisterClassW(classname, 0);
}
