#define _CRT_SECURE_NO_WARNINGS
#include "OptionsDialog.h"
#include "..\PluginGeneric\IniSettings.h"
#include "..\PluginGeneric\Injector.h"
#include "..\PluginGeneric\ScyllaHideVersion.h"

#ifdef OLLY1
#include "..\ScyllaHideOlly1Plugin\resource.h"
#include "..\ScyllaHideOlly1Plugin\ollyplugindefinitions.h"
#elif OLLY2
#include "..\ScyllaHideOlly2Plugin\resource.h"
#include "..\ScyllaHideOlly2Plugin\plugin.h"
#elif __IDP__
//#define BUILD_IDA_64BIT 1
#include "..\ScyllaHideIDAProPlugin\resource.h"
#include "..\ScyllaHideIDAProPlugin\idasdk\ida.hpp"
#include "..\ScyllaHideIDAProPlugin\idasdk\idp.hpp"
#include "..\ScyllaHideIDAProPlugin\idasdk\dbg.hpp"
#include "..\PluginGeneric\UpdateCheck.h"
#include "..\ScyllaHideIDAProPlugin\IdaServerClient.h"
#include "..\PluginGeneric\AttachDialog.h"
#elif X64DBG
#include "..\ScyllaHideX64DBGPlugin\bridgemain.h"
#include "..\ScyllaHideX64DBGPlugin\resource.h"
#endif

extern WCHAR CurrentProfile[MAX_SECTION_NAME];
extern WCHAR ProfileNames[2048];
extern struct HideOptions pHideOptions;
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
                "ScyllaHide Plugin v"SCYLLA_HIDE_VERSION_STRING_A"\n"
                "(Anti-Anti-Debug in usermode)\n\n"
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
                "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
}

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

void UpdateOptions(HWND hWnd)
{
    SendMessage(GetDlgItem(hWnd, IDC_PEBBEINGDEBUGGED), BM_SETCHECK, pHideOptions.PEBBeingDebugged, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PEBHEAPFLAGS), BM_SETCHECK, pHideOptions.PEBHeapFlags, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PEBNTGLOBALFLAG), BM_SETCHECK, pHideOptions.PEBNtGlobalFlag, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PEBSTARTUPINFO), BM_SETCHECK, pHideOptions.PEBStartupInfo, 0);
    if(pHideOptions.PEBBeingDebugged && pHideOptions.PEBHeapFlags && pHideOptions.PEBNtGlobalFlag && pHideOptions.PEBStartupInfo)
        SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 1, 0);
    else
        SendMessage(GetDlgItem(hWnd, IDC_PEB), BM_SETCHECK, 0, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONTHREAD), BM_SETCHECK, pHideOptions.NtSetInformationThread, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONPROCESS), BM_SETCHECK, pHideOptions.NtSetInformationProcess, 0);
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
    else
        SendMessage(GetDlgItem(hWnd, IDC_PROTECTDRX), BM_SETCHECK, 0, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTUSERFINDWINDOWEX), BM_SETCHECK, pHideOptions.NtUserFindWindowEx, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTUSERBUILDHWNDLIST), BM_SETCHECK, pHideOptions.NtUserBuildHwndList, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTUSERQUERYWINDOW), BM_SETCHECK, pHideOptions.NtUserQueryWindow, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTSETDEBUGFILTERSTATE), BM_SETCHECK, pHideOptions.NtSetDebugFilterState, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTCLOSE), BM_SETCHECK, pHideOptions.NtClose, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTCREATETHREADEX), BM_SETCHECK, pHideOptions.NtCreateThreadEx, 0);
    SendMessage(GetDlgItem(hWnd, IDC_REMOVEDEBUGPRIV), BM_SETCHECK, pHideOptions.removeDebugPrivileges, 0);
    SendMessage(GetDlgItem(hWnd, IDC_PREVENTTHREADCREATION), BM_SETCHECK, pHideOptions.preventThreadCreation, 0);
    SendMessage(GetDlgItem(hWnd, IDC_RUNPE), BM_SETCHECK, pHideOptions.malwareRunpeUnpacker, 0);
    SendMessage(GetDlgItem(hWnd, IDC_DLLSTEALTH), BM_SETCHECK, pHideOptions.DLLStealth, 0);
    SendMessage(GetDlgItem(hWnd, IDC_DLLNORMAL), BM_SETCHECK, pHideOptions.DLLNormal, 0);
    SendMessage(GetDlgItem(hWnd, IDC_DLLUNLOAD), BM_SETCHECK, pHideOptions.DLLUnload, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT), BM_SETCHECK, pHideOptions.GetTickCount, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETTICKCOUNT64), BM_SETCHECK, pHideOptions.GetTickCount64, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETLOCALTIME), BM_SETCHECK, pHideOptions.GetLocalTime, 0);
    SendMessage(GetDlgItem(hWnd, IDC_GETSYSTEMTIME), BM_SETCHECK, pHideOptions.GetSystemTime, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYSYSTEMTIME), BM_SETCHECK, pHideOptions.NtQuerySystemTime, 0);
    SendMessage(GetDlgItem(hWnd, IDC_NTQUERYPERFCOUNTER), BM_SETCHECK, pHideOptions.NtQueryPerformanceCounter, 0);
    SendMessage(GetDlgItem(hWnd, IDC_KILLANTIATTACH), BM_SETCHECK, pHideOptions.killAntiAttach, 0);


#ifdef OLLY1
    SetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle);
    SendMessage(GetDlgItem(hWnd, IDC_DELEPBREAK), BM_SETCHECK, pHideOptions.removeEPBreak, 0);
    SendMessage(GetDlgItem(hWnd, IDC_FIXOLLY), BM_SETCHECK, pHideOptions.fixOllyBugs, 0);
    SendMessage(GetDlgItem(hWnd, IDC_X64FIX), BM_SETCHECK, pHideOptions.x64Fix, 0);
    SendMessage(GetDlgItem(hWnd, IDC_SKIPEPOUTSIDE), BM_SETCHECK, pHideOptions.skipEPOutsideCode, 0);
    SendMessage(GetDlgItem(hWnd, IDC_BREAKTLS), BM_SETCHECK, pHideOptions.breakTLS, 0);

    if(pHideOptions.skipCompressedDoAnalyze || pHideOptions.skipCompressedDoNothing) {
        SendMessage(GetDlgItem(hWnd, IDC_COMPRESSED), BM_SETCHECK, 1, 0);
        EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), TRUE);
        EnableWindow(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), TRUE);
    }
    SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), BM_SETCHECK, pHideOptions.skipCompressedDoAnalyze, 0);
    SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), BM_SETCHECK, pHideOptions.skipCompressedDoNothing, 0);
    if(pHideOptions.skipLoadDllDoLoad || pHideOptions.skipLoadDllDoNothing) {
        SendMessage(GetDlgItem(hWnd, IDC_LOADDLL), BM_SETCHECK, 1, 0);
        EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLLOAD), TRUE);
        EnableWindow(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), TRUE);
    }
    SendMessage(GetDlgItem(hWnd, IDC_LOADDLLLOAD), BM_SETCHECK, pHideOptions.skipLoadDllDoLoad, 0);
    SendMessage(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), BM_SETCHECK, pHideOptions.skipLoadDllDoNothing, 0);
    SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDGOTO), BM_SETCHECK, pHideOptions.advancedGoto, 0);
    SendMessage(GetDlgItem(hWnd, IDC_BADPEIMAGE), BM_SETCHECK, pHideOptions.ignoreBadPEImage, 0);
    SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDINFOBAR), BM_SETCHECK, pHideOptions.advancedInfobar, 0);
	EnableWindow(GetDlgItem(hWnd, IDC_OUTPUTDEBUGSTRINGA), FALSE);
#elif OLLY2
    SetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle);
#elif __IDP__
    SendMessage(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), BM_SETCHECK, pHideOptions.autostartServer, 0);
    SetDlgItemTextW(hWnd, IDC_SERVERPORT, pHideOptions.serverPort);

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
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_NTSETINFORMATIONPROCESS), BM_GETCHECK, 0, 0))
    {
        pHideOptions.NtSetInformationProcess = 1;
    }
    else
        pHideOptions.NtSetInformationProcess = 0;
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
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_PREVENTTHREADCREATION), BM_GETCHECK, 0, 0))
    {
        pHideOptions.preventThreadCreation = 1;
    }
    else
        pHideOptions.preventThreadCreation = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_RUNPE), BM_GETCHECK, 0, 0))
    {
        pHideOptions.malwareRunpeUnpacker = 1;
    }
    else
        pHideOptions.malwareRunpeUnpacker = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_REMOVEDEBUGPRIV), BM_GETCHECK, 0, 0))
    {
        pHideOptions.removeDebugPrivileges = 1;
    }
    else
        pHideOptions.removeDebugPrivileges = 0;
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
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_KILLANTIATTACH), BM_GETCHECK, 0, 0))
    {
        pHideOptions.killAntiAttach = 1;
    }
    else
        pHideOptions.killAntiAttach = 0;

#ifdef OLLY1
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
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_SKIPEPOUTSIDE), BM_GETCHECK, 0, 0))
    {
        pHideOptions.skipEPOutsideCode = 1;
    }
    else
        pHideOptions.skipEPOutsideCode = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_BADPEIMAGE), BM_GETCHECK, 0, 0))
    {
        pHideOptions.ignoreBadPEImage = 1;
    }
    else
        pHideOptions.ignoreBadPEImage = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDGOTO), BM_GETCHECK, 0, 0))
    {
        pHideOptions.advancedGoto = 1;
    }
    else
        pHideOptions.advancedGoto = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDANALYZE), BM_GETCHECK, 0, 0))
    {
        pHideOptions.skipCompressedDoAnalyze = 1;
    }
    else
        pHideOptions.skipCompressedDoAnalyze = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_COMPRESSEDNOTHING), BM_GETCHECK, 0, 0))
    {
        pHideOptions.skipCompressedDoNothing = 1;
    }
    else
        pHideOptions.skipCompressedDoNothing = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_LOADDLLLOAD), BM_GETCHECK, 0, 0))
    {
        pHideOptions.skipLoadDllDoLoad = 1;
    }
    else
        pHideOptions.skipLoadDllDoLoad = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_LOADDLLNOTHING), BM_GETCHECK, 0, 0))
    {
        pHideOptions.skipLoadDllDoNothing = 1;
    }
    else
        pHideOptions.skipLoadDllDoNothing = 0;
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_ADVANCEDINFOBAR), BM_GETCHECK, 0, 0))
    {
        pHideOptions.advancedInfobar = 1;
    }
    else
        pHideOptions.advancedInfobar = 0;
#elif __IDP__
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_AUTOSTARTSERVER), BM_GETCHECK, 0, 0))
    {
        pHideOptions.autostartServer = 1;
    }
    else
        pHideOptions.autostartServer = 0;

    GetDlgItemTextW(hWnd, IDC_SERVERPORT, pHideOptions.serverPort, 6);
#endif

#ifdef OLLY1
    GetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle, 33);
    SetWindowTextW(hwmain, pHideOptions.ollyTitle);
#elif OLLY2
    GetDlgItemTextW(hWnd, IDC_OLLYTITLE, pHideOptions.ollyTitle, 33);
    SetWindowTextW(hwollymain, pHideOptions.ollyTitle);
#endif

    //save all options
    SaveSettings();
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
        { IDOK,                          L"Apply Settings and close the dialog"   },
        { IDC_PROFILES,                  L"Select profile"                        },
        { IDC_SAVEPROFILE,               L"Save profile"                          },
        { IDC_PEB,                       L"The most important anti-anti-debug option. Almost every protector checks for\r\nPEB values. There are three important options and one minor option."},
        { IDC_PEBBEINGDEBUGGED,          L"Very important option, should be always enabled.\r\nIsDebuggerPresent is using this value to check for debuggers."},
        { IDC_PEBHEAPFLAGS,              L"Very important option, a lot of protectors check for this value."},
        { IDC_PEBNTGLOBALFLAG,           L"Very important option. E.g. Themida checks for heap artifacts and heap flags."},
        { IDC_PEBSTARTUPINFO,            L"This is not really important, only a few protectors check for this. Maybe Enigma checks it."},
        { IDC_NTSETINFORMATIONTHREAD,    L"The THREADINFOCLASS value ThreadHideFromDebugger is a well-known\r\nanti-debug measurement. The debugger cannot handle hidden threads.\r\nThis leads to a loss of control over the target."},
        { IDC_NTSETINFORMATIONPROCESS,   L"The PROCESSINFOCLASS value ProcessHandleTracing can be used to\r\ndetect a debugger. The PROCESSINFOCLASS value ProcessBreakOnTermination\r\ncan be used to generate a Blue Screen of Death on process termination."},
        { IDC_NTQUERYSYSTEMINFORMATION,  L"The SYSTEM_INFORMATION_CLASS value SystemKernelDebuggerInformation\r\ncan be used to detect kernel debuggers. The SYSTEM_INFORMATION_CLASS\r\nvalue SystemProcessInformation is used to get a process list. A debugger\r\nshould be hidden in a process list and the debugee should have a good parent\r\nprocess ID like the ID from explorer.exe."},
        {   IDC_NTQUERYINFORMATIONPROCESS, L"A very important option. Various PROCESSINFOCLASS values can be used\r\nto detect a debugger.\r\n\
    ProcessDebugFlags: Should return 1 in the supplied buffer.\r\n\
    ProcessDebugPort: Should return 0 in the supplied buffer.\r\n\
    ProcessDebugObjectHandle: Should return 0 in the supplied buffer\r\nand the error STATUS_PORT_NOT_SET (0xC0000353)\r\n\
    ProcessBasicInformation: Reveals the parent process ID.\r\n\
    ProcessBreakOnTermination: Please see NtSetInformationProcess\r\n\
    ProcessHandleTracing: Please see NtSetInformationProcess\r\n\
A lot of protectors use this to detect debuggers. The windows API CheckRemoteDebuggerPresent uses NtQueryInformationProcess internally."
        },
        { IDC_NTQUERYOBJECT,             L"The OBJECT_INFORMATION_CLASS ObjectTypesInformation and ObjectTypeInformation\r\ncan be used to detect debuggers. ScyllaHide filters DebugObject references."},
        { IDC_NTYIELDEXECUTION,          L"A very unrealiable anti-debug method. This is only used in some UnpackMe's\r\nor in some Proof of Concept code. Only activate this if you really need it.\r\nProbably you will never need this option."},
        { IDC_NTCREATETHREADEX,          L"Threads hidden from debuggers can be created with a special creation flag\r\nTHREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER. ScyllaHide doesn't\r\nallow hidden threads. The anti-debug effect is similar to NtSetInformationThread"},
        { IDC_OUTPUTDEBUGSTRINGA,        L"OutputDebugStringW uses OutputDebugStringA internally. ScyllaHide only hooks\r\nthe ANSI version and this is therefore enough. This is a very unreliable\r\nantidebug method, so you will not need this option very often."},
        { IDC_BLOCKINPUT,                L"Very effective anti-debug method. This is used e.g. in Yoda's Protector. \r\n\"Blocks keyboard and mouse input events from reaching applications.\""},
        { IDC_NTUSERFINDWINDOWEX,        L"This is a system call function in user32.dll. The windows APIs FindWindowA/W\r\n and FindWindowExA/W call this internally. The debugger window will be hidden."},
        { IDC_NTUSERBUILDHWNDLIST,       L"This is a system call function in user32.dll. The windows APIs EnumWindows\r\nand EnumThreadWindows call this internally. The debugger window will be hidden."},
        { IDC_NTUSERQUERYWINDOW,         L"This is a system call function in user32.dll. The windows API GetWindowThreadProcessId\r\n calls this internally. This is used to hide the debugger process."},
        { IDC_NTSETDEBUGFILTERSTATE,     L"ScyllaHide returns always STATUS_ACCESS_DENIED. This anti-debugn measurement\r\nisn't used very often. Probably you will never need this option in a real world target."},
        { IDC_NTCLOSE,                   L"This is called with an invalid handle to detect a debugger. ScyllaHide calls\r\nNtQueryObject to check the validity of the handle. A few protectors are using\r\nthis method."},
        { IDC_REMOVEDEBUGPRIV,           L"If a debugger creates the process of the target, the target will have debug\r\nprivileges. This can be used to detect a debugger."},
        { IDC_PROTECTDRX,                L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"},
        { IDC_NTGETCONTEXTTHREAD,        L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"},
        { IDC_NTSETCONTEXTTHREAD,        L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"},
        { IDC_NTCONTINUE,                L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"},
        { IDC_KIUED,                     L"Hardware breakpoints can be detected/cleared with exceptions or the windows\r\nAPIs NtGetContextThread/NtSetContextThread. Enable this option only if you need it!"},
        { IDC_GETTICKCOUNT,              L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!"},
        { IDC_GETTICKCOUNT64,            L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!"},
        { IDC_GETLOCALTIME,              L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!"},
        { IDC_GETSYSTEMTIME,             L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!"},
        { IDC_NTQUERYSYSTEMTIME,         L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!"},
        { IDC_NTQUERYPERFCOUNTER,        L"There are a few windows APIs to measure the time. Timing can be used to\r\ndetect debuggers, because they slow down the execution. Enable with care\r\nand only if you need it!"},
        { IDC_PREVENTTHREADCREATION,     L"This option prevents the creation of new threads. This can be useful if a protector\r\n uses a lot of protection threads. This option can be useful for EXECryptor.\r\nEnable with care and only if you need it!\r\nYou must know what you are doing here!"},
        {   IDC_RUNPE,                     L"This option hooks NtResumeThread. If the malware creates a new process,\r\nScyllaHide terminates and dumps any newly created process. If you are unpacking\r\nmalware, enable and try it. Should be only used inside a VM.\r\n\
A typical RunPE workflow:\r\n\
    1. Create a new process of any target in suspended state (Process flag\r\nCREATE_SUSPENDED: 0x00000004)\r\n\
    2. Replace the original process PE image with a new (malicious) PE image.\r\nThis can involve several steps and various windows API functions.\r\n\
    3. Start the process with the windows API function ResumeThread (or NtResumeThread)."
        },
        { IDC_DLLSTEALTH,                L"Normal DLL injection or stealth dll injection. You better try the normal\r\ninjection first..."},
        { IDC_DLLNORMAL,                 L"Normal DLL injection or stealth dll injection. You better try the normal\r\ninjection first..."},
        { IDC_DLLUNLOAD,                 L"Unload after DLLMain"                  },
        { IDC_KILLANTIATTACH,            L"Kill Anti-Attach"                      },
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

                    ti.cbSize   = TTTOOLINFO_V1_SIZE;
                    ti.uFlags   = TTF_SUBCLASS | TTF_IDISHWND;
                    ti.hwnd     = hwndDlg;
                    ti.uId      = (UINT_PTR)hwnd;
                    ti.hinst    = hInstance;
                    ti.lpszText = (LPWSTR)lpszText;
                    ti.lParam   = 0;

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
        ReadSettings();

        //add current profile to options title
        WCHAR title[MAX_SECTION_NAME+30] = {0};
        wcscpy(title, L"[ScyllaHide Options] Profile: ");
        wcscat(title, CurrentProfile);
        SetWindowTextW(hWnd, title);

        //fill combobox with profiles
        WCHAR* profile = ProfileNames;
        int index = 0;
        while(*profile != 0x00)
        {

            SendMessage(GetDlgItem(hWnd, IDC_PROFILES), CB_ADDSTRING,0,(LPARAM) profile);

            if(wcscmp(profile, CurrentProfile) == 0)
                SendMessage(GetDlgItem(hWnd, IDC_PROFILES), CB_SETCURSEL, index, 0);


            index++;
            profile = profile + wcslen(profile) + 1;
        }

        UpdateOptions(hWnd);

#ifdef OLLY1
        if (!isWindows64())
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
        switch(LOWORD(wParam))
        {
        case IDC_PROFILES:
        {
            int profileIndex = (int)SendMessage(GetDlgItem(hWnd, IDC_PROFILES), (UINT) CB_GETCURSEL, 0, 0);
            profileIndex+=10; //increase when top-level menu needs more than 9 elements, probably never

            SetCurrentProfile(profileIndex);

            //update options title
            WCHAR title[MAX_SECTION_NAME+30] = {0};
            wcscpy(title, L"[ScyllaHide Options] Profile: ");
            wcscat(title, CurrentProfile);
            SetWindowTextW(hWnd, title);

            ReadSettings();
            UpdateOptions(hWnd);

            break;
        }
        case IDC_SAVEPROFILE:
        {
            WCHAR newProfileW[MAX_SECTION_NAME] = {0};
#ifdef OLLY1
            char newProfile[MAX_SECTION_NAME] = {0};
            if(_Gettext("New profile name?", newProfile, 0, 0, 0)>0) {
                mbstowcs(newProfileW, newProfile, MAX_SECTION_NAME);
#elif OLLY2
            if(Getstring(hWnd, L"New profile name?", newProfileW, MAX_SECTION_NAME, 0, 0, 0, 0, 0, 0)>0) {
#elif __IDP__
            char* newProfile;
            newProfile = askstr(0, "", "New profile name?");
            if(newProfile != NULL) {
                mbstowcs(newProfileW, newProfile, MAX_SECTION_NAME);
#elif X64DBG
            char newProfile[GUI_MAX_LINE_SIZE]="";
            if(GuiGetLineWindow("New profile name?", newProfile)) {
                mbstowcs(newProfileW, newProfile, MAX_SECTION_NAME);
#endif
                SetCurrentProfile(newProfileW);
                SaveOptions(hWnd); //this creates the new section in the ini

                WCHAR title[MAX_SECTION_NAME+30] = {0};
                wcscpy(title, L"[ScyllaHide Options] Profile: ");
                wcscat(title, CurrentProfile);
                SetWindowTextW(hWnd, title);
                SendMessage(GetDlgItem(hWnd, IDC_PROFILES), CB_ADDSTRING,0,(LPARAM) newProfileW);
                int profileCount = (int)SendMessage(GetDlgItem(hWnd, IDC_PROFILES), CB_GETCOUNT, 0, 0);
                SendMessage(GetDlgItem(hWnd, IDC_PROFILES), CB_SETCURSEL, profileCount-1, 0);

                //need to update the ProfileNames buffer so re-selecting new profile while dialog hasnt been closed will work
                GetPrivateProfileSectionNamesW(ProfileNames, sizeof(ProfileNames)/sizeof(WCHAR), ScyllaHideIniPath);
            }

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
					pHideOptions.handleExceptionPrint = 1;
					pHideOptions.handleExceptionIllegalInstruction = 1;
					pHideOptions.handleExceptionInvalidLockSequence = 1;
					pHideOptions.handleExceptionNoncontinuableException = 1;
					pHideOptions.handleExceptionRip = 1;
					pHideOptions.handleExceptionAssertionFailure = 1;
					pHideOptions.handleExceptionBreakpoint = 1;
					pHideOptions.handleExceptionGuardPageViolation = 1;
					pHideOptions.handleExceptionWx86Breakpoint = 1;
				}
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
        case IDC_UPDATE:
        {
            if(isNewVersionAvailable()) {
                MessageBoxA((HWND)callui(ui_get_hwnd).vptr,
                            "There is a new version of ScyllaHide available !\n\n"
                            "Check out https://bitbucket.org/NtQuery/scyllahide/downloads \n"
                            "or some RCE forums !",
                            "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
            } else {
                MessageBoxA((HWND)callui(ui_get_hwnd).vptr,
                            "You already have the latest version of ScyllaHide !",
                            "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
            }
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
	if (pHideOptions.handleExceptionIllegalInstruction &&
		pHideOptions.handleExceptionInvalidLockSequence &&
		pHideOptions.handleExceptionNoncontinuableException &&
		pHideOptions.handleExceptionPrint &&
		pHideOptions.handleExceptionRip &&
		pHideOptions.handleExceptionBreakpoint &&
		pHideOptions.handleExceptionWx86Breakpoint &&
		pHideOptions.handleExceptionGuardPageViolation
		)
#endif
#ifdef OLLY2
		if (pHideOptions.handleExceptionNoncontinuableException &&
			pHideOptions.handleExceptionPrint &&
			pHideOptions.handleExceptionRip
			)
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
		L"Print",L"DBG_PRINTEXCEPTION_C 0x40010006", ID_EXCEPTION_PRINT
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
	pHideOptions.handleExceptionPrint = 0;
	pHideOptions.handleExceptionIllegalInstruction = 0;
	pHideOptions.handleExceptionInvalidLockSequence = 0;
	pHideOptions.handleExceptionNoncontinuableException = 0;
	pHideOptions.handleExceptionRip = 0;
	pHideOptions.handleExceptionAssertionFailure = 0;
	pHideOptions.handleExceptionBreakpoint = 0;
	pHideOptions.handleExceptionGuardPageViolation = 0;
	pHideOptions.handleExceptionWx86Breakpoint = 0;
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
		height = rect.bottom - rect.top - height + (EXCEPTION_WINDOW_BASE_HEIGHT + (numOfExceptions*(HEIGHT_OF_EXCEPTION_CHECKBOX+5)));
		SetWindowPos(hwnd, NULL, 0, 0, rect.right - rect.left, height, SWP_NOMOVE | SWP_NOZORDER);

		HFONT hFont;
		NONCLIENTMETRICSW metric = {0};
		metric.cbSize = sizeof(NONCLIENTMETRICSW);
		if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICSW), &metric, 0))
		{
			hFont = CreateFontIndirectW(&metric.lfMessageFont);
		}
		else
		{
			hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
		}

		HWND hwndTT = CreateWindowExW(WS_EX_TOPMOST,TOOLTIPS_CLASS,NULL,WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,hwnd,NULL,0,NULL);

		for (int i = 0, j = 200; i < numOfExceptions; i++, j++)
		{
			control = CreateWindowExW(0, L"Button", exceptionNamesTooltip[i].name, WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 1, i*20, EXCEPTION_WINDOW_WIDTH, HEIGHT_OF_EXCEPTION_CHECKBOX, hwnd, (HMENU)exceptionNamesTooltip[i].windowId, hInst, NULL);
			SendMessage(control,WM_SETFONT,(WPARAM)hFont,MAKELPARAM(1,0));

			TOOLINFO ti = {0};

			ti.cbSize   = TTTOOLINFO_V1_SIZE;
			ti.uFlags   = TTF_SUBCLASS | TTF_IDISHWND;
			ti.hwnd     = hwnd;
			ti.uId      = (UINT_PTR)control;
			ti.lpszText = exceptionNamesTooltip[i].tooltip;

			SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM)&ti);
		}

		if (pHideOptions.handleExceptionPrint) CheckDlgButton(hwnd, ID_EXCEPTION_PRINT, BST_CHECKED);
		if (pHideOptions.handleExceptionIllegalInstruction) CheckDlgButton(hwnd, ID_EXCEPTION_Illegal, BST_CHECKED);
		if (pHideOptions.handleExceptionInvalidLockSequence) CheckDlgButton(hwnd, ID_EXCEPTION_InvalidLockSequence, BST_CHECKED);
		if (pHideOptions.handleExceptionNoncontinuableException) CheckDlgButton(hwnd, ID_EXCEPTION_Noncontinable, BST_CHECKED);
		if (pHideOptions.handleExceptionAssertionFailure) CheckDlgButton(hwnd, ID_EXCEPTION_AssertionFailure, BST_CHECKED);
		if (pHideOptions.handleExceptionBreakpoint) CheckDlgButton(hwnd, ID_EXCEPTION_Breakpoint, BST_CHECKED);
		if (pHideOptions.handleExceptionGuardPageViolation) CheckDlgButton(hwnd, ID_EXCEPTION_GuardPage, BST_CHECKED);
		if (pHideOptions.handleExceptionWx86Breakpoint) CheckDlgButton(hwnd, ID_EXCEPTION_Wx86Breakpoint, BST_CHECKED);
		if (pHideOptions.handleExceptionRip) CheckDlgButton(hwnd, ID_EXCEPTION_RIP, BST_CHECKED);

		control = CreateWindowExW(0, L"Button", L"Apply", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 1, (numOfExceptions)*20 + 1, 100, 20, hwnd, (HMENU)ID_EXCEPTION_APPLY, hInst, NULL);
		SendMessage(control,WM_SETFONT,(WPARAM)hFont,MAKELPARAM(1,0));
		control = CreateWindowExW(0, L"Button", L"Cancel", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,1, (numOfExceptions+1)*20 + 1, 100, 20, hwnd, (HMENU)ID_EXCEPTION_CANCEL, hInst, NULL);
		SendMessage(control,WM_SETFONT,(WPARAM)hFont,MAKELPARAM(1,0));

		//DeleteObject(hFont);

	}
	else if (msg == WM_COMMAND)
	{
		if (LOWORD(wparam) == ID_EXCEPTION_APPLY)
		{

			ResetAllExceptions();

			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_PRINT) == BST_CHECKED)
			{
				pHideOptions.handleExceptionPrint = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Illegal) == BST_CHECKED)
			{
				pHideOptions.handleExceptionIllegalInstruction = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_InvalidLockSequence) == BST_CHECKED)
			{
				pHideOptions.handleExceptionInvalidLockSequence = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Noncontinable) == BST_CHECKED)
			{
				pHideOptions.handleExceptionNoncontinuableException = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_RIP) == BST_CHECKED)
			{
				pHideOptions.handleExceptionRip = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_GuardPage) == BST_CHECKED)
			{
				pHideOptions.handleExceptionGuardPageViolation = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Breakpoint) == BST_CHECKED)
			{
				pHideOptions.handleExceptionBreakpoint = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_Wx86Breakpoint) == BST_CHECKED)
			{
				pHideOptions.handleExceptionWx86Breakpoint = 1;
			}
			if (IsDlgButtonChecked(hwnd, ID_EXCEPTION_AssertionFailure) == BST_CHECKED)
			{
				pHideOptions.handleExceptionAssertionFailure = 1;
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
	WNDCLASSW wc = {0};
	HWND     wnd;
	MSG      msg;
	//wc.hbrBackground = (HBRUSH)(COLOR_3DFACE + 1);
	wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
	wc.hInstance     = GetModuleHandleW(0);
	wc.style         = CS_PARENTDC | CS_DBLCLKS;
	wc.lpfnWndProc   = ExceptionSettingsWndproc;
	wc.lpszClassName = classname;
	RegisterClassW(&wc);

	int windowHeight = EXCEPTION_WINDOW_BASE_HEIGHT + (_countof(exceptionNamesTooltip)*(HEIGHT_OF_EXCEPTION_CHECKBOX+5) );

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