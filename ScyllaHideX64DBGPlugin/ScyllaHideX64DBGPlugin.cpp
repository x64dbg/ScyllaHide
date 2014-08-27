#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <string>
#include "resource.h"
#include "..\PluginGeneric\ScyllaHideVersion.h"
#include "ScyllaHideX64DBGPlugin.h"
#include "..\PluginGeneric\Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\UpdateCheck.h"
#include "..\PluginGeneric\IniSettings.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"

#define plugin_name "ScyllaHide"

//scyllaHide definitions
struct HideOptions pHideOptions = {0};

#ifdef _WIN64
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};
WCHAR ScyllaHideIniPath[MAX_PATH] = {0};

extern WCHAR CurrentProfile[MAX_SECTION_NAME];
extern WCHAR ProfileNames[2048];
extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;
extern t_AttachProcess _AttachProcess;

//globals
HINSTANCE hinst;
HMODULE hNtdllModule = 0;
bool specialPebFix = false;
int pluginHandle;
HWND hwndDlg;
int hMenu;
DWORD ProcessId = 0;
bool bHooked = false;

DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion= (SCYLLA_HIDE_MAJOR_VERSION * 10) + SCYLLA_HIDE_MINOR_VERSION;
    initStruct->sdkVersion=PLUG_SDKVERSION;
    strcpy(initStruct->pluginName, plugin_name);
    pluginHandle=initStruct->pluginHandle;

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    _plugin_registercallback(pluginHandle, CB_DEBUGEVENT, cbDebugloop);
    _plugin_registercallback(pluginHandle, CB_STOPDEBUG, cbReset);

    if(pHideOptions.killAntiAttach) {
        InstallAntiAttachHook();
    }

    return true;
}

void cbMenuEntry(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_MENUENTRY* info=(PLUG_CB_MENUENTRY*)callbackInfo;
    switch(info->hEntry)
    {
    case MENU_OPTIONS:
    {
        GetPrivateProfileSectionNamesWithFilter();
        DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwndDlg, &OptionsProc);
        break;
    }
    case MENU_INJECTDLL:
    {
        if(ProcessId) {
            wchar_t dllPath[MAX_PATH] = {};
            if(GetFileDialog(dllPath))
                injectDll(ProcessId, dllPath);
        }
        break;
    }
    case MENU_ATTACH:
    {
        DialogBox(hinst, MAKEINTRESOURCE(IDD_ATTACH), hwndDlg, &AttachProc);
        break;
    }
    case MENU_UPDATECHECK:
    {
        if(isNewVersionAvailable()) {
            MessageBoxA(hwndDlg,
                        "There is a new version of ScyllaHide available !\n\n"
                        "Check out https://bitbucket.org/NtQuery/scyllahide/downloads \n"
                        "or some RCE forums !",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
        }
        else {
            MessageBoxA(hwndDlg,
                        "You already have the latest version of ScyllaHide !",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
        }
        break;
    }
    case MENU_ABOUT:
    {
        ShowAbout(hwndDlg);

        break;
    }
    //profile names/count is dynamic so we catch loading them with default case
    default: {
        SetCurrentProfile(info->hEntry);
        ReadSettings();

        if (ProcessId)
        {
            startInjection(ProcessId, ScyllaHideDllPath, true);
            bHooked = true;
            MessageBoxA(hwndDlg, "Applied changes! Restarting target is NOT necessary!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxA(hwndDlg, "Please start the target to apply changes!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
        }
        break;
    }
    }
}

DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg=setupStruct->hwndDlg;
    hMenu=setupStruct->hMenu;

    ReadCurrentProfile();
    ReadSettings();

    _plugin_logprintf("ScyllaHide Plugin v"SCYLLA_HIDE_VERSION_STRING_A"\n");
    _plugin_logprintf("  Copyright (C) 2014 Aguila / cypher\n");

    _plugin_menuaddentry(hMenu, MENU_OPTIONS, "&Options");
    int hProfile = _plugin_menuadd(hMenu, "&Load Profile");

    //add profiles to menu
    GetPrivateProfileSectionNamesWithFilter();

    WCHAR* profile = ProfileNames;
    char buf[MAX_SECTION_NAME+1];
    int i=10;
    while(*profile != 0x00 && i<MAX_PROFILES-1) {
        wcstombs(buf, profile, MAX_SECTION_NAME);
        _plugin_menuaddentry(hProfile, i,buf);
        i++;
        profile = profile + wcslen(profile) + 1;
    }

    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_INJECTDLL, "&Inject DLL");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_ATTACH, "&Attach process");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_UPDATECHECK, "&Update-Check");
    _plugin_menuaddentry(hMenu, MENU_ABOUT, "&About");
}

void cbDebugloop(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_DEBUGEVENT* d = (PLUG_CB_DEBUGEVENT*)callbackInfo;

    if (pHideOptions.PEBHeapFlags)
    {
        if (specialPebFix)
        {
            StartFixBeingDebugged(ProcessId, false);
            specialPebFix = false;
        }

        if (d->DebugEvent->u.LoadDll.lpBaseOfDll == hNtdllModule)
        {
            StartFixBeingDebugged(ProcessId, true);
            specialPebFix = true;
        }
    }

    //char text[1000];
    //wsprintfA(text, "dwDebugEventCode %X dwProcessId %X dwThreadId %X ExceptionCode %X ExceptionFlags %X",d->DebugEvent->dwDebugEventCode, d->DebugEvent->dwProcessId, d->DebugEvent->dwThreadId, d->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode,d->DebugEvent->u.Exception.ExceptionRecord.ExceptionFlags);
    //MessageBoxA(0,text,text,0);

    switch(d->DebugEvent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        ProcessId = d->DebugEvent->dwProcessId;
        bHooked = false;
        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
        break;
    }
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
        switch(d->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (!bHooked)
            {
                _plugin_logprintf("[ScyllaHide] Reading NT API Information %S\n", NtApiIniPath);
                ReadNtApiInformation();

                bHooked = true;
                startInjection(ProcessId, ScyllaHideDllPath, true);
            }

            break;
        }

        }

        break;
    }
    }

}

void cbReset(CBTYPE cbType, void* callbackInfo)
{
    ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
    bHooked = false;
    ProcessId = 0;
}

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason==DLL_PROCESS_ATTACH)
    {
        _AttachProcess = AttachProcess;
        LogWrap = LogWrapper;
        LogErrorWrap = LogErrorWrapper;

        hNtdllModule = GetModuleHandleW(L"ntdll.dll");
        GetModuleFileNameW(hinstDLL, NtApiIniPath, _countof(NtApiIniPath));
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

        hinst=hinstDLL;
    }

    return TRUE;
}

void LogErrorWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

    _plugin_logprintf("%s\n",textA);
}

void LogWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

    _plugin_logprintf("%s\n",textA);
}

void AttachProcess(DWORD dwPID)
{
	char cmd[30] = {0};
    wsprintfA(cmd, "attach %x", dwPID);
    if (!DbgCmdExec(cmd))
	{
		MessageBoxW(hwndDlg,
			L"Can't attach to that process !",
			L"ScyllaHide Plugin",MB_OK|MB_ICONERROR);
	}
}