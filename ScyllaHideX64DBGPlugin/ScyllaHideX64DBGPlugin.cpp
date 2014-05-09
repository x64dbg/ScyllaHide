#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "resource.h"
#include "..\PluginGeneric\ScyllaHideVersion.h"
#include "ScyllaHideX64DBGPlugin.h"
#include "..\PluginGeneric\Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\UpdateCheck.h"
#include "..\PluginGeneric\IniSettings.h"
#include "..\PluginGeneric\OptionsDialog.h"

#define plugin_name "ScyllaHide"
#define plugin_version 001

//scyllaHide definitions
struct HideOptions pHideOptions = {0};

const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
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

//globals
static HINSTANCE hinst;

HMODULE hNtdllModule = 0;
int pluginHandle;
HWND hwndDlg;
int hMenu;
DWORD ProcessId = 0;
bool bHooked = false;

DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion=plugin_version;
    initStruct->sdkVersion=PLUG_SDKVERSION;
    strcpy(initStruct->pluginName, plugin_name);
    pluginHandle=initStruct->pluginHandle;

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);

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
    default: {
        break;
    }
    }
}

DLL_EXPORT bool plugstop()
{

    return true;
}

DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg=setupStruct->hwndDlg;
    hMenu=setupStruct->hMenu;

    ReadCurrentProfile();
    ReadSettings();

    _plugin_logprintf("ScyllaHide Plugin v"SCYLLA_HIDE_VERSION_STRING_A"\n");
    _plugin_logprintf("  Copyright (C) 2014 Aguila / cypher");

    _plugin_menuaddentry(hMenu, MENU_OPTIONS, "&Options");
    int hProfile = _plugin_menuadd(hMenu, "&Load Profile");
    _plugin_menuaddentry(hProfile, MENU_PROFILES, "test");
    //_plugin_menuaddentry(hMenu, MENU_TEST, "&Menu Test");
    //_plugin_menuaddentry(hMenu, MENU_SELECTION, "&Selection API Test");
}

extern "C" DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason==DLL_PROCESS_ATTACH)
    {
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

    _plugin_logprintf("&s",textA);
}

void LogWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

    _plugin_logprintf("&s",textA);
}