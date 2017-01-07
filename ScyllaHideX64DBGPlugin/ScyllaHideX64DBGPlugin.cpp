#include "ScyllaHideX64DBGPlugin.h"
#include <codecvt>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Version.h>

#include "..\PluginGeneric\Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"

#include "resource.h"

#ifdef _WIN64
#pragma comment(lib, "x64dbg\\x64dbg.lib")
#pragma comment(lib, "x64dbg\\x64bridge.lib")
#else
#pragma comment(lib, "x64dbg\\x32dbg.lib")
#pragma comment(lib, "x64dbg\\x32bridge.lib")
#endif

enum ScyllaMenuItems : int {
    MENU_OPTIONS = 0,
    MENU_PROFILES,
    MENU_INJECTDLL,
    MENU_ATTACH,
    MENU_ABOUT,
    MENU_MAX
};

scl::Settings g_settings;

#ifdef _WIN64
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = { 0 };
WCHAR NtApiIniPath[MAX_PATH] = { 0 };
WCHAR ScyllaHideIniPath[MAX_PATH] = { 0 };

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;
extern t_AttachProcess _AttachProcess;

HINSTANCE hinst;
HMODULE hNtdllModule = 0;
bool specialPebFix = false;
int pluginHandle;
HWND hwndDlg;
int hMenu;
DWORD ProcessId = 0;
bool bHooked = false;
ICONDATA mainIconData = { 0 };

DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = (SCYLLA_HIDE_VERSION_MAJOR * 100) + (SCYLLA_HIDE_VERSION_MINOR * 10) + SCYLLA_HIDE_VERSION_PATCH;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy(initStruct->pluginName, SCYLLA_HIDE_NAME_A, sizeof(initStruct->pluginName));
    pluginHandle = initStruct->pluginHandle;

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    _plugin_registercallback(pluginHandle, CB_DEBUGEVENT, cbDebugloop);
    _plugin_registercallback(pluginHandle, CB_STOPDEBUG, cbReset);

    return true;
}

void cbMenuEntry(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)callbackInfo;
    switch (info->hEntry)
    {
    case MENU_OPTIONS:
    {
        DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwndDlg, &OptionsProc);
        break;
    }
    case MENU_INJECTDLL:
    {
        if (ProcessId) {
            wchar_t dllPath[MAX_PATH] = {};
            if (GetFileDialog(dllPath))
                injectDll(ProcessId, dllPath);
        }
        break;
    }
    case MENU_ATTACH:
    {
        DialogBox(hinst, MAKEINTRESOURCE(IDD_ATTACH), hwndDlg, &AttachProc);
        break;
    }
    case MENU_ABOUT:
    {
        ShowAbout(hwndDlg);

        break;
    }
    default: {
        auto profile_name = g_settings.profile_names()[info->hEntry - MENU_MAX].c_str();
        g_settings.SetProfile(profile_name);

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
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;

    g_settings.Load(ScyllaHideIniPath);

    _plugin_logprintf("%s Plugin v%s Copyright (C) 2014 Aguila / cypher\n", SCYLLA_HIDE_NAME_A, SCYLLA_HIDE_VERSION_STRING_A);

    _plugin_menuaddentry(hMenu, MENU_OPTIONS, "&Options");
    int hProfile = _plugin_menuadd(hMenu, "&Load Profile");

    //add profiles to menu
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wstr2str;
    for (size_t i = 0; i < g_settings.profile_names().size(); i++)
    {
        auto mbstrName = wstr2str.to_bytes(g_settings.profile_names()[i].c_str());
        _plugin_menuaddentry(hProfile, (int)i + MENU_MAX, mbstrName.c_str());
    }

    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_INJECTDLL, "&Inject DLL");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_ATTACH, "&Attach process");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_ABOUT, "&About");

    //load png

    HRSRC hResPng = FindResourceW(hinst, MAKEINTRESOURCEW(IDB_GHOSTPNG), L"PNG");
    if (hResPng != NULL)
    {
        HGLOBAL hResLoad = LoadResource(hinst, hResPng);
        if (hResLoad != NULL)
        {
            mainIconData.data = LockResource(hResLoad);
            mainIconData.size = SizeofResource(hinst, hResPng);

            if (mainIconData.data != NULL && mainIconData.size != 0)
            {
                _plugin_menuseticon(hMenu, (const ICONDATA *)&mainIconData);
            }
            else
            {
                _plugin_logprintf("Warning: Cannot lock ScyllaHide icon! LockResource, SizeofResource\n");
            }
        }
        else
        {
            _plugin_logprintf("Warning: Cannot load ScyllaHide icon! LoadResource\n");
        }
    }
    else
    {
        _plugin_logprintf("Warning: Cannot find ScyllaHide icon! FindResourceW\n");
    }
}

void cbDebugloop(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_DEBUGEVENT* d = (PLUG_CB_DEBUGEVENT*)callbackInfo;

    if (g_settings.opts().fixPebHeapFlags)
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

    switch (d->DebugEvent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        ProcessId = d->DebugEvent->dwProcessId;
        bHooked = false;
        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

        if (d->DebugEvent->u.CreateProcessInfo.lpStartAddress == NULL)
        {
            //ATTACH
            if (g_settings.opts().killAntiAttach)
            {
                if (!ApplyAntiAntiAttach(ProcessId))
                {
                    MessageBoxW(hwndDlg, L"Anti-Anti-Attach failed", L"Error", MB_ICONERROR);
                }
            }
        }

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
        switch (d->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (!bHooked)
            {
                _plugin_logprintf("[ScyllaHide] Reading NT API Information %S\n", NtApiIniPath);
                ReadNtApiInformation(NtApiIniPath, &DllExchangeLoader);

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
    if (fdwReason == DLL_PROCESS_ATTACH)
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
            wcscat(ScyllaHideIniPath, scl::Settings::kFileName);
            wcscat(NtApiIniPath, NtApiIniFilename);
        }

        hinst = hinstDLL;
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

    WideCharToMultiByte(CP_ACP, 0, text, -1, textA, _countof(textA), 0, 0);

    _plugin_logprintf("%s\n", textA);
}

void LogWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP, 0, text, -1, textA, _countof(textA), 0, 0);

    _plugin_logprintf("%s\n", textA);
}

void AttachProcess(DWORD dwPID)
{
    char cmd[30] = { 0 };
    wsprintfA(cmd, "attach %x", dwPID);
    if (!DbgCmdExec(cmd))
    {
        MessageBoxW(hwndDlg,
            L"Can't attach to that process !",
            L"ScyllaHide Plugin", MB_OK | MB_ICONERROR);
    }
}
