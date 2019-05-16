#include <codecvt>
#include <Scylla/Logger.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>
#include <Scylla/Version.h>
#include <x64dbg/_plugins.h>

#include "..\PluginGeneric\Injector.h"
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

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif

typedef void(__cdecl * t_AttachProcess)(DWORD dwPID);

enum ScyllaMenuItems : int {
    MENU_OPTIONS = 0,
    MENU_PROFILES,
    MENU_INJECTDLL,
    MENU_ATTACH,
    MENU_ABOUT,
    MENU_MAX
};

extern t_AttachProcess _AttachProcess;

#ifdef _WIN64
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

scl::Settings g_settings;
scl::Logger g_log;
std::wstring g_scyllaHideDllPath;
std::wstring g_scyllaHideIniPath;

HOOK_DLL_DATA g_hdd = { 0 };

HINSTANCE hinst;
HMODULE hNtdllModule = 0;
bool specialPebFix = false;
int pluginHandle;
HWND hwndDlg;
int hMenu;
DWORD ProcessId = 0;
bool bHooked = false;
ICONDATA mainIconData = { 0 };

static void LogCallback(const char *msg)
{
    _plugin_logprintf("[%s] %s\n", SCYLLA_HIDE_NAME_A, msg);
}

static void AttachProcess(DWORD dwPID)
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

static void cbMenuEntry(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)callbackInfo;
    switch (info->hEntry)
    {
    case MENU_OPTIONS:
    {
        DialogBoxW(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwndDlg, &OptionsDlgProc);
        break;
    }
    case MENU_INJECTDLL:
    {
        if (ProcessId) {
            wchar_t dllPath[MAX_PATH] = {};
            if (scl::GetFileDialogW(dllPath, _countof(dllPath)))
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
        scl::ShowAboutBox(hwndDlg);

        break;
    }
    default: {
        auto profile_name = g_settings.profile_names()[info->hEntry - MENU_MAX].c_str();
        g_settings.SetProfile(profile_name);

        if (ProcessId)
        {
            startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
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

static void cbDebugloop(CBTYPE cbType, void* callbackInfo)
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

    switch (d->DebugEvent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        ProcessId = d->DebugEvent->dwProcessId;
        bHooked = false;
        ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));

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
            startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), false);
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
                ReadNtApiInformation(&g_hdd);

                bHooked = true;
                startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
            }

            break;
        }

        }

        break;
    }
    }
}

static void cbReset(CBTYPE cbType, void* callbackInfo)
{
    ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));
    bHooked = false;
    ProcessId = 0;
}

extern "C" DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = (SCYLLA_HIDE_VERSION_MAJOR * 100) + (SCYLLA_HIDE_VERSION_MINOR * 10) + SCYLLA_HIDE_VERSION_PATCH;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), SCYLLA_HIDE_NAME_A, _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    _plugin_registercallback(pluginHandle, CB_DEBUGEVENT, cbDebugloop);
    _plugin_registercallback(pluginHandle, CB_STOPDEBUG, cbReset);

    return true;
}

extern "C" DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;

    g_settings.Load(g_scyllaHideIniPath.c_str());

    _plugin_logprintf("%s Plugin v%s Copyright (C) 2014 Aguila / cypher\n", SCYLLA_HIDE_NAME_A, SCYLLA_HIDE_VERSION_STRING_A);

    _plugin_menuaddentry(hMenu, MENU_OPTIONS, "&Options");
    int hProfile = _plugin_menuadd(hMenu, "&Load Profile");

    //add profiles to menu
    for (size_t i = 0; i < g_settings.profile_names().size(); i++)
    {
        auto mbstrName = scl::wstr_conv().to_bytes(g_settings.profile_names()[i].c_str());
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

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        hinst = hInstDLL;
        _AttachProcess = AttachProcess;
        hNtdllModule = GetModuleHandleW(L"ntdll.dll");

        auto wstrPath = scl::GetModuleFileNameW(hInstDLL);
        wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);

        g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
        g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;

        auto log_file = wstrPath + scl::Logger::kFileName;
        g_log.SetLogFile(log_file.c_str());
        g_log.SetLogCb(scl::Logger::Info, LogCallback);
        g_log.SetLogCb(scl::Logger::Error, LogCallback);
    }

    return TRUE;
}
