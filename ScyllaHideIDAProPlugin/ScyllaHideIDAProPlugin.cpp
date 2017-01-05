#define USE_STANDARD_FILE_FUNCTIONS
#pragma warning(disable : 4996 4512 4127 4201)

//also switch this in OptionsDialog.cpp !
//#define BUILD_IDA_64BIT 1

//for 64bit - p64
#ifdef BUILD_IDA_64BIT
#define __EA64__
#pragma comment(lib, "idasdk/x86_win_vc_64/ida.lib")
#else
//for 32bit - plw
#pragma comment(lib, "idasdk/x86_win_vc_32/ida.lib")
#endif

#include <Windows.h>
#include <idasdk/ida.hpp>
#include <idasdk/idp.hpp>
#include <idasdk/dbg.hpp>
#include <idasdk/loader.hpp>
#include <idasdk/kernwin.hpp>
#include <Scylla/Settings.h>
#include <Scylla/Version.h>

#include "..\PluginGeneric\Injector.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "IdaServerClient.h"
#include "resource.h"

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
typedef void (__cdecl * t_AttachProcess)(DWORD dwPID);
void LogWrapper(const WCHAR * format, ...);
void LogErrorWrapper(const WCHAR * format, ...);
void __cdecl AttachProcess(DWORD dwPID);
int idaapi debug_mainloop(void *user_data, int notif_code, va_list va);
bool SetDebugPrivileges();

std::vector<std::wstring> g_hideProfileNames;
std::wstring g_hideProfileName;
Scylla::HideSettings g_hideSettings;

const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
const WCHAR ScyllaHidex64ServerFilename[] = L"ScyllaHideIDASrvx64.exe";

WCHAR ScyllaHideIniPath[MAX_PATH] = { 0 };
WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};
WCHAR ScyllaHidex64ServerPath[MAX_PATH] = {0};

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;
extern t_AttachProcess _AttachProcess;

//globals
HINSTANCE hinst;
DWORD ProcessId = 0;
bool bHooked = false;
HMODULE hNtdllModule = 0;
PROCESS_INFORMATION ServerProcessInfo = {0};
STARTUPINFO ServerStartupInfo = {0};

BOOL FileExists(LPCWSTR szPath);

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{
    if (reason==DLL_PROCESS_ATTACH)
    {
        _AttachProcess = AttachProcess;
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
            wcscpy(ScyllaHidex64ServerPath, NtApiIniPath);
            wcscat(ScyllaHidex64ServerPath, ScyllaHidex64ServerFilename);
            wcscat(NtApiIniPath, NtApiIniFilename);
        }

        SetDebugPrivileges();

        g_hideProfileName = Scylla::LoadHideProfileName(ScyllaHideIniPath);
        Scylla::LoadHideProfileSettings(ScyllaHideIniPath, g_hideProfileName.c_str(), &g_hideSettings);

        if (!StartWinsock())
        {
            MessageBoxA(0,"Failed to start Winsock!", "Error", MB_ICONERROR);
        }

        hinst=hi;
    }

    return TRUE;
};

//init the plugin
int idaapi IDAP_init(void)
{
    //ensure target is PE executable
    if (inf.filetype != f_PE) return PLUGIN_SKIP;

    //install hook for debug mainloop
    if (!hook_to_notification_point(HT_DBG, debug_mainloop, NULL))
    {
        msg("[ScyllaHide] Error hooking notification point\n");
        return PLUGIN_SKIP;
    }

    msg("##################################################\n");
    msg("# ScyllaHide v" SCYLLA_HIDE_VERSION_STRING_A " Copyright 2014 Aguila / cypher #\n");
    msg("##################################################\n");

    bHooked = false;
    ProcessId = 0;
    ZeroMemory(&ServerStartupInfo, sizeof(ServerStartupInfo));
    ZeroMemory(&ServerProcessInfo, sizeof(ServerProcessInfo));

    //read profile names
    g_hideProfileNames = Scylla::LoadHideProfileNames(ScyllaHideIniPath);

    return PLUGIN_KEEP;
}

//cleanup on plugin unload
void idaapi IDAP_term(void)
{
    unhook_from_notification_point(HT_DBG, debug_mainloop, NULL);

    return;
}

//called when user clicks in plugin menu or presses hotkey
void idaapi IDAP_run(int arg)
{
    DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), (HWND)callui(ui_get_hwnd).vptr, &OptionsProc);

    return;
}

bool isAttach = false;

//callback for various debug events
int idaapi debug_mainloop(void *user_data, int notif_code, va_list va)
{
    switch (notif_code)
    {
    case dbg_process_attach:
		{
			isAttach = true;
			break; //attaching not supported
		}
    case dbg_process_start:
    {
		isAttach = false;

        const debug_event_t* dbgEvent = va_arg(va, const debug_event_t*);

        ProcessId = dbgEvent->pid;
        bHooked = false;
        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

        if (dbg != 0)
        {
            //char text[1000];
            //wsprintfA(text, "dbg->id %d processor %s", dbg->id , dbg->processor);
            //MessageBoxA(0, text, text,0);
            // dbg->id DEBUGGER_ID_WINDBG -> 64bit and 32bit
            // dbg->id DEBUGGER_ID_X86_IA32_WIN32_USER -> 32bit

            if (dbg->is_remote())
            {
                qstring hoststring;
                char host[200] = {0};
                char port[6] = {0};
                wcstombs(port, g_hideSettings.serverPort.c_str(), _countof(port));

                get_process_options(NULL, NULL, NULL, &hoststring, NULL, NULL);
                GetHost((char*)hoststring.c_str(), host);

                //msg("Host-String: %s\n", hoststring.c_str());
                //msg("Host: %s\n", host);

#ifdef BUILD_IDA_64BIT
                //autostart server if necessary
                if(pHideOptions.autostartServer)
                {
                    if (!FileExists(ScyllaHidex64ServerPath))
                    {
                        msg("Cannot find server executable %S\n", ScyllaHidex64ServerPath);
                    }

                    DWORD dwRunningStatus = 0;
                    if (ServerProcessInfo.hProcess)
                    {
                        GetExitCodeProcess(ServerProcessInfo.hProcess, &dwRunningStatus);
                    }

                    if(dwRunningStatus != STILL_ACTIVE)
                    {
                        if (ServerProcessInfo.hProcess)
                        {
                            CloseHandle(ServerProcessInfo.hProcess);
                            CloseHandle(ServerProcessInfo.hThread);
                        }

                        ZeroMemory(&ServerStartupInfo, sizeof(ServerStartupInfo));
                        ZeroMemory(&ServerProcessInfo, sizeof(ServerProcessInfo));

                        WCHAR commandline[MAX_PATH*2] = {0};
                        wcscpy(commandline, ScyllaHidex64ServerPath);
                        wcscat(commandline, L" ");
                        wcscat(commandline, pHideOptions.serverPort);
                        ServerStartupInfo.cb = sizeof(ServerStartupInfo);
                        if (!CreateProcessW(0, commandline, NULL, NULL, FALSE, 0, NULL, NULL, &ServerStartupInfo, &ServerProcessInfo))
                        {
                            msg("[ScyllaHide] Cannot start server, error %d\n", GetLastError());
                        }
                        else
                        {
                            msg("[ScyllaHide] Started IDA Server successfully\n");
                        }
                    }
                }
#endif
                if (ConnectToServer(host, port))
                {
                    if (!SendEventToServer(notif_code, ProcessId))
                    {
                        msg("[ScyllaHide] SendEventToServer failed\n");
                    }
                }
                else
                {
                    msg("[ScyllaHide] Cannot connect to host %s\n", host);
                }
            }
            else
            {

#ifndef BUILD_IDA_64BIT
                if (!bHooked)
                {
                    bHooked = true;
                    startInjection(ProcessId, ScyllaHideDllPath, true);
                }
#else
				msg("[ScyllaHide] Error IDA_64BIT please contact ScyllaHide developers!\n");
#endif
            }
        }
    }
    break;

    case dbg_process_exit:
    {
        if (!isAttach && dbg->is_remote())
        {
            if (!SendEventToServer(notif_code, ProcessId))
            {
                msg("[ScyllaHide] SendEventToServer failed\n");
            }

            CloseServerSocket();
        }
        ProcessId = 0;
        bHooked = false;
    }
    break;

    case dbg_library_load:
    {

        if (!isAttach && dbg->is_remote())
        {
            if (!SendEventToServer(notif_code, ProcessId))
            {
                msg("[ScyllaHide] SendEventToServer failed\n");
            }
        }
        else if (!isAttach)
        {
#ifndef BUILD_IDA_64BIT
            if (bHooked)
            {
                startInjection(ProcessId, ScyllaHideDllPath, false);
            }
#endif
        }

    }
    break;

    case dbg_bpt:
    {
        thid_t tid = va_arg(va, thid_t);
        ea_t breakpoint_ea = va_arg(va, ea_t);
        va_arg(va, int*);
    }
    break;

    case dbg_exception:
    {
        const debug_event_t* dbgEvent = va_arg(va, const debug_event_t*);

    }
    break;
    }

    return 0;
}

bool SetDebugPrivileges()
{
    TOKEN_PRIVILEGES Debug_Privileges;
    bool retVal = false;

    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
    {
        HANDLE hToken = 0;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            Debug_Privileges.PrivilegeCount = 1;

            retVal = AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL) != FALSE;

            CloseHandle(hToken);
        }
    }

    return retVal;
}

void LogErrorWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

    msg(textA);
    msg("\n");
}

void LogWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP,0,text,-1,textA, _countof(textA), 0,0);

    msg("%s",textA);
    msg("\n");
}

void AttachProcess(DWORD dwPID)
{
    int res = attach_process((pid_t)dwPID);

    switch(res) {
    case -1:
    {
        MessageBoxA((HWND)callui(ui_get_hwnd).vptr,
                    "Can't attach to that process !",
                    "ScyllaHide Plugin",MB_OK|MB_ICONERROR);
        break;
    }
    case -2:
    {
        MessageBoxA((HWND)callui(ui_get_hwnd).vptr,
                    "Can't find that PID !",
                    "ScyllaHide Plugin",MB_OK|MB_ICONERROR);
        break;
    }
    }
}

// There isn't much use for these yet, but I set them anyway.
static char IDAP_comment[] 	= "ScyllaHide usermode Anti-Anti-Debug Plugin";
static char IDAP_help[] 		= "ScyllaHide";

// The name of the plug-in displayed in the Edit->Plugins menu
static char IDAP_name[] 		= "ScyllaHide";

// The hot-key the user can use to run your plug-in.
static char IDAP_hotkey[] 	= "Alt-X";

// The all-important exported PLUGIN object
idaman ida_module_data plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    0,
    IDAP_init,
    IDAP_term,
    IDAP_run,
    IDAP_comment,
    IDAP_help,
    IDAP_name,
    IDAP_hotkey
};
