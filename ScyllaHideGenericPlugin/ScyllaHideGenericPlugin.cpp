#include "ScyllaHideGenericPlugin.h"
#include <string>
#include <unordered_map>
#include <Scylla/Logger.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>

#include "..\PluginGeneric\Injector.h"

struct HookStatus
{
    HookStatus()
        : ProcessId(0),
        bHooked(false),
        specialPebFix(false)
    {
    }

    DWORD ProcessId;
    bool bHooked;
    bool specialPebFix;
};

typedef void(__cdecl * t_AttachProcess)(DWORD dwPID);

#ifdef _WIN64
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

scl::Settings g_settings;
scl::Logger g_log;
std::wstring g_scyllaHideDllPath;
std::wstring g_scyllaHideIniPath;

HOOK_DLL_DATA g_hdd;

//globals
static HMODULE hNtdllModule = 0;
static std::unordered_map<DWORD, HookStatus> hookStatusMap;

static void LogCallback(const wchar_t *msg)
{
    _putws(msg);
}

DLL_EXPORT void ScyllaHideDebugLoop(const DEBUG_EVENT* DebugEvent)
{
    auto pid = DebugEvent->dwProcessId;
    auto status = HookStatus();
    auto found = hookStatusMap.find(pid);
    if (found == hookStatusMap.end())
        hookStatusMap[pid] = status;
    else
        status = hookStatusMap[pid];

    if (g_settings.opts().fixPebHeapFlags)
    {
        if (status.specialPebFix)
        {
            StartFixBeingDebugged(status.ProcessId, false);
            status.specialPebFix = false;
        }

        if (DebugEvent->u.LoadDll.lpBaseOfDll == hNtdllModule)
        {
            StartFixBeingDebugged(status.ProcessId, true);
            status.specialPebFix = true;
        }
    }

    switch (DebugEvent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        status.ProcessId = DebugEvent->dwProcessId;
        status.bHooked = false;
        ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));

        if (DebugEvent->u.CreateProcessInfo.lpStartAddress == NULL)
        {
            //ATTACH
            if (g_settings.opts().killAntiAttach)
            {
                if (!ApplyAntiAntiAttach(status.ProcessId))
                {
                    g_log.LogError(L"Anti-Anti-Attach failed");
                }
            }
        }

        break;
    }

    case LOAD_DLL_DEBUG_EVENT:
    {
        if (status.bHooked)
        {
            startInjection(status.ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), false);
        }

        break;
    }

    case EXCEPTION_DEBUG_EVENT:
    {
        switch (DebugEvent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (!status.bHooked)
            {
                ReadNtApiInformation(&g_hdd);

                status.bHooked = true;
                startInjection(status.ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
            }

            break;
        }
        }

        break;
    }
    }

    hookStatusMap[pid] = status;
}

DLL_EXPORT void ScyllaHideReset()
{
    ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));
    hookStatusMap.clear();
}

DLL_EXPORT void ScyllaHideInit(const WCHAR* Directory, LOGWRAPPER Logger, LOGWRAPPER ErrorLogger)
{
    hNtdllModule = GetModuleHandleW(L"ntdll.dll");

    std::wstring wstrPath;

    if (Directory)
    {
        wstrPath = Directory;
        if (wstrPath.back() != L'\\')
            wstrPath += L'\\';
    } else
    {
        wstrPath = scl::GetModuleFileNameW();
        wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);
    }

    g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
    g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;

    auto log_file = wstrPath + scl::Logger::kFileName;
    g_log.SetLogFile(log_file.c_str());

    auto log_cb = Logger ? Logger : LogCallback;
    auto log_err_cb = ErrorLogger ? ErrorLogger : LogCallback;
    g_log.SetLogCb(scl::Logger::Info, log_cb);
    g_log.SetLogCb(scl::Logger::Error, log_err_cb);

    g_settings.Load(g_scyllaHideIniPath.c_str());
}
