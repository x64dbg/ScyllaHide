#include <windows.h>
#include <string>
#include <unordered_map>
#include "ScyllaHideGenericPlugin.h"
#include "..\PluginGeneric\ScyllaHideVersion.h"
#include "..\PluginGeneric\Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\UpdateCheck.h"
#include "..\PluginGeneric\IniSettings.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"
#include "..\InjectorCLI\OperatingSysInfo.h"

typedef void(__cdecl * t_LogWrapper)(const WCHAR * format, ...);
typedef void(__cdecl * t_AttachProcess)(DWORD dwPID);

//scyllaHide definitions
struct HideOptions pHideOptions = { 0 };

#ifdef _WIN64
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = { 0 };
WCHAR NtApiIniPath[MAX_PATH] = { 0 };
WCHAR ScyllaHideIniPath[MAX_PATH] = { 0 };

extern WCHAR CurrentProfile[MAX_SECTION_NAME];
extern WCHAR ProfileNames[2048];
extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;

//globals
static HMODULE hNtdllModule = 0;

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

static std::unordered_map<DWORD, HookStatus> hookStatusMap;

DLL_EXPORT void ScyllaHideDebugLoop(const DEBUG_EVENT* DebugEvent)
{
    auto pid = DebugEvent->dwProcessId;
    auto status = HookStatus();
    auto found = hookStatusMap.find(pid);
    if (found == hookStatusMap.end())
        hookStatusMap[pid] = status;
    else
        status = hookStatusMap[pid];

    if (pHideOptions.PEBHeapFlags)
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
        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

        if (DebugEvent->u.CreateProcessInfo.lpStartAddress == NULL)
        {
            //ATTACH
            if (pHideOptions.killAntiAttach)
            {
                if (!ApplyAntiAntiAttach(status.ProcessId))
                {
                    LogWrap(L"Anti-Anti-Attach failed");
                }
            }
        }

        break;
    }

    case LOAD_DLL_DEBUG_EVENT:
    {
        if (status.bHooked)
        {
            startInjection(status.ProcessId, ScyllaHideDllPath, false);
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
                LogWrap(L"[ScyllaHide] Reading NT API Information %s", NtApiIniPath);
                ReadNtApiInformation();

                status.bHooked = true;
                startInjection(status.ProcessId, ScyllaHideDllPath, true);
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
    ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
    hookStatusMap.clear();
}

static void LogErrorWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP, 0, text, -1, textA, _countof(textA), 0, 0);

    printf("%s\n", textA);
}

static void LogWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    CHAR textA[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    WideCharToMultiByte(CP_ACP, 0, text, -1, textA, _countof(textA), 0, 0);

    printf("%s\n", textA);
}

DLL_EXPORT void ScyllaHideInit(const WCHAR* Directory, LOGWRAPPER Logger, LOGWRAPPER ErrorLogger)
{
    //Set log functions
    if (!Logger)
        LogWrap = LogWrapper;
    else
        LogWrap = Logger;
    if (!ErrorLogger)
        LogErrorWrap = LogErrorWrapper;
    else
        LogErrorWrap = ErrorLogger;
    
    //Load paths
    hNtdllModule = GetModuleHandleW(L"ntdll.dll");
    if (!Directory)
        GetModuleFileNameW(GetModuleHandleA(0), NtApiIniPath, _countof(NtApiIniPath));
    else
    {
        wcscpy_s(NtApiIniPath, Directory);
        if (NtApiIniPath[wcslen(NtApiIniPath) - 1] != L'\\')
            wcscat_s(NtApiIniPath, L"\\");
    }
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

    //Read settings file
    ReadCurrentProfile();
    ReadSettings();
}
