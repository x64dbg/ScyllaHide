#include <windows.h>
#include <titan/TitanEngine.h>
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\Injector.h"
#include "..\PluginGeneric\ScyllaHideVersion.h"
#include "..\PluginGeneric\IniSettings.h"

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
void LogWrapper(const WCHAR * format, ...);


struct HideOptions pHideOptions = {0};

#ifdef _WIN64
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};
WCHAR ScyllaHideIniPath[MAX_PATH] = {0};

bool bHooked;
DWORD ProcessId;

bool SetDebugPrivileges();

BOOL WINAPI DllMain(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        LogWrap = LogWrapper;
        LogErrorWrap = LogWrapper;

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
            wcscat(NtApiIniPath, NtApiIniFilename);

            ReadCurrentProfile();
            ReadSettings();

            SetDebugPrivileges(); //set debug privilege
        }
    }
    return TRUE;
}

void LogWrapper(const WCHAR * format, ...)
{
    //WCHAR text[2000];
    //va_list va_alist;
    //va_start(va_alist, format);

    //wvsprintfW(text, format, va_alist);

    //Message(0, text);
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

extern "C" __declspec(dllexport) void TitanDebuggingCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
{
    switch(CallReason)
    {
    case UE_PLUGIN_CALL_REASON_EXCEPTION:
    {
        switch(debugEvent->dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            ProcessId=debugEvent->dwProcessId;
            bHooked = false;
            ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
            ReadSettings();
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
            switch(debugEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case STATUS_BREAKPOINT:
            {
                if (!bHooked)
                {
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
    break;
    }
}

extern "C" __declspec(dllexport) bool TitanRegisterPlugin(char* szPluginName, DWORD* titanPluginMajorVersion, DWORD* titanPluginMinorVersion)
{
    if(titanPluginMajorVersion && titanPluginMinorVersion)
    {
        *titanPluginMajorVersion = SCYLLA_HIDE_MAJOR_VERSION;
        *titanPluginMinorVersion = SCYLLA_HIDE_MINOR_VERSION;
        strcpy(szPluginName, "ScyllaHide");
        return true;
    }
    return false;
}
