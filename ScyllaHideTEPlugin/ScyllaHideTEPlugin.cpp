#include <Windows.h>
#include <titan/TitanEngine.h>
#include <Scylla/NtApiLoader.h>
#include <Scylla/Settings.h>
#include <Scylla/Version.h>
#include <Scylla/Util.h>

#include "..\PluginGeneric\Injector.h"

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);
void LogWrapper(const WCHAR * format, ...);

scl::Settings g_settings;

#ifdef _WIN64
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;

std::wstring g_scyllaHideDllPath;
std::wstring g_ntApiCollectionIniPath;
std::wstring g_scyllaHideIniPath;

bool bHooked;
DWORD ProcessId;

bool SetDebugPrivileges();

BOOL WINAPI DllMain(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        LogWrap = LogWrapper;
        LogErrorWrap = LogWrapper;

        auto wstrPath = scl::GetModuleFileNameW(hi);
        wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);

        g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
        g_ntApiCollectionIniPath = wstrPath + scl::NtApiLoader::kFileName;
        g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;

        g_settings.Load(g_scyllaHideIniPath.c_str());

        SetDebugPrivileges(); //set debug privilege
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
            break;
        }

        case LOAD_DLL_DEBUG_EVENT:
        {
            if (bHooked)
            {
                startInjection(ProcessId, g_scyllaHideDllPath.c_str(), false);
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
                    ReadNtApiInformation(g_ntApiCollectionIniPath.c_str(), &DllExchangeLoader);

                    bHooked = true;
                    startInjection(ProcessId, g_scyllaHideDllPath.c_str(), true);
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
        *titanPluginMajorVersion = SCYLLA_HIDE_VERSION_MAJOR;
        *titanPluginMinorVersion = SCYLLA_HIDE_VERSION_MINOR;
        strcpy(szPluginName, SCYLLA_HIDE_NAME_A);
        return true;
    }
    return false;
}
