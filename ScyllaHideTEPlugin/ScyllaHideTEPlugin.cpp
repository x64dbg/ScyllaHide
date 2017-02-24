#include <Windows.h>
#include <Scylla/NtApiLoader.h>
#include <Scylla/Settings.h>
#include <Scylla/Version.h>
#include <Scylla/Util.h>
#include <titan/TitanEngine.h>

#include "..\PluginGeneric\Injector.h"

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;

#ifdef _WIN64
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

scl::Settings g_settings;
std::wstring g_scyllaHideDllPath;
std::wstring g_ntApiCollectionIniPath;
std::wstring g_scyllaHideIniPath;

bool bHooked;
DWORD ProcessId;

static void LogWrapper(const WCHAR * format, ...)
{
}

static bool SetDebugPrivileges()
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

extern "C" DLL_EXPORT void TitanDebuggingCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
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

extern "C" DLL_EXPORT bool TitanRegisterPlugin(char* szPluginName, DWORD* titanPluginMajorVersion, DWORD* titanPluginMinorVersion)
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

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        LogWrap = LogWrapper;
        LogErrorWrap = LogWrapper;

        auto wstrPath = scl::GetModuleFileNameW(hInstDll);
        wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);

        g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
        g_ntApiCollectionIniPath = wstrPath + scl::NtApiLoader::kFileName;
        g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;

        g_settings.Load(g_scyllaHideIniPath.c_str());

        SetDebugPrivileges();
    }
    return TRUE;
}
