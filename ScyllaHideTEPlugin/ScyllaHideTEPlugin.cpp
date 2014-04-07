#include <windows.h>
#include "TitanEngine.h"
#include "Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"

const WCHAR ScyllaHideDllFilename[] = L"HookLibrary.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

static WCHAR ScyllaHideDllPath[MAX_PATH] = { 0 };
WCHAR NtApiIniPath[MAX_PATH] = { 0 };

BOOL WINAPI DllMain(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        GetModuleFileNameW(hi, NtApiIniPath, _countof(NtApiIniPath));
        WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
        if (temp)
        {
            temp++;
            *temp = 0;
            wcscpy(ScyllaHideDllPath, NtApiIniPath);
            wcscat(ScyllaHideDllPath, ScyllaHideDllFilename);
            wcscat(NtApiIniPath, NtApiIniFilename);
        }
    }
    return TRUE;
};

static DWORD SetDebugPrivileges()
{
    DWORD err = 0;
    TOKEN_PRIVILEGES Debug_Privileges;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid)) return GetLastError();

    HANDLE hToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        err = GetLastError();
        if (hToken) CloseHandle(hToken);
        return err;
    }

    Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Debug_Privileges.PrivilegeCount = 1;

    if (!AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, NULL, NULL))
    {
        err = GetLastError();
        if (hToken) CloseHandle(hToken);
    }

    return err;
}

static void ScyllaHide(DWORD ProcessId)
{
    SetDebugPrivileges(); //set debug privilege
    ReadNtApiInformation(); //read rva stuff
    startInjection(ProcessId, ScyllaHideDllPath); //inject
}

extern "C" __declspec(dllexport) void TitanDebuggingCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
{
    static bool bHooked;
    static DWORD ProcessId;

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
        }
        break;

        case EXCEPTION_DEBUG_EVENT:
        {
            switch(debugEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case STATUS_BREAKPOINT:
            {
                if (!bHooked)
                {
                    bHooked = true;
                    ScyllaHide(ProcessId);
                }
            }
            break;
            }
        }
        break;
        }
    }
    break;
    }
}

extern "C" __declspec(dllexport) bool TitanRegisterPlugin(char* szPluginName, DWORD* titanPluginMajorVersion, DWORD* titanPluginMinorVersion)
{
    const DWORD PLUGIN_MAJOR_VERSION = 0;
    const DWORD PLUGIN_MINOR_VERSION = 1;

    if(titanPluginMajorVersion && titanPluginMinorVersion)
    {
        *titanPluginMajorVersion = PLUGIN_MAJOR_VERSION;
        *titanPluginMinorVersion = PLUGIN_MINOR_VERSION;
        strcpy(szPluginName, "ScyllaHide");
        return true;
    }
    return false;
}
