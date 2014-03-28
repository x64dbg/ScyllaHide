#include <windows.h>
#include "TitanEngine.h"
#include "Injector.h"

BOOL APIENTRY DllMain(HINSTANCE hi, DWORD reason, LPVOID)
{
    switch(reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hi);
        break;
    }
    return TRUE;
}

static void ScyllaHide(DWORD ProcessId) {
    WCHAR * dllPath = 0;

#ifdef _WIN64
    dllPath = L"Z:\\__dev\\scyllahide\\Debug\\HookLibrary.dll";
#else
    dllPath = L"Z:\\__dev\\scyllahide\\Debug\\HookLibrary.dll";
#endif

    SetDebugPrivileges();
    startInjection(ProcessId, dllPath);
}

extern "C" __declspec(dllexport) void TitanDebuggingCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
{
    static DWORD ProcessId;
    static HANDLE hProcess;
    switch(CallReason)
    {
    case UE_PLUGIN_CALL_REASON_EXCEPTION:
    {
        switch(debugEvent->dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            hProcess=debugEvent->u.CreateProcessInfo.hProcess;
            ProcessId=debugEvent->dwProcessId;
            
        }
        break;

        case EXCEPTION_DEBUG_EVENT:
        {
            switch(debugEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case STATUS_BREAKPOINT:
            {
				ScyllaHide(ProcessId);
            }
            break;
            }
        }
        break;
        }
    }
    break;

    case UE_PLUGIN_CALL_REASON_POSTDEBUG:
    {
        //TitanHideCall(ProcessId, UnhidePid);
    }
    break;
    }
}

extern "C" __declspec(dllexport) bool TitanRegisterPlugin(char* szPluginName, DWORD* titanPluginMajorVersion, DWORD* titanPluginMinorVersion)
{
    const DWORD PLUGIN_MAJOR_VERSION = 1;
    const DWORD PLUGIN_MINOR_VERSION = 0;

    if(titanPluginMajorVersion && titanPluginMinorVersion)
    {
        *titanPluginMajorVersion = PLUGIN_MAJOR_VERSION;
        *titanPluginMinorVersion = PLUGIN_MINOR_VERSION;
        strcpy(szPluginName, "ScyllaHide");
        return true;
    }
    return false;
}