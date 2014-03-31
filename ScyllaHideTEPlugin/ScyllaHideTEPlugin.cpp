#include <windows.h>
#include "TitanEngine.h"
#include "Injector.h"

static DWORD ProcessId;

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
    dllPath = L".\\plugins\\x64\\HookLibrary.dll";
#else
    dllPath = L".\\plugins\\x86\\HookLibrary.dll";
#endif

    SetDebugPrivileges();
    startInjection(ProcessId, dllPath);
}

extern "C" __declspec(dllexport) void TitanDebuggingCallBack(LPDEBUG_EVENT debugEvent, int CallReason)
{
    static HANDLE hProcess;
    static ULONG_PTR startAddress;

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
            startAddress = (ULONG_PTR)debugEvent->u.CreateProcessInfo.lpStartAddress;
        }
        break;

        case EXCEPTION_DEBUG_EVENT:
        {
            switch(debugEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case STATUS_BREAKPOINT:
            {
                //are we at EP ? (dont try setting BP callback on EP, it will break e.g. TitanScript
                if(debugEvent->u.Exception.ExceptionRecord.ExceptionAddress == (PVOID)startAddress) {
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