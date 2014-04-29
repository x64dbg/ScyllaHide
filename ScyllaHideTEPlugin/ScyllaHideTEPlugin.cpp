#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "TitanEngine.h"
#include "Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\ScyllaHideOlly2Plugin\ScyllaHideVersion.h"

#ifdef _WIN64
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif


const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

extern HOOK_DLL_EXCHANGE DllExchangeLoader;

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
			ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));
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
    if(titanPluginMajorVersion && titanPluginMinorVersion)
    {
        *titanPluginMajorVersion = SCYLLA_HIDE_MAJOR_VERSION;
        *titanPluginMinorVersion = SCYLLA_HIDE_MINOR_VERSION;
        strcpy(szPluginName, "ScyllaHide");
        return true;
    }
    return false;
}
