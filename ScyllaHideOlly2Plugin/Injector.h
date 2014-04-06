#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

struct HideOptions {
    int PEB;
    int NtSetInformationThread;
    int NtQuerySystemInformation;
    int NtQueryInformationProcess;
    int NtQueryObject;
    int NtYieldExecution;
    int GetTickCount;
    int OutputDebugStringA;
    int BlockInput;
    int ProtectDrx;
    int NtUserFindWindowEx;
    int NtUserBuildHwndList;
    int NtUserQueryWindow;
    int NtSetDebugFilterState;
};

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory);
void startInjection(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
