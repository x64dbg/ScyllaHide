#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

struct HideOptions
{
    int PEB;
    int NtSetInformationThread;
    int NtQuerySystemInformation;
    int NtQueryInformationProcess;
    int NtQueryObject;
    int NtYieldExecution;
    int GetTickCount;
    int OutputDebugStringA;
    int BlockInput;
    int NtGetContextThread;
    int NtSetContextThread;
    int NtContinue;
    int KiUserExceptionDispatcher;
    int NtUserFindWindowEx;
    int NtUserBuildHwndList;
    int NtUserQueryWindow;
    int NtSetDebugFilterState;
    int NtClose;
    WCHAR ollyTitle[256];
};

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
void StartFixBeingDebugged(DWORD targetPid, bool setToNull);