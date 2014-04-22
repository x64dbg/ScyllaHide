#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

struct HideOptions
{
    int PEBBeingDebugged;
    int PEBHeapFlags;
    int PEBNtGlobalFlag;
    int PEBStartupInfo;
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
    int NtCreateThreadEx;
    int removeEPBreak;
    int fixOllyBugs;
    int breakTLS;
    char ollyTitle[32];
    int x64Fix;
    int preventThreadCreation;
};

void StartFixBeingDebugged(DWORD targetPid, bool setToNull);
void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess);
void injectDll(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
