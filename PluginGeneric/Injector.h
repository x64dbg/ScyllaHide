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
    int NtSetInformationProcess;
    int NtQueryObject;
    int NtYieldExecution;
    int GetTickCount;
    int GetTickCount64;
    int GetLocalTime;
    int GetSystemTime;
    int NtQuerySystemTime;
    int NtQueryPerformanceCounter;
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
    int skipEPOutsideCode;
    WCHAR ollyTitle[300];
    int x64Fix;
    int preventThreadCreation;
    int DLLStealth;
    int DLLNormal;
    int DLLUnload;
    WCHAR serverPort[6];
    int autostartServer;
    int removeDebugPrivileges;
    int malwareRunpeUnpacker;
    int killAntiAttach;
    int ignoreBadPEImage;
    int advancedGoto;
    int skipCompressedDoAnalyze;
    int skipCompressedDoNothing;
    int skipLoadDllDoLoad;
    int skipLoadDllDoNothing;
};

void InstallAntiAttachHook();
void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess);
void injectDll(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
void StartFixBeingDebugged(DWORD targetPid, bool setToNull);
bool ApplyAntiAntiAttach(DWORD targetPid);

bool IsProcessWOW64(HANDLE hProcess);
bool isWindows64();
bool RemoveDebugPrivileges(HANDLE hProcess);
