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
	WCHAR ollyTitle[300];
	int x64Fix;
	int preventThreadCreation;
	int DLLStealth;
	int DLLNormal;
	int DLLUnload;
};

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess);
void injectDll(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
void StartFixBeingDebugged(DWORD targetPid, bool setToNull);