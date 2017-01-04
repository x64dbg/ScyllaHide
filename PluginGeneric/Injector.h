#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

void InstallAntiAttachHook();
void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess);
void injectDll(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
void StartFixBeingDebugged(DWORD targetPid, bool setToNull);
bool ApplyAntiAntiAttach(DWORD targetPid);

DWORD_PTR GetAddressOfEntryPoint(BYTE * dllMemory);
bool RemoveDebugPrivileges(HANDLE hProcess);
