#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

void ReadNtApiInformation(const wchar_t *file, HOOK_DLL_DATA *hde);

void InstallAntiAttachHook();
void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess);
void injectDll(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillHookDllData(HANDLE hProcess, HOOK_DLL_DATA * data);
bool StartFixBeingDebugged(DWORD targetPid, bool setToNull);
bool ApplyAntiAntiAttach(DWORD targetPid);

DWORD_PTR GetAddressOfEntryPoint(BYTE * dllMemory);
bool RemoveDebugPrivileges(HANDLE hProcess);
