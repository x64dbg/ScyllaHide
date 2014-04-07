#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory);
void startInjection(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
