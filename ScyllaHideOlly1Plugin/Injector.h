#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory);
void startInjection(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);
DWORD SetDebugPrivileges();

//olly definitions
extern "C" void _Addtolist(long addr,int highlight,char *format,...);
extern "C" void _Message(unsigned long addr,char *format,...);
extern "C" void _Error(char *format,...);