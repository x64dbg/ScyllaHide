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
    int ProtectDrx;
    int NtUserFindWindowEx;
    int NtUserBuildHwndList;
    int NtUserQueryWindow;
    int NtSetDebugFilterState;
    int NtClose;
    int removeEPBreak;
    char ollyTitle[32];
};

void startInjectionProcess(HANDLE hProcess, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, const WCHAR * dllPath, bool newProcess);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillExchangeStruct(HANDLE hProcess, HOOK_DLL_EXCHANGE * data);


//olly definitions
extern "C" void _Addtolist(long addr,int highlight,char *format,...);
extern "C" void _Message(unsigned long addr,char *format,...);
extern "C" void _Error(char *format,...);
extern "C" int _Pluginwriteinttoini(HINSTANCE dllinst,char *key,int value);
extern "C" int _Pluginreadintfromini(HINSTANCE dllinst,char *key,int def);
extern "C" int _Pluginwritestringtoini(HINSTANCE dllinst,char *key,char *s);
extern "C" int _Pluginreadstringfromini(HINSTANCE dllinst,char *key, char *s,char *def);
extern "C" void _Deletebreakpoints(unsigned long addr0,unsigned long addr1,int silent);
extern "C" int _Setbreakpoint(unsigned long addr,unsigned long type,unsigned char cmd);
