#include <windows.h>
#include "..\HookLibrary\HookMain.h"
#include "..\InjectorCLI\DynamicMapping.h"

#define IMAGE32(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define HEADER_FIELD(NtHeaders, Field) (IMAGE64(NtHeaders) \
	? ((PIMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field \
	: ((PIMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)
#define THUNK_VAL(NtHeaders, Ptr, Val) (IMAGE64(NtHeaders) \
	? ((PIMAGE_THUNK_DATA64)(Ptr))->Val \
	: ((PIMAGE_THUNK_DATA32)(Ptr))->Val)

typedef struct _THREAD_SUSPEND_INFO
{
    HANDLE ThreadId;
    HANDLE ThreadHandle;
    NTSTATUS SuspendStatus;
} THREAD_SUSPEND_INFO, *PTHREAD_SUSPEND_INFO;

typedef struct _PROCESS_SUSPEND_INFO
{
    HANDLE ProcessId;
    HANDLE ProcessHandle;
    ULONG NumThreads;
    PTHREAD_SUSPEND_INFO ThreadSuspendInfo; // THREAD_SUSPEND_INFO[NumThreads]
} PROCESS_SUSPEND_INFO, *PPROCESS_SUSPEND_INFO;

void ReadNtApiInformation(HOOK_DLL_DATA *hdd);

void InstallAntiAttachHook();
void startInjectionProcess(HANDLE hProcess, HOOK_DLL_DATA *hdd, BYTE * dllMemory, bool newProcess);
void startInjection(DWORD targetPid, HOOK_DLL_DATA *hdd, const WCHAR * dllPath, bool newProcess);
void injectDll(DWORD targetPid, const WCHAR * dllPath);
BYTE * ReadFileToMemory(const WCHAR * targetFilePath);
void FillHookDllData(HANDLE hProcess, HOOK_DLL_DATA * data);
bool StartFixBeingDebugged(DWORD targetPid, bool setToNull);
bool ApplyAntiAntiAttach(DWORD targetPid);

DWORD GetAddressOfEntryPoint(BYTE * dllMemory);
bool RemoveDebugPrivileges(HANDLE hProcess);
bool SafeSuspendProcess(HANDLE hProcess, PPROCESS_SUSPEND_INFO suspendInfo);
bool SafeResumeProcess(PPROCESS_SUSPEND_INFO suspendInfo);
