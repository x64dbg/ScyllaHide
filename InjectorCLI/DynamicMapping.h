#pragma once

#include <windows.h>

typedef struct _SameTebFlags
{
    union
    {
        struct
        {
            USHORT DbgSafeThunkCall : 1;
            USHORT DbgInDebugPrint : 1;
            USHORT DbgHasFiberData : 1;
            USHORT DbgSkipThreadAttach : 1;
            USHORT DbgWerInShipAssertCode : 1;
            USHORT DbgIssuedInitialBp : 1;
            USHORT DbgClonedThread : 1;
            USHORT SpareSameTebBits : 9;
        };
        USHORT SameTebFlags;
    };
} SameTebFlags;

#ifdef _WIN64
#define TEB_OFFSET_SAME_TEB_FLAGS 0x17EE
#else
#define TEB_OFFSET_SAME_TEB_FLAGS 0xFCA
#endif

LPVOID MapModuleToProcess(HANDLE hProcess, BYTE * dllMemory, bool wipeHeaders);
void DoBaseRelocation(PIMAGE_BASE_RELOCATION relocation, DWORD_PTR memory, DWORD_PTR dwDelta);
DWORD GetDllFunctionAddressRVA(BYTE * dllMemory, LPCSTR apiName);
DWORD RVAToOffset(PIMAGE_NT_HEADERS pNtHdr, DWORD dwRVA);
HMODULE GetModuleBaseRemote(HANDLE hProcess, const wchar_t* szDLLName);
bool ResolveImports(PIMAGE_IMPORT_DESCRIPTOR pImport, DWORD_PTR module);
