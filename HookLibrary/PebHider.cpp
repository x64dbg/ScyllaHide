#include "PebHider.h"
#include "HookHelper.h"

#ifndef _WIN64
bool IsThisProcessWow64()
{
    typedef BOOL (WINAPI * tIsWow64Process)(HANDLE hProcess,PBOOL Wow64Process);
    BOOL bIsWow64 = FALSE;
    tIsWow64Process fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if (fnIsWow64Process)
    {
        fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
    }

    return (bIsWow64 != FALSE);
}
#endif

PEB_CURRENT * GetPEBCurrent()
{
    PEB_CURRENT *pPeb = 0;

#ifdef _WIN64
    pPeb = (PEB_CURRENT *)__readgsqword(12 * sizeof(DWORD_PTR));
#else
    pPeb = (PEB_CURRENT *)__readfsdword(12 * sizeof(DWORD_PTR));
#endif

    return pPeb;
}

PEB64 * GetPEB64()
{
    PEB64 *pPeb = 0;
#ifndef _WIN64
    if (IsThisProcessWow64())
    {
        pPeb = (PEB64 *)__readfsdword(12 * sizeof(DWORD_PTR));
        pPeb = (PEB64 *)((DWORD_PTR)pPeb + 0x1000);
    }
#endif
    return pPeb;
}



static int getHeapFlagsOffset(bool x64)
{
    if (x64) //x64 offsets
    {
        if (IsAtleastVista())
        {
            return 0x70;
        }
        else
        {
            return 0x14;
        }
    }
    else //x86 offsets
    {
        if (IsAtleastVista())
        {
            return 0x40;
        }
        else
        {
            return 0x0C;
        }
    }
}

static int getHeapForceFlagsOffset(bool x64)
{
    if (x64) //x64 offsets
    {
        if (IsAtleastVista())
        {
            return 0x74;
        }
        else
        {
            return 0x18;
        }
    }
    else //x86 offsets
    {
        if (IsAtleastVista())
        {
            return 0x44;
        }
        else
        {
            return 0x10;
        }
    }
}


void FixPebAntidebug()
{
    DWORD * heapFlagsAddress = 0;
    DWORD * heapForceFlagsAddress = 0;

    PEB64 *pPeb64 = GetPEB64();
    PEB_CURRENT *pPeb = GetPEBCurrent();

    pPeb->BeingDebugged = FALSE;
    pPeb->NtGlobalFlag &= ~0x70;

    if (pPeb64)
    {
        pPeb64->BeingDebugged = FALSE;
        pPeb64->NtGlobalFlag &= ~0x70;
    }

#ifdef _WIN64
    heapFlagsAddress = (DWORD *)((LONG_PTR)pPeb->ProcessHeap + getHeapFlagsOffset(true));
    heapForceFlagsAddress = (DWORD *)((LONG_PTR)pPeb->ProcessHeap + getHeapForceFlagsOffset(true));
#else
    heapFlagsAddress = (DWORD *)((LONG_PTR)pPeb->ProcessHeap + getHeapFlagsOffset(false));
    heapForceFlagsAddress = (DWORD *)((LONG_PTR)pPeb->ProcessHeap + getHeapForceFlagsOffset(false));
#endif

    *heapFlagsAddress &= HEAP_GROWABLE;
    *heapForceFlagsAddress = 0;
}
