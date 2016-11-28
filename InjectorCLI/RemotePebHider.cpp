#include "RemotePebHider.h"
#include <Scylla/Peb.h>
#include <Scylla/OsInfo.h>

//Quote from The Ultimate Anti-Debugging Reference by Peter Ferrie
//Flags field exists at offset 0x0C in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x40 on the 32-bit versions of Windows Vista and later.
//Flags field exists at offset 0x14 in the heap on the 64-bit versions of Windows XP, and at offset 0x70 in the heap on the 64-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x10 in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x44 on the 32-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x18 in the heap on the 64-bit versions of Windows XP, and at offset 0x74 in the heap on the 64-bit versions of Windows Vista and later.

static int getHeapFlagsOffset(bool x64)
{
    if (x64) //x64 offsets
    {
        if (Scylla::GetWindowsVersion() >= Scylla::OS_WIN_VISTA)
            return 0x70;
        else
            return 0x14;
    }
    else //x86 offsets
    {
        if (Scylla::GetWindowsVersion() >= Scylla::OS_WIN_VISTA)
            return 0x40;
        else
            return 0x0C;
    }
}

static int getHeapForceFlagsOffset(bool x64)
{
    if (x64) //x64 offsets
    {
        if (Scylla::GetWindowsVersion() >= Scylla::OS_WIN_VISTA)
            return 0x74;
        else
            return 0x18;
    }
    else //x86 offsets
    {
        if (Scylla::GetWindowsVersion() >= Scylla::OS_WIN_VISTA)
            return 0x44;
        else
            return 0x10;
    }
}

//some debuggers manipulate StartUpInfo to start the debugged process and therefore can be detected...
bool FixStartUpInfo(Scylla::PEB* myPEB, HANDLE hProcess)
{
    RTL_USER_PROCESS_PARAMETERS * rtlProcessParam = (RTL_USER_PROCESS_PARAMETERS *)myPEB->ProcessParameters;

    DWORD_PTR startOffset = (DWORD_PTR)&rtlProcessParam->StartingX;
    DWORD_PTR patchSize = (DWORD_PTR)&rtlProcessParam->WindowFlags - (DWORD_PTR)&rtlProcessParam->StartingX;

    LPVOID memoryZero = calloc(patchSize, 1);

    bool retVal = (WriteProcessMemory(hProcess, (LPVOID)startOffset, memoryZero, patchSize, 0) != FALSE);
    free(memoryZero);

    return retVal;
}

void FixHeapFlag(HANDLE hProcess, DWORD_PTR heapBase, bool isDefaultHeap)
{
    void * heapFlagsAddress = 0;
    DWORD heapFlags = 0;
    void * heapForceFlagsAddress = 0;
    DWORD heapForceFlags = 0;
#ifdef _WIN64
    heapFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapFlagsOffset(true));
    heapForceFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapForceFlagsOffset(true));
#else
    heapFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapFlagsOffset(false));
    heapForceFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapForceFlagsOffset(false));
#endif //_WIN64

    if (ReadProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0))
    {
        if (isDefaultHeap)
        {
            heapFlags &= HEAP_GROWABLE;
        }
        else
        {
            //user defined heaps with user defined flags
            //flags from RtlCreateHeap/HeapCreate
            heapFlags &= (HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE | HEAP_CREATE_ENABLE_EXECUTE);
        }
        WriteProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
    }
    if (ReadProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0))
    {
        heapForceFlags = 0;
        WriteProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);
    }
}

bool FixPebBeingDebugged(HANDLE hProcess, bool SetToNull)
{
    auto peb = Scylla::GetPeb(hProcess);
    if (!peb)
        return false;

    peb->BeingDebugged = SetToNull ? FALSE : TRUE;
    if (!Scylla::SetPeb(hProcess, peb.get()))
        return false;

#ifndef _WIN64
    auto peb64 = Scylla::GetPeb64(hProcess);
    if (!peb64 && Scylla::IsWow64Process(hProcess))
        return false;

    if (peb64)
    {
        peb64->BeingDebugged = SetToNull ? FALSE : TRUE;
        return Scylla::SetPeb64(hProcess, peb64.get());
    }
#endif

    return true;
}

bool FixPebInProcess(HANDLE hProcess, DWORD EnableFlags)
{
    auto peb = Scylla::GetPeb(hProcess);
    if (!peb)
        return false;

#ifndef _WIN64
    auto peb64 = Scylla::GetPeb64(hProcess);
    if (!peb64 && Scylla::IsWow64Process(hProcess))
        return false;
#endif

    if (EnableFlags & PEB_PATCH_StartUpInfo)
        FixStartUpInfo(peb.get(), hProcess);

    if (EnableFlags & PEB_PATCH_BeingDebugged) peb->BeingDebugged = FALSE;
    if (EnableFlags & PEB_PATCH_NtGlobalFlag) peb->NtGlobalFlag &= ~0x70;

#ifndef _WIN64
    if (peb64)
    {
        if (EnableFlags & PEB_PATCH_BeingDebugged) peb->BeingDebugged = FALSE;
        if (EnableFlags & PEB_PATCH_NtGlobalFlag) peb->NtGlobalFlag &= ~0x70;
    }
#endif

    if (EnableFlags & PEB_PATCH_HeapFlags)
    {
        //handle to the default heap of the calling process
        FixHeapFlag(hProcess, peb->ProcessHeap, true);

        // first is always default heap
        if (peb->NumberOfHeaps > 1)
        {
            auto heapArray = (PVOID *)calloc(peb->NumberOfHeaps, sizeof(PVOID));
            if (heapArray)
            {
                ReadProcessMemory(hProcess, (PVOID)peb->ProcessHeaps, heapArray, peb->NumberOfHeaps*sizeof(PVOID), 0);

                //skip index 0 same as default heap myPEB.ProcessHeap
                for (DWORD i = 1; i < peb->NumberOfHeaps; i++)
                {
                    FixHeapFlag(hProcess, (DWORD_PTR)heapArray[i], false);
                }
            }
            free(heapArray);
        }
    }

    if (!Scylla::SetPeb(hProcess, peb.get()))
        return false;
#ifndef _WIN64
    if (peb64 && !Scylla::SetPeb64(hProcess, peb64.get()))
        return false;
#endif

    return true;
}
