#include "PebHider.h"
#include <Scylla/NtApiShim.h>
#include <Scylla/Peb.h>
#include <Scylla/OsInfo.h>

//some debuggers manipulate StartUpInfo to start the debugged process and therefore can be detected...
bool FixStartUpInfo(scl::PEB* myPEB, HANDLE hProcess)
{
    auto rtlProcessParam = (scl::RTL_USER_PROCESS_PARAMETERS<DWORD_PTR> *)myPEB->ProcessParameters;

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
    heapFlagsAddress = (void *)((LONG_PTR)heapBase + scl::GetHeapFlagsOffset(true));
    heapForceFlagsAddress = (void *)((LONG_PTR)heapBase + scl::GetHeapForceFlagsOffset(true));
#else
    heapFlagsAddress = (void *)((LONG_PTR)heapBase + scl::GetHeapFlagsOffset(false));
    heapForceFlagsAddress = (void *)((LONG_PTR)heapBase + scl::GetHeapForceFlagsOffset(false));
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
    auto peb = scl::GetPeb(hProcess);
    if (!peb)
        return false;

    peb->BeingDebugged = SetToNull ? FALSE : TRUE;
    if (!scl::SetPeb(hProcess, peb.get()))
        return false;

#ifndef _WIN64
    auto peb64 = scl::GetPeb64(hProcess);
    if (!peb64 && scl::IsWow64Process(hProcess))
        return false;

    if (peb64)
    {
        peb64->BeingDebugged = SetToNull ? FALSE : TRUE;
        return scl::SetPeb64(hProcess, peb64.get());
    }
#endif

    return true;
}

bool FixPebInProcess(HANDLE hProcess, DWORD EnableFlags)
{
    auto peb = scl::GetPeb(hProcess);
    if (!peb)
        return false;

#ifndef _WIN64
    auto peb64 = scl::GetPeb64(hProcess);
    if (!peb64 && scl::IsWow64Process(hProcess))
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

    if (!scl::SetPeb(hProcess, peb.get()))
        return false;
#ifndef _WIN64
    if (peb64 && !scl::SetPeb64(hProcess, peb64.get()))
        return false;
#endif

    return true;
}
