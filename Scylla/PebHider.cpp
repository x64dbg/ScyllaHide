#include "PebHider.h"
#include <vector>
#include <Scylla/NtApiShim.h>
#include <Scylla/Peb.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Util.h>

bool scl::PebPatchProcessParameters(PEB* peb, HANDLE hProcess)
{
    RTL_USER_PROCESS_PARAMETERS<DWORD_PTR> rupp;

    if (ReadProcessMemory(hProcess, (PVOID)peb->ProcessParameters, &rupp, sizeof(rupp), nullptr) == FALSE)
        return false;

    // Some debuggers manipulate StartUpInfo to start the debugged process and therefore can be detected...
    auto patch_size = (DWORD_PTR)&rupp.WindowFlags - (DWORD_PTR)&rupp.StartingX;
    ZeroMemory(&rupp.WindowFlags, patch_size);

    // Magic flag.
    rupp.Flags |= (ULONG)0x4000;

    return (WriteProcessMemory(hProcess, (PVOID)peb->ProcessParameters, &rupp, sizeof(rupp), nullptr) == TRUE);
}

bool scl::Wow64Peb64PatchProcessParameters(PEB64* peb64, HANDLE hProcess)
{
#ifndef _WIN64
    scl::RTL_USER_PROCESS_PARAMETERS<DWORD64> rupp;

    if (!scl::Wow64ReadProcessMemory64(hProcess, (PVOID64)peb64->ProcessParameters, (PVOID)&rupp, sizeof(rupp), nullptr))
        return false;

    // Some debuggers manipulate StartUpInfo to start the debugged process and therefore can be detected...
    auto patch_size = (DWORD_PTR)&rupp.WindowFlags - (DWORD_PTR)&rupp.StartingX;
    ZeroMemory(&rupp.WindowFlags, patch_size);

    // Magic flag.
    rupp.Flags |= (ULONG)0x4000;

    return Wow64WriteProcessMemory64(hProcess, (PVOID)peb64->ProcessParameters, &rupp, sizeof(rupp), nullptr);
#endif

    return false;
}

bool scl::PebPatchHeapFlags(PEB* peb, HANDLE hProcess)
{
#ifdef _WIN64
    const auto is_x64 = true;
#else
    const auto is_x64 = false;
#endif

    std::vector<PVOID> heaps;
    heaps.resize(peb->NumberOfHeaps);

    if (ReadProcessMemory(hProcess, (PVOID)peb->ProcessHeaps, (PVOID)heaps.data(), heaps.size()*sizeof(PVOID), nullptr) == FALSE)
        return false;

    std::basic_string<uint8_t> heap;
    heap.resize(0x100); // hacky
    for (DWORD i = 0; i < peb->NumberOfHeaps; i++)
    {
        if (ReadProcessMemory(hProcess, heaps[i], (PVOID)heap.data(), heap.size(), nullptr) == FALSE)
            return false;

        auto flags = (DWORD *)(heap.data() + scl::GetHeapFlagsOffset(is_x64));
        auto force_flags = (DWORD *)(heap.data() + scl::GetHeapForceFlagsOffset(is_x64));

        if (i == 0)
        {
            // Default heap.
            *flags &= HEAP_GROWABLE;
        }
        else
        {
            // Flags from RtlCreateHeap/HeapCreate.
            *flags &= (HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE | HEAP_CREATE_ENABLE_EXECUTE);
        }

        *force_flags = 0;

        if (WriteProcessMemory(hProcess, heaps[i], (PVOID)heap.data(), heap.size(), nullptr) == FALSE)
            return false;
    }

    return true;
}

bool scl::Wow64Peb64PatchHeapFlags(PEB64* peb, HANDLE hProcess)
{
    std::vector<PVOID64> heaps;
    heaps.resize(peb->NumberOfHeaps);

    if (scl::Wow64ReadProcessMemory64(hProcess, (PVOID64)peb->ProcessHeaps, (PVOID)heaps.data(), heaps.size()*sizeof(PVOID64), nullptr) == FALSE)
        return false;

    std::basic_string<uint8_t> heap;
    heap.resize(0x100); // hacky
    for (DWORD i = 0; i < peb->NumberOfHeaps; i++)
    {
        if (Wow64ReadProcessMemory64(hProcess, (PVOID64)heaps[i], (PVOID)heap.data(), heap.size(), nullptr) == FALSE)
            return false;

        auto flags = (DWORD *)(heap.data() + scl::GetHeapFlagsOffset(true));
        auto force_flags = (DWORD *)(heap.data() + scl::GetHeapForceFlagsOffset(true));

        if (i == 0)
        {
            // Default heap.
            *flags &= HEAP_GROWABLE;
        }
        else
        {
            // Flags from RtlCreateHeap/HeapCreate.
            *flags &= (HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE | HEAP_CREATE_ENABLE_EXECUTE);
        }

        *force_flags = 0;

        if (Wow64WriteProcessMemory64(hProcess, (PVOID64)heaps[i], (PVOID)heap.data(), heap.size(), nullptr) == FALSE)
            return false;
    }

    return true;
}
