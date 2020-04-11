#include "PebHider.h"
#include <vector>
#include <Scylla/NtApiShim.h>
#include <Scylla/Peb.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Util.h>

#define HEAP_VALIDATE_ALL_ENABLED       0x20000000
#define HEAP_CAPTURE_STACK_BACKTRACES   0x08000000

// Flags set by RtlDebugCreateHeap
#define RTLDEBUGCREATEHEAP_HEAP_FLAGS   (HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS)

// Additional debug flags that may be set depending on NtGlobalFlags
#define NTGLOBALFLAGS_HEAP_FLAGS        (HEAP_DISABLE_COALESCE_ON_FREE | HEAP_FREE_CHECKING_ENABLED | HEAP_TAIL_CHECKING_ENABLED | \
                                        HEAP_VALIDATE_ALL_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED | HEAP_CAPTURE_STACK_BACKTRACES)

// The set of heap flags to clear is the union of flags set by RtlDebugCreateHeap and NtGlobalFlags
#define HEAP_CLEARABLE_FLAGS            (RTLDEBUGCREATEHEAP_HEAP_FLAGS | NTGLOBALFLAGS_HEAP_FLAGS)

// Only a subset of possible flags passed to RtlCreateHeap persists into force flags
#define HEAP_VALID_FORCE_FLAGS          (HEAP_NO_SERIALIZE | HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY | \
                                        HEAP_VALIDATE_PARAMETERS_ENABLED | HEAP_VALIDATE_ALL_ENABLED | HEAP_TAIL_CHECKING_ENABLED | \
                                        HEAP_CREATE_ALIGN_16 | HEAP_FREE_CHECKING_ENABLED)

// The set of force flags to clear is the intersection of valid force flags and the debug flags
#define HEAP_CLEARABLE_FORCE_FLAGS      (HEAP_CLEARABLE_FLAGS & HEAP_VALID_FORCE_FLAGS)

bool scl::PebPatchProcessParameters(PEB* peb, HANDLE hProcess)
{
    RTL_USER_PROCESS_PARAMETERS<DWORD_PTR> rupp;

    if (ReadProcessMemory(hProcess, (PVOID)peb->ProcessParameters, &rupp, sizeof(rupp), nullptr) == FALSE)
        return false;

    // Some debuggers manipulate StartUpInfo to start the debugged process and therefore can be detected...
    auto patch_size = (DWORD_PTR)&rupp.WindowFlags - (DWORD_PTR)&rupp.StartingX;
    ZeroMemory(&rupp.WindowFlags, patch_size);

    // https://github.com/x64dbg/ScyllaHide/issues/99
    rupp.WindowFlags = STARTF_USESHOWWINDOW;
    rupp.ShowWindowFlags = SW_SHOWNORMAL;

    // If the debugger used IFEO, the app doesn't need to know that
    rupp.Flags |= RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING;

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

    // https://github.com/x64dbg/ScyllaHide/issues/99
    rupp.WindowFlags = STARTF_USESHOWWINDOW;
    rupp.ShowWindowFlags = SW_SHOWNORMAL;

    // If the debugger used IFEO, the app doesn't need to know that
    rupp.Flags |= RTL_USER_PROCESS_PARAMETERS_IMAGE_KEY_MISSING;

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

        *flags &= ~HEAP_CLEARABLE_FLAGS;

        *force_flags &= ~HEAP_CLEARABLE_FORCE_FLAGS;

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

        *flags &= ~HEAP_CLEARABLE_FLAGS;

        *force_flags &= ~HEAP_CLEARABLE_FORCE_FLAGS;

        if (Wow64WriteProcessMemory64(hProcess, (PVOID64)heaps[i], (PVOID)heap.data(), heap.size(), nullptr) == FALSE)
            return false;
    }

    return true;
}
