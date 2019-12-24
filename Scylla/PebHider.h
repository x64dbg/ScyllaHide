#pragma once

#include "Peb.h"

#define PEB_PATCH_BeingDebugged         0x00000001
#define PEB_PATCH_NtGlobalFlag          0x00000002
#define PEB_PATCH_HeapFlags             0x00000004
#define PEB_PATCH_ProcessParameters     0x00000008
#define PEB_PATCH_OsBuildNumber         0x00000010

namespace scl
{
    bool PebPatchProcessParameters(PEB* peb, HANDLE hProcess);
    bool Wow64Peb64PatchProcessParameters(PEB64* peb64, HANDLE hProcess);

    bool PebPatchHeapFlags(PEB* peb, HANDLE hProcess);
    bool Wow64Peb64PatchHeapFlags(PEB64* peb64, HANDLE hProcess);
}
