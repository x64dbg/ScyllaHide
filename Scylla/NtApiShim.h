#pragma once

#include <ntdll/ntdll.h>

#ifndef FLG_HEAP_ENABLE_TAIL_CHECK
#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#endif

#ifndef FLG_HEAP_ENABLE_FREE_CHECK
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#endif

#ifndef FLG_HEAP_VALIDATE_PARAMETERS
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#endif

#ifndef HEAP_SKIP_VALIDATION_CHECKS
#define HEAP_SKIP_VALIDATION_CHECKS 0x10000000
#endif

#ifndef HEAP_VALIDATE_PARAMETERS_ENABLED
#define HEAP_VALIDATE_PARAMETERS_ENABLED 0x40000000
#endif

typedef NTSTATUS(WINAPI *t_NtWow64QueryInformationProcess64)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

namespace scl
{
    template<typename PTR>
    struct PROCESS_BASIC_INFORMATION
    {
        DWORD ExitStatus;
        PTR PebBaseAddress;
        PTR AffinityMask;
        DWORD BasePriority;
        PTR UniqueProcessId;
        PTR InheritedFromUniqueProcessId;
    };
}
