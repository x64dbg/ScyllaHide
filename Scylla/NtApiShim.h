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

#ifndef DBG_PRINTEXCEPTION_WIDE_C
#define DBG_PRINTEXCEPTION_WIDE_C ((DWORD)0x4001000A)
#endif

typedef NTSTATUS(WINAPI *t_NtWow64QueryInformationProcess64)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(WINAPI *t_NtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
typedef NTSTATUS(WINAPI *t_NtWow64WriteVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, LPCVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesWritten);


namespace scl
{
    template <typename PTR>
    struct UNICODE_STRING
    {
        union
        {
            struct
            {
                WORD Length;
                WORD MaximumLength;
            };
            PTR dummy;
        };
        PTR _Buffer;
    };

    template<typename PTR>
    struct CURDIR {
        UNICODE_STRING<PTR> DosPath;
        PTR Handle;
    };

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

    template<typename PTR>
    struct RTL_USER_PROCESS_PARAMETERS {
        ULONG MaximumLength;
        ULONG Length;

        ULONG Flags;
        ULONG DebugFlags;

        PTR ConsoleHandle;
        ULONG  ConsoleFlags;
        PTR StandardInput;
        PTR StandardOutput;
        PTR StandardError;

        CURDIR<PTR> CurrentDirectory;
        UNICODE_STRING<PTR> DllPath;
        UNICODE_STRING<PTR> ImagePathName;
        UNICODE_STRING<PTR> CommandLine;
        PTR Environment;

        ULONG StartingX;
        ULONG StartingY;
        ULONG CountX;
        ULONG CountY;
        ULONG CountCharsX;
        ULONG CountCharsY;
        ULONG FillAttribute;

        ULONG WindowFlags;
        ULONG ShowWindowFlags;
        UNICODE_STRING<PTR> WindowTitle;
        UNICODE_STRING<PTR> DesktopInfo;
        UNICODE_STRING<PTR> ShellInfo;
        UNICODE_STRING<PTR> RuntimeData;
    };
}
