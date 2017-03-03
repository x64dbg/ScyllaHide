#pragma once

#include <windows.h>
#include <memory>

#include "NtApiShim.h"

//
// http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
//

namespace scl {

#pragma pack(push, 1)
    template <typename T>
    struct LIST_ENTRY
    {
        T Flink;
        T Blink;
    };

    template <typename T, typename NGF, int A>
    struct _PEB_T
    {
        union
        {
            struct
            {
                BYTE InheritedAddressSpace;
                BYTE ReadImageFileExecOptions;
                BYTE BeingDebugged;
                BYTE _SYSTEM_DEPENDENT_01;
            };
            T dummy01;
        };
        T Mutant;
        T ImageBaseAddress;
        T Ldr;
        T ProcessParameters;
        T SubSystemData;
        T ProcessHeap;
        T FastPebLock;
        T _SYSTEM_DEPENDENT_02;
        T _SYSTEM_DEPENDENT_03;
        T _SYSTEM_DEPENDENT_04;
        union
        {
            T KernelCallbackTable;
            T UserSharedInfoPtr;
        };
        DWORD SystemReserved;
        DWORD _SYSTEM_DEPENDENT_05;
        T _SYSTEM_DEPENDENT_06;
        T TlsExpansionCounter;
        T TlsBitmap;
        DWORD TlsBitmapBits[2];
        T ReadOnlySharedMemoryBase;
        T _SYSTEM_DEPENDENT_07;
        T ReadOnlyStaticServerData;
        T AnsiCodePageData;
        T OemCodePageData;
        T UnicodeCaseTableData;
        DWORD NumberOfProcessors;
        union
        {
            DWORD NtGlobalFlag;
            NGF dummy02;
        };
        LARGE_INTEGER CriticalSectionTimeout;
        T HeapSegmentReserve;
        T HeapSegmentCommit;
        T HeapDeCommitTotalFreeThreshold;
        T HeapDeCommitFreeBlockThreshold;
        DWORD NumberOfHeaps;
        DWORD MaximumNumberOfHeaps;
        T ProcessHeaps;
        T GdiSharedHandleTable;
        T ProcessStarterHelper;
        T GdiDCAttributeList;
        T LoaderLock;
        DWORD OSMajorVersion;
        DWORD OSMinorVersion;
        WORD OSBuildNumber;
        WORD OSCSDVersion;
        DWORD OSPlatformId;
        DWORD ImageSubsystem;
        DWORD ImageSubsystemMajorVersion;
        T ImageSubsystemMinorVersion;
        union
        {
            T ImageProcessAffinityMask;
            T ActiveProcessAffinityMask;
        };
        T GdiHandleBuffer[A];
        T PostProcessInitRoutine;
        T TlsExpansionBitmap;
        DWORD TlsExpansionBitmapBits[32];
        T SessionId;
        ULARGE_INTEGER AppCompatFlags;
        ULARGE_INTEGER AppCompatFlagsUser;
        T pShimData;
        T AppCompatInfo;
        UNICODE_STRING<T> CSDVersion;
        T ActivationContextData;
        T ProcessAssemblyStorageMap;
        T SystemDefaultActivationContextData;
        T SystemAssemblyStorageMap;
        T MinimumStackCommit;
    };
#pragma pack(pop)

    typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
    typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

#ifdef _WIN64
    typedef PEB64 PEB;
#else
    typedef PEB32 PEB;
#endif

    PEB *GetPebAddress(HANDLE hProcess);
    PVOID64 GetPeb64Address(HANDLE hProcess);

    std::shared_ptr<PEB> GetPeb(HANDLE hProcess);
    std::shared_ptr<PEB64> Wow64GetPeb64(HANDLE hProcess);

    bool SetPeb(HANDLE hProcess, const PEB *pPeb);
    bool Wow64SetPeb64(HANDLE hProcess, const PEB64 *pPeb64);

    DWORD GetHeapFlagsOffset(bool x64);
    DWORD GetHeapForceFlagsOffset(bool x64);
    }
