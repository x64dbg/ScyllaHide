#pragma once

#include <windows.h>
#include <memory>

#include "NtApiShim.h"

//
// http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
//

namespace scl {

#pragma pack(push, 1)
    template <class T>
    struct _LIST_ENTRY_T
    {
        T Flink;
        T Blink;
    };

    template <class T>
    struct _UNICODE_STRING_T
    {
        union
        {
            struct
            {
                WORD Length;
                WORD MaximumLength;
            };
            T dummy;
        };
        T Buffer;
    };

    template <class T>
    struct _LDR_DATA_TABLE_ENTRY_T
    {
        _LIST_ENTRY_T<T> InLoadOrderLinks;
        _LIST_ENTRY_T<T> InMemoryOrderLinks;
        _LIST_ENTRY_T<T> InInitializationOrderLinks;
        T DllBase;
        T EntryPoint;
        union
        {
            DWORD SizeOfImage;
            T dummy01;
        };
        _UNICODE_STRING_T<T> FullDllName;
        _UNICODE_STRING_T<T> BaseDllName;
        DWORD Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union
        {
            _LIST_ENTRY_T<T> HashLinks;
            struct
            {
                T SectionPointer;
                T CheckSum;
            };
        };
        union
        {
            T LoadedImports;
            DWORD TimeDateStamp;
        };
        T EntryPointActivationContext;
        T PatchInformation;
        _LIST_ENTRY_T<T> ForwarderLinks;
        _LIST_ENTRY_T<T> ServiceTagLinks;
        _LIST_ENTRY_T<T> StaticLinks;
        T ContextInformation;
        T OriginalBase;
        _LARGE_INTEGER LoadTime;
    };

    template <class T>
    struct _PEB_LDR_DATA_T
    {
        DWORD Length;
        DWORD Initialized;
        T SsHandle;
        _LIST_ENTRY_T<T> InLoadOrderModuleList;
        _LIST_ENTRY_T<T> InMemoryOrderModuleList;
        _LIST_ENTRY_T<T> InInitializationOrderModuleList;
        T EntryInProgress;
        DWORD ShutdownInProgress;
        T ShutdownThreadId;

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

    typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
    typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;

    typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
    typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;

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

    PVOID64 Wow64GetModuleHandle64(HANDLE hProcess, const wchar_t* moduleName);

    DWORD GetHeapFlagsOffset(bool x64);
    DWORD GetHeapForceFlagsOffset(bool x64);
    }
