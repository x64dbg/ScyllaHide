#include <Windows.h>
#include <cstdio>
#include <Scylla/NtApiShim.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Peb.h>
#include <Scylla/Util.h>

enum ScyllaTestResult
{
    ScyllaTestOk = 0,
    ScyllaTestFail,
    ScyllaTestDetected,
    ScyllaTestSkip
};

#define SCYLLA_TEST_FAIL_IF(x) if (x) return ScyllaTestFail;
#define SCYLLA_TEST_CHECK(x) ((x) ? ScyllaTestOk : ScyllaTestDetected);

#ifdef _WIN64
const bool is_x64 = true;
#else
const bool is_x64 = false;
#endif

static HANDLE g_proc_handle, g_stopEvent;

static BOOL NTAPI CtrlHandler(ULONG)
{
    // Signal test stop, and don't pass to next handler
    NtSetEvent(g_stopEvent, nullptr);
    return TRUE;
}

static HANDLE GetRealCurrentProcess()
{
    auto pseudo_handle = GetCurrentProcess();
    auto hRealHandle = INVALID_HANDLE_VALUE;
    DuplicateHandle(pseudo_handle, pseudo_handle, pseudo_handle, &hRealHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
    return hRealHandle;
}

static NTSTATUS GetOtherOperationCount(PULONGLONG otherOperationCount)
{
    *otherOperationCount = 0;
    ULONGLONG otherOperationCountSystemProcessInformation = 0,
        otherOperationCountSystemExtendedProcessInformation = 0,
        otherOperationCountSystemSessionProcessInformation = 0;

    // NtQSI(SystemProcessInformation)
    ULONG size;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;
    const PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, size * 2);
    if (SystemProcessInfo == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;
    status = NtQuerySystemInformation(SystemProcessInformation, SystemProcessInfo, size * 2, nullptr);
    if (!NT_SUCCESS(status))
    {
        RtlFreeHeap(RtlProcessHeap(), 0, SystemProcessInfo);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION entry = SystemProcessInfo;
    status = STATUS_NOT_FOUND;

    while (true)
    {
        if (entry->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
        {
            otherOperationCountSystemProcessInformation = entry->OtherOperationCount.QuadPart;
            status = STATUS_SUCCESS;
            break;
        }
        
        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)entry + entry->NextEntryOffset);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, SystemProcessInfo);
    if (!NT_SUCCESS(status))
        return status;

    // NtQSI(SystemExtendedProcessInformation)
    status = NtQuerySystemInformation(SystemExtendedProcessInformation, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;
    const PSYSTEM_PROCESS_INFORMATION systemExtendedProcessInfo = (PSYSTEM_PROCESS_INFORMATION)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, size * 2);
    if (SystemProcessInfo == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;
    status = NtQuerySystemInformation(SystemExtendedProcessInformation, systemExtendedProcessInfo, size * 2, nullptr);
    if (!NT_SUCCESS(status))
    {
        RtlFreeHeap(RtlProcessHeap(), 0, systemExtendedProcessInfo);
        return status;
    }

    entry = systemExtendedProcessInfo;
    status = STATUS_NOT_FOUND;

    while (true)
    {
        if (entry->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
        {
            otherOperationCountSystemExtendedProcessInformation = entry->OtherOperationCount.QuadPart;
            status = STATUS_SUCCESS;
            break;
        }
        
        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)entry + entry->NextEntryOffset);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, systemExtendedProcessInfo);
    if (!NT_SUCCESS(status))
        return status;

    // NtQSI(SystemSessionProcessInformation)
    SYSTEM_SESSION_PROCESS_INFORMATION sessionProcessInfo = { NtCurrentPeb()->SessionId, sizeof(SYSTEM_SESSION_PROCESS_INFORMATION), &sessionProcessInfo };
    status = NtQuerySystemInformation(SystemSessionProcessInformation, &sessionProcessInfo, sizeof(sessionProcessInfo), &sessionProcessInfo.SizeOfBuf);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;
    sessionProcessInfo.SizeOfBuf *= 2;
    sessionProcessInfo.Buffer = RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sessionProcessInfo.SizeOfBuf);
    if (SystemProcessInfo == nullptr)
        return STATUS_INSUFFICIENT_RESOURCES;
    status = NtQuerySystemInformation(SystemSessionProcessInformation, &sessionProcessInfo, sizeof(sessionProcessInfo), nullptr);
    if (!NT_SUCCESS(status))
    {
        RtlFreeHeap(RtlProcessHeap(), 0, sessionProcessInfo.Buffer);
        return status;
    }

    entry = (PSYSTEM_PROCESS_INFORMATION)sessionProcessInfo.Buffer;
    status = STATUS_NOT_FOUND;

    while (true)
    {
        if (entry->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
        {
            otherOperationCountSystemSessionProcessInformation = entry->OtherOperationCount.QuadPart;
            status = STATUS_SUCCESS;
            break;
        }
        
        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)entry + entry->NextEntryOffset);
    }

    RtlFreeHeap(RtlProcessHeap(), 0, sessionProcessInfo.Buffer);
    if (!NT_SUCCESS(status))
        return status;

    // NtQIP(IoCounters)
    IO_COUNTERS ioCounters;
    status = NtQueryInformationProcess(g_proc_handle, ProcessIoCounters, &ioCounters, sizeof(ioCounters), nullptr);
    if (!NT_SUCCESS(status))
        return status;

    // All four counts should be the same
    if (otherOperationCountSystemProcessInformation != otherOperationCountSystemExtendedProcessInformation ||
        otherOperationCountSystemProcessInformation != otherOperationCountSystemSessionProcessInformation ||
        otherOperationCountSystemProcessInformation != ioCounters.OtherOperationCount)
        return STATUS_DATA_NOT_ACCEPTED;

    // Return final count
    *otherOperationCount = otherOperationCountSystemProcessInformation;
    return STATUS_SUCCESS;
}

static ScyllaTestResult Check_PEB_BeingDebugged()
{
    const auto peb = scl::GetPebAddress(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb);
    return SCYLLA_TEST_CHECK(peb->BeingDebugged == 0);
}

static ScyllaTestResult Check_Wow64PEB64_BeingDebugged()
{
    const auto peb64 = scl::Wow64GetPeb64(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb64);

    return SCYLLA_TEST_CHECK(peb64->BeingDebugged == 0);
}

static ScyllaTestResult Check_PEB_NtGlobalFlag()
{
    const DWORD bad_flags = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;
    const auto peb = scl::GetPebAddress(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb);
    return SCYLLA_TEST_CHECK((peb->NtGlobalFlag & bad_flags) == 0);
}

static ScyllaTestResult Check_Wow64PEB64_NtGlobalFlag()
{
    const DWORD bad_flags = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;
    const auto peb64 = scl::Wow64GetPeb64(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb64);
    return SCYLLA_TEST_CHECK((peb64->NtGlobalFlag & bad_flags) == 0);
}

static ScyllaTestResult Check_PEB_HeapFlags()
{
    const DWORD bad_flags = HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED;

    const auto peb = scl::GetPebAddress(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb);

    auto heaps = (void **)peb->ProcessHeaps;
    for (DWORD i = 0; i < peb->NumberOfHeaps; i++)
    {
        auto flags = *(DWORD *)((BYTE *)heaps[i] + scl::GetHeapFlagsOffset(is_x64));
        auto force_flags = *(DWORD *)((BYTE *)heaps[i] + scl::GetHeapForceFlagsOffset(is_x64));

        if ((flags & bad_flags) || (force_flags & bad_flags))
            return ScyllaTestDetected;
    }

    return ScyllaTestOk;
}

static ScyllaTestResult Check_Wow64PEB64_HeapFlags()
{
    const DWORD bad_flags = HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED;
    const auto peb64 = scl::Wow64GetPeb64(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb64);

    std::basic_string<PVOID64> heaps64;
    heaps64.resize(peb64->NumberOfHeaps);

    SCYLLA_TEST_FAIL_IF(!scl::Wow64ReadProcessMemory64(g_proc_handle, (PVOID64)peb64->ProcessHeaps, (PVOID)heaps64.data(), heaps64.size()*sizeof(PVOID64), nullptr));

    std::basic_string<uint8_t> heap;
    heap.resize(0x100); // hacky
    for (DWORD i = 0; i < peb64->NumberOfHeaps; i++)
    {
        SCYLLA_TEST_FAIL_IF(!scl::Wow64ReadProcessMemory64(g_proc_handle, heaps64[i], (PVOID)heap.data(), heap.size(), nullptr));

        auto flags = *(DWORD *)(heap.data() + scl::GetHeapFlagsOffset(true));
        auto force_flags = *(DWORD *)(heap.data() + scl::GetHeapForceFlagsOffset(true));

        if ((flags & bad_flags) || (force_flags & bad_flags))
            return ScyllaTestDetected;
    }

    return ScyllaTestOk;
}

static ScyllaTestResult Check_PEB_ProcessParameters()
{
    const auto peb = scl::GetPebAddress(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb);

    auto rupp = (scl::RTL_USER_PROCESS_PARAMETERS<DWORD_PTR> *)peb->ProcessParameters;

    return SCYLLA_TEST_CHECK((rupp->Flags & 0x4000) != 0);
}

static ScyllaTestResult Check_Wow64PEB64_ProcessParameters()
{
    const auto peb64 = scl::GetPebAddress(g_proc_handle);
    SCYLLA_TEST_FAIL_IF(!peb64);

    scl::RTL_USER_PROCESS_PARAMETERS<DWORD64> rupp{};

    SCYLLA_TEST_FAIL_IF(!scl::Wow64ReadProcessMemory64(g_proc_handle, (PVOID64)peb64->ProcessParameters, (PVOID)&rupp, sizeof(rupp), nullptr));

    return SCYLLA_TEST_CHECK((rupp.Flags & 0x4000) != 0);
}

static ScyllaTestResult Check_IsDebuggerPresent()
{
    return SCYLLA_TEST_CHECK(!IsDebuggerPresent());
}

static ScyllaTestResult Check_CheckRemoteDebuggerPresent()
{
    BOOL present;
    CheckRemoteDebuggerPresent(g_proc_handle, &present);
    return SCYLLA_TEST_CHECK(!present);
}

static ScyllaTestResult Check_OutputDebugStringA_LastError()
{
    const DWORD last_error = 0xDEAD;
    SetLastError(last_error);
    OutputDebugStringA("test");
    return SCYLLA_TEST_CHECK(GetLastError() != last_error);
}

static ScyllaTestResult Check_OutputDebugStringA_Exception()
{
    char text[] = "test";
    ULONG_PTR args[2];
    args[0] = (ULONG_PTR)strlen(text) + 1;
    args[1] = (ULONG_PTR)text;

    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 2, args);
        return ScyllaTestDetected;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return ScyllaTestOk;
    }
}

static ScyllaTestResult Check_OutputDebugStringW_Exception()
{
    wchar_t text_w[] = L"test";
    char text_a[_countof(text_w)] = { 0 };
    WideCharToMultiByte(CP_ACP, 0, text_w, -1, text_a, sizeof(text_a), nullptr, nullptr);

    ULONG_PTR args[4];

    args[0] = (ULONG_PTR)wcslen(text_w) + 1;
    args[1] = (ULONG_PTR)text_w;
    args[2] = (ULONG_PTR)strlen(text_a) + 1;
    args[3] = (ULONG_PTR)text_a;

    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, 4, args);
        return ScyllaTestDetected;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return ScyllaTestOk;
    }
}

static ScyllaTestResult Check_NtQueryInformationProcess_ProcessDebugPort()
{
    HANDLE handle = nullptr;
    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQueryInformationProcess(g_proc_handle, ProcessDebugPort, &handle, sizeof(handle), nullptr)));
    return SCYLLA_TEST_CHECK(handle == nullptr);
}

static ScyllaTestResult Check_NtQuerySystemInformation_KernelDebugger()
{
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SysKernDebInfo;

    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQuerySystemInformation(SystemKernelDebuggerInformation, &SysKernDebInfo, sizeof(SysKernDebInfo), NULL)));

    if (SysKernDebInfo.KernelDebuggerEnabled || !SysKernDebInfo.KernelDebuggerNotPresent)
    {
        return ScyllaTestDetected;
    }
    return ScyllaTestOk;
}

static ScyllaTestResult Check_NtQuery_OverlappingReturnLength() // https://github.com/x64dbg/ScyllaHide/issues/47
{
    UCHAR Buffer[sizeof(OBJECT_TYPE_INFORMATION) + 64];
    RtlZeroMemory(Buffer, sizeof(Buffer));
    PULONG pReturnLength = (PULONG)&Buffer[0];

    NTSTATUS Status = NtQueryInformationProcess(g_proc_handle, ProcessDebugObjectHandle, Buffer, sizeof(HANDLE), pReturnLength);
    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(Status) && Status != STATUS_PORT_NOT_SET);
    if (*pReturnLength != sizeof(HANDLE))
        return ScyllaTestDetected;

    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQuerySystemInformation(SystemKernelDebuggerInformation, Buffer, sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION), pReturnLength)));
    if (*pReturnLength != sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION))
        return ScyllaTestDetected;

    HANDLE DebugObjectHandle;
    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, nullptr, 0)));

    pReturnLength = (PULONG)(Buffer + FIELD_OFFSET(OBJECT_TYPE_INFORMATION, TotalNumberOfObjects)); // Where TotalNumberOfObjects would be
    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQueryObject(DebugObjectHandle, ObjectTypeInformation, Buffer, sizeof(Buffer), pReturnLength)));
    if (*pReturnLength < sizeof(OBJECT_TYPE_INFORMATION) + sizeof(ULONG))
        return ScyllaTestDetected;

    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtClose(DebugObjectHandle)));

    return ScyllaTestOk;
}

static ScyllaTestResult Check_NtClose()
{
    __try
    {
        NtClose((HANDLE)(ULONG_PTR)0x1337);
        return ScyllaTestOk;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode() == EXCEPTION_INVALID_HANDLE
            ? ScyllaTestDetected
            : ScyllaTestFail;
    }
}

static ScyllaTestResult Check_OtherOperationCount() // https://everdox.blogspot.com/2013/11/debugger-detection-with.html
{
    // Open some file
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING ntdllPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
    OBJECT_ATTRIBUTES objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES((PUNICODE_STRING)&ntdllPath, OBJ_CASE_INSENSITIVE);
    HANDLE fileHandle;
    NTSTATUS status = NtCreateFile(&fileHandle,
                                SYNCHRONIZE | FILE_EXECUTE,
                                &objectAttributes,
                                &ioStatusBlock,
                                nullptr,
                                FILE_ATTRIBUTE_NORMAL,
                                FILE_SHARE_READ,
                                FILE_OPEN,
                                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                nullptr,
                                0);
    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(status));

    // Create section. Must be SEC_IMAGE, not SEC_COMMIT
    HANDLE SectionHandle;
    status = NtCreateSection(&SectionHandle,
                            SECTION_MAP_EXECUTE,
                            nullptr,
                            nullptr,
                            PAGE_EXECUTE,
                            SEC_IMAGE,
                            fileHandle);
    NtClose(fileHandle);
    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(status));

    // Query other operation count (first go)
    ULONGLONG otherOperationCountBefore;
    status = GetOtherOperationCount(&otherOperationCountBefore);
    if (!NT_SUCCESS(status))
    {
        NtClose(SectionHandle);
        return status == STATUS_DATA_NOT_ACCEPTED
            ? ScyllaTestDetected
            : ScyllaTestFail;
    }

    // Map a view of the section
    PVOID baseAddress = nullptr;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(SectionHandle,
                                g_proc_handle,
                                &baseAddress,
                                0, 
                                0,
                                nullptr,
                                &viewSize,
                                ViewUnmap,
                                0,
                                PAGE_EXECUTE);
    NtClose(SectionHandle);
    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(status));

    // Query other operation count (second go)
    ULONGLONG otherOperationCountAfter;
    status = GetOtherOperationCount(&otherOperationCountAfter);

    NtUnmapViewOfSection(g_proc_handle, baseAddress);

    if (!NT_SUCCESS(status))
    {
        return status == STATUS_DATA_NOT_ACCEPTED
            ? ScyllaTestDetected
            : ScyllaTestFail;
    }

    // If the other operation count was incremented, the image was mapped into a debugger
    return otherOperationCountAfter > otherOperationCountBefore
        ? ScyllaTestDetected
        : ScyllaTestOk;
}

static void PrintScyllaTestResult(ScyllaTestResult result, ULONG charsPrinted)
{
    // Neither stdout nor GetStdHandle() work and I cba with this kernel32/CRT shit anymore. Pay me
    const HANDLE stdOut = NtCurrentPeb()->ProcessParameters->StandardOutput;
    CONSOLE_SCREEN_BUFFER_INFO consoleBufferInfo = { sizeof(CONSOLE_SCREEN_BUFFER_INFO) };
    GetConsoleScreenBufferInfo(stdOut, &consoleBufferInfo);
    const USHORT defaultColours = consoleBufferInfo.wAttributes;

    const ULONG pad = charsPrinted <= 48 ? 48 - charsPrinted : 0;
    for (ULONG i = 0; i < pad; ++i)
        printf(" ");

    switch (result)
    {
    case ScyllaTestOk:
    {
        SetConsoleTextAttribute(stdOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("OK\n");
        break;
    }
    case ScyllaTestFail:
    {
        SetConsoleTextAttribute(stdOut, FOREGROUND_RED | BACKGROUND_BLUE | FOREGROUND_INTENSITY);
        printf("FAIL\n");
        break;
    }
    case ScyllaTestDetected:
    {
        SetConsoleTextAttribute(stdOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("DETECTED\n");
        break;
    }
    case ScyllaTestSkip:
    {
        SetConsoleTextAttribute(stdOut, FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("SKIP\n");
        break;
    }
    default:
        printf("UNKNOWN\n");
        break;
    }
    SetConsoleTextAttribute(stdOut, defaultColours);
}

static bool OpenConsole()
{
    if (!AllocConsole())
    {
        auto text = L"Failed to allocate console: " + scl::FormatMessageW(GetLastError());
        MessageBoxW(HWND_DESKTOP, text.c_str(), L"Error", MB_ICONERROR);
        return false;
    }

    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
        return false;

    return true;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    if (!OpenConsole())
        return -1;

    g_proc_handle = GetRealCurrentProcess();
    if (g_proc_handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Failed to obtain real process handle.\n");
        return -1;
    }

    auto ver = scl::GetWindowsVersion();
    if (ver < scl::OS_WIN_XP)
    {
        fprintf(stderr, "Unsupported OS version.\n");
        return -1;
    }
    
    WCHAR title[64];
    _snwprintf_s(title, sizeof(title), L"[ScyllaTest] PID: %u", (ULONG)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess);
    SetConsoleTitleW(title);

    auto is_wow64 = scl::IsWow64Process(g_proc_handle);
    if (!NT_SUCCESS(NtCreateEvent(&g_stopEvent, EVENT_ALL_ACCESS, nullptr, NotificationEvent, FALSE)))
        return -1;

#define SCYLLA_TEST_IF(condition, x)      \
    { ULONG n = printf("%s: ", #x);          \
    if (!(condition)) { PrintScyllaTestResult(ScyllaTestSkip, n); } \
    else { auto ret = Check_ ## x(); PrintScyllaTestResult(ret, n); } }
#define SCYLLA_TEST(x) SCYLLA_TEST_IF(true, x)

    printf("Starting test loop. Press CTRL+C or the power button on your PC to exit.\n\n");
    while (true)
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -1LL * 10000LL * 1500LL; // 1500 ms
        if (NtWaitForSingleObject(g_stopEvent, FALSE, &timeout) != STATUS_TIMEOUT)
            break;

        printf("--------------------\n");

        SCYLLA_TEST(PEB_BeingDebugged);
        SCYLLA_TEST_IF(is_wow64, Wow64PEB64_BeingDebugged);
        SCYLLA_TEST(PEB_NtGlobalFlag);
        SCYLLA_TEST_IF(is_wow64, Wow64PEB64_NtGlobalFlag);
        SCYLLA_TEST(PEB_HeapFlags);
        SCYLLA_TEST_IF(is_wow64, Wow64PEB64_HeapFlags);
        SCYLLA_TEST(PEB_ProcessParameters);
        SCYLLA_TEST_IF(is_wow64, Wow64PEB64_ProcessParameters);
        SCYLLA_TEST(IsDebuggerPresent);
        SCYLLA_TEST(CheckRemoteDebuggerPresent);
        SCYLLA_TEST_IF(ver < scl::OS_WIN_VISTA, OutputDebugStringA_LastError);
        SCYLLA_TEST(OutputDebugStringA_Exception);
        SCYLLA_TEST_IF(ver >= scl::OS_WIN_10, OutputDebugStringW_Exception);
        SCYLLA_TEST(NtQueryInformationProcess_ProcessDebugPort);
        SCYLLA_TEST(NtQuerySystemInformation_KernelDebugger);
        SCYLLA_TEST(NtQuery_OverlappingReturnLength);
        SCYLLA_TEST(NtClose);
        SCYLLA_TEST_IF(ver >= scl::OS_WIN_VISTA, OtherOperationCount);

        printf("--------------------\n\n");
    }

    NtClose(g_stopEvent);
    NtClose(g_proc_handle);
    SetConsoleCtrlHandler(nullptr, FALSE);
    FreeConsole();
    return 0;
}
