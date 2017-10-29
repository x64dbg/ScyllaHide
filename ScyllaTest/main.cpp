#include <Windows.h>
#include <cstdio>
#include <string>
#include <Scylla/NtApiShim.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Peb.h>
#include <Scylla/Util.h>

enum ScyllaTestResult
{
    ScyllaTestOk = 0,
    ScyllaTestFail,
    ScyllaTestDetected
};

#define SCYLLA_TEST_FAIL_IF(x) if (x) return ScyllaTestFail;
#define SCYLLA_TEST_CHECK(x) ((x) ? ScyllaTestOk : ScyllaTestDetected);

#ifdef _WIN64
const bool is_x64 = true;
#else
const bool is_x64 = false;
#endif

static HANDLE g_proc_handle;

static HANDLE GetRealCurrentProcess()
{
    auto pseudo_handle = GetCurrentProcess();
    auto hRealHandle = INVALID_HANDLE_VALUE;
    DuplicateHandle(pseudo_handle, pseudo_handle, pseudo_handle, &hRealHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
    return hRealHandle;
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

    scl::RTL_USER_PROCESS_PARAMETERS<DWORD64> rupp;

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
    auto last_error = 0xDEAD;
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

static const char *ScyllaTestResultAsStr(ScyllaTestResult result)
{
    switch (result)
    {
    case ScyllaTestOk:
        return "OK";
    case ScyllaTestFail:
        return "FAIL";
    case ScyllaTestDetected:
        return "DETECTED";
    default:
        return "UNKNOWN";
    }
}

static ScyllaTestResult Check_NtQuerySystemInformation_SystemKernelDebuggerInformation()
{
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SysKernDebInfo;

    SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQuerySystemInformation(SystemKernelDebuggerInformation, &SysKernDebInfo, sizeof(SysKernDebInfo), NULL)));

    if (SysKernDebInfo.KernelDebuggerEnabled || !SysKernDebInfo.KernelDebuggerNotPresent)
    {
        return ScyllaTestDetected;
    }
    return ScyllaTestOk;
}

static bool isExeDetected(const std::wstring& exe)
{
    // TODO: merge it together with the list used inside the core?
	static const std::wstring exeToDetect[] = {
		// OllyDbg v1/2
		L"ollydbg.exe",
		// IDA Pro v5/6
		L"idaq.exe",
		L"idaq64.exe",
		// IDA Pro v7+
		L"ida.exe",
		L"ida64.exe",
        L"idat.exe",
        L"idat64.exe",
		// x32/64Dbg
		L"x32dbg.exe",
		L"x64dbg.exe"

		// add more before this mark
	};

	for (auto item : exeToDetect)
	{
		if (item == exe) //TODO: case-insensitive
			return true;
	}
	return false;
}

ScyllaTestResult walkProcessList(PSYSTEM_PROCESS_INFORMATION pinfo)
{
	ScyllaTestResult result = ScyllaTestOk;

	// iterate over all the process entries
	while (pinfo->NextEntryOffset)
	{
		//printf("\nProcess name: %ws | Process ID: %d\n", pinfo->ImageName.Buffer, (int)pinfo->UniqueProcessId);
		const std::wstring processName = pinfo->ImageName.Buffer ? pinfo->ImageName.Buffer : L"";
		if (isExeDetected(processName))
		{
			result = ScyllaTestDetected;
			break;
		}
		// jump to next entry. 
		// NextEntryOffset has variable length due to differnt number of threads, etc
		pinfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pinfo + pinfo->NextEntryOffset);
	}
	return result;
}

static ScyllaTestResult _NtQuerySystemInformation_SystemProcessInformation(SYSTEM_INFORMATION_CLASS sysInfoClass)
{
	ScyllaTestResult result = ScyllaTestOk;
	PSYSTEM_PROCESS_INFORMATION pinfo;
	ULONG returnLength;

	// expecting fail here, so testing for success, strange but true
	SCYLLA_TEST_FAIL_IF(NT_SUCCESS(NtQuerySystemInformation(sysInfoClass, NULL, NULL, &returnLength)));
	
	PVOID buffer = malloc(returnLength);

	pinfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQuerySystemInformation(sysInfoClass, pinfo, returnLength, NULL)));

	result = walkProcessList(pinfo);

    //TODO: think about better alloc/free strategy in case when we exit before this line
	free(buffer);

	return result;
}

static ScyllaTestResult Check_NtQuerySystemInformation_SystemProcessInformation()
{
	return _NtQuerySystemInformation_SystemProcessInformation(SystemProcessInformation);
}

static ScyllaTestResult Check_NtQuerySystemInformation_SystemExtendedProcessInformation()
{
	return _NtQuerySystemInformation_SystemProcessInformation(SystemExtendedProcessInformation);
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

    auto is_wow64 = scl::IsWow64Process(g_proc_handle);

#define SCYLLA_TEST_IF(condition, x)      \
    printf("Check %s...\t", #x);          \
    if (!(condition)) { printf("SKIP\n"); } else { auto ret = Check_ ## x(); printf("%s\n", ScyllaTestResultAsStr(ret)); }
#define SCYLLA_TEST(x) SCYLLA_TEST_IF(true, x)

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
    SCYLLA_TEST(NtQuerySystemInformation_SystemKernelDebuggerInformation);
	SCYLLA_TEST(NtQuerySystemInformation_SystemProcessInformation);
	SCYLLA_TEST(NtQuerySystemInformation_SystemExtendedProcessInformation);

    CloseHandle(g_proc_handle);
    g_proc_handle = INVALID_HANDLE_VALUE;

    getchar();
    return 0;
}
