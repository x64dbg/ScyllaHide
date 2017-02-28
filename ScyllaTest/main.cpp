#include <Windows.h>
#include <cstdio>
#include <Scylla/NtApiShim.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Peb.h>
#include <Scylla/Util.h>

#ifndef DBG_PRINTEXCEPTION_WIDE_C
#define DBG_PRINTEXCEPTION_WIDE_C ((DWORD)0x4001000A)
#endif

#define ANTI_TEST(x, stmt)             \
    printf("Check %s...\t", #x);       \
    if (!(stmt)) printf("SKIP\n"); else if (!Check_ ## x()) printf("FAIL!\n"); else printf("OK!\n");

static bool Check_PEB_BeingDebugged()
{
    const auto peb = scl::GetPebAddress(GetCurrentProcess());
    if (peb->BeingDebugged)
        return false;

#ifndef _WIN64
    if (scl::IsWow64Process(GetCurrentProcess()))
    {
        const auto peb64 = scl::GetPeb64Address(GetCurrentProcess());
        if (!peb64 || peb64->BeingDebugged)
            return false;
    }
#endif

    return true;
}

static bool Check_PEB_NtGlobalFlag()
{
    const DWORD bad_flags = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;

    const auto peb = scl::GetPebAddress(GetCurrentProcess());
    if (peb->NtGlobalFlag & bad_flags)
        return false;

#ifndef _WIN64
    if (scl::IsWow64Process(GetCurrentProcess()))
    {
        const auto peb64 = scl::GetPeb64Address(GetCurrentProcess());
        if (!peb64 || (peb64->NtGlobalFlag & bad_flags))
            return false;
    }
#endif

    return true;
}

static bool Check_PEB_HeapFlags()
{
    const DWORD bad_flags = HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED;
#ifdef _WIN64
    const auto is_x64 = true;
#else
    const auto is_x64 = false;
#endif

    const auto peb = scl::GetPebAddress(GetCurrentProcess());

    auto heaps = (void **)peb->ProcessHeaps;
    for(DWORD i = 0; i < peb->NumberOfHeaps; i++)
    {
        auto flags = *(DWORD *)((BYTE *)heaps[i] + scl::GetHeapFlagsOffset(is_x64));
        auto force_flags = *(DWORD *)((BYTE *)heaps[i] + scl::GetHeapForceFlagsOffset(is_x64));

        if ((flags & bad_flags) || (force_flags & bad_flags))
            return false;
    }

#if 0
    if (scl::IsWow64Process(GetCurrentProcess()))
    {
        const auto peb64 = scl::GetPeb64Address(GetCurrentProcess());
        if (!peb64)
            return false;

        auto heaps64 = (DWORD64 *)peb64->ProcessHeaps;
        for (DWORD i = 0; i < peb->NumberOfHeaps; i++)
        {
            auto flags = *(DWORD *)((BYTE *)heaps64[i] + scl::GetHeapFlagsOffset(true));
            auto force_flags = *(DWORD *)((BYTE *)heaps64[i] + scl::GetHeapFlagsOffset(true));

            if ((flags & bad_flags) || (force_flags & bad_flags))
                return false;
        }
    }
#endif

    return true;
}

static bool Check_IsDebuggerPresent()
{
    return !IsDebuggerPresent();
}

static bool Check_CheckRemoteDebuggerPresent()
{
    BOOL present;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return !present;
}

static bool Check_OutputDebugStringA_LastError()
{
    auto last_error = 0xDEAD;
    SetLastError(last_error);
    OutputDebugStringA("test");
    return GetLastError() != last_error;
}

static bool Check_OutputDebugStringA_Exception()
{
    char text[] = "test";
    ULONG_PTR args[2];
    args[0] = (ULONG_PTR)strlen(text) + 1;
    args[1] = (ULONG_PTR)text;

    __try
    {
        RaiseException(DBG_PRINTEXCEPTION_C, 0, 2, args);
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
}

static bool Check_OutputDebugStringW_Exception()
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
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
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
        return 0;

    auto ver = scl::GetWindowsVersion();


    ANTI_TEST(PEB_BeingDebugged, true);
    ANTI_TEST(PEB_NtGlobalFlag, true);
    ANTI_TEST(PEB_HeapFlags, true);
    ANTI_TEST(IsDebuggerPresent, true);
    ANTI_TEST(CheckRemoteDebuggerPresent, true);
    ANTI_TEST(OutputDebugStringA_LastError, ver < scl::OS_WIN_VISTA);
    ANTI_TEST(OutputDebugStringA_Exception, true);
    ANTI_TEST(OutputDebugStringW_Exception, ver >= scl::OS_WIN_10);

    getchar();
    return 0;
}
