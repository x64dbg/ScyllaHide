#include <Windows.h>
#include <cstdio>
#include <Scylla/OsInfo.h>
#include <Scylla/Peb.h>
#include <Scylla/Util.h>

#ifndef DBG_PRINTEXCEPTION_WIDE_C
#define DBG_PRINTEXCEPTION_WIDE_C ((DWORD)0x4001000A)
#endif

#define ANTI_TEST(x, stmt)             \
    printf("Check %s...\t", #x);       \
    if (!(stmt)) printf("SKIP\n"); else if (!Check_ ## x()) printf("FAIL!\n"); else printf("OK!\n");

static bool Check_CheckRemoteDebuggerPresent()
{
    BOOL present;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return !present;
}

static bool Check_IsDebuggerPresent()
{
    return !IsDebuggerPresent();
}

static bool Check_IsDebuggerPresent_PEB()
{
    const auto peb = scl::GetPebAddress(GetCurrentProcess());
    return peb->BeingDebugged == 0;
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


    ANTI_TEST(IsDebuggerPresent, true);
    ANTI_TEST(IsDebuggerPresent_PEB, true);
    ANTI_TEST(CheckRemoteDebuggerPresent, true);
    ANTI_TEST(OutputDebugStringA_LastError, ver < scl::OS_WIN_VISTA);
    ANTI_TEST(OutputDebugStringA_Exception, true);
    ANTI_TEST(OutputDebugStringW_Exception, ver >= scl::OS_WIN_10);

    getchar();
    return 0;
}
