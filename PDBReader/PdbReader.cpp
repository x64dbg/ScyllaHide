#include <Windows.h>
#include <cstdio>
#include <Scylla/DbgHelp.h>
#include <Scylla/Util.h>
#include <Scylla/OsInfo.h>

static const wchar_t *wszFunctionNames[] = {
    L"NtUserQueryWindow",
    L"NtUserBuildHwndList",
    L"NtUserFindWindowEx",
    L"NtUserInternalGetWindowText",
    L"NtUserGetClassName"
};

static ULONG64 GetFunctionAddressPDB(HMODULE hModule, const wchar_t *wszSymbolName)
{
    static ULONG64 buffer[(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t) + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
    auto pSymbol = (PSYMBOL_INFOW)buffer;

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    pSymbol->ModBase = (ULONG64)hModule;

    if (!SymFromNameW(GetCurrentProcess(), wszSymbolName, pSymbol))
    {
        return 0;
    }

    return pSymbol->Address;
}

static BOOL CALLBACK SymServCallbackLogger(HANDLE hProcess, ULONG uActionCode, ULONG64 pCallbackData, ULONG64 pUserContext)
{
    switch (uActionCode)
    {
    case CBA_EVENT: {
        auto evt = (PIMAGEHLP_CBA_EVENT)pCallbackData;
        wprintf(L"%s", (const wchar_t *)evt->desc);
        return TRUE;
    }
    case CBA_DEBUG_INFO:
        wprintf(L"%s", (const wchar_t *)pCallbackData);
        return TRUE;
    default:
        return FALSE;
    }
}

static bool InitSymServ(const wchar_t *wszSymbolPath)
{
    auto hProc = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED | SYMOPT_DEBUG);
    if (SymInitializeW(hProc, wszSymbolPath, TRUE)) {
        return SymRegisterCallbackW64(hProc, SymServCallbackLogger, 0) == TRUE;
    }

    return false;
}

int wmain(int argc, wchar_t* argv[])
{
    const auto osVerInfo = Scylla::GetVersionExW();
    const auto osSysInfo = Scylla::GetNativeSystemInfo();

    auto wstrPath = Scylla::GetModuleFileNameW();
    wstrPath.resize(wstrPath.find_last_of(L"\\"));

    auto wstrIniFile = wstrPath + L"\\NtApiCollection.ini";
    auto wstrSymbolPath = Scylla::format_wstring(L"srv*%s*http://msdl.microsoft.com/download/symbols", wstrPath.c_str());

    // Must be called before InitSymServ()
    auto hUser32 = LoadLibraryW(L"user32.dll");
    if (!hUser32)
    {
        fwprintf(stderr, L"Failed to get user32.dll module handle: %s\n", Scylla::FormatMessageW(GetLastError()).c_str());
        return EXIT_FAILURE;
    }

    if (!InitSymServ(wstrSymbolPath.c_str()))
    {
        fwprintf(stderr, L"Failed to initialize symbol server API: %s\n", Scylla::FormatMessageW(GetLastError()).c_str());
        return EXIT_FAILURE;
    }

#ifdef _WIN64
    const wchar_t wszArch[] = L"x64";
#else
    const wchar_t wszArch[] = L"x86";
#endif

    auto wstrOsId = Scylla::format_wstring(L"%02X%02X%02X%02X%02X%02X_%s",
        osVerInfo->dwMajorVersion, osVerInfo->dwMinorVersion,
        osVerInfo->wServicePackMajor, osVerInfo->wServicePackMinor,
        osVerInfo->wProductType, osSysInfo->wProcessorArchitecture, wszArch);

    wprintf(L"OS MajorVersion %u MinorVersion %u\n", osVerInfo->dwMajorVersion, osVerInfo->dwMinorVersion);
    wprintf(L"OS ID: %s\n", wstrOsId.c_str());

    auto pDosUser = (PIMAGE_DOS_HEADER)hUser32;
    auto pNtUser = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosUser + pDosUser->e_lfanew);
    if (pNtUser->Signature != IMAGE_NT_SIGNATURE)
    {
        fwprintf(stderr, L"Invalid User32.dll NT Header\n");
        return EXIT_FAILURE;
    }

    wprintf(L"User32 Base 0x%p\nFetching symbols...\n", hUser32);

    auto wstrIniSection = Scylla::format_wstring(L"%s_%08X", wstrOsId.c_str(), pNtUser->OptionalHeader.AddressOfEntryPoint);
    for (size_t i = 0; i < _countof(wszFunctionNames); i++)
    {
        auto ulFunctionVA = GetFunctionAddressPDB(hUser32, wszFunctionNames[i]);
        if (!ulFunctionVA)
        {
            fwprintf(stderr, L"Failed to get symbol info for %s: %s\n", wszFunctionNames[i], Scylla::FormatMessageW(GetLastError()).c_str());
            continue;
        }

        auto ulFunctionRVA = ulFunctionVA - (ULONG64)hUser32;
        auto wstrFunctionRva = Scylla::format_wstring(L"%08llX", ulFunctionRVA);
        wprintf(L"Name %s VA 0x%p RVA 0x%08llX\n", wszFunctionNames[i], (void *)ulFunctionVA, ulFunctionRVA);
        WritePrivateProfileStringW(wstrIniSection.c_str(), wszFunctionNames[i], wstrFunctionRva.c_str(), wstrIniFile.c_str());
    }

    SymCleanup(GetCurrentProcess());
    wprintf(L"Done!\n");
    getchar();
    return EXIT_SUCCESS;
}
