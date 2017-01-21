#include "NtApiLoader.h"
#include "dbghelp.h"

#include "OsInfo.h"
#include "Util.h"

const wchar_t scl::NtApiLoader::kFileName[] = L"NtApiCollection.ini";

const std::map<std::wstring, std::vector<std::wstring>> scl::NtApiLoader::fun_names_{
    {
        L"user32.dll",
        { L"NtUserQueryWindow", L"NtUserBuildHwndList", L"NtUserFindWindowEx" }
    }
};

std::wstring scl::NtApiLoader::GetOsId() const
{
    const auto osVerInfo = GetVersionExW();
    const auto osSysInfo = GetNativeSystemInfo();

#ifdef _WIN64
    const wchar_t wszArch[] = L"x64";
#else
    const wchar_t wszArch[] = L"x86";
#endif

    return fmtw(L"%x.%x.%x.%x.%x.%x.%s",
        osVerInfo->dwMajorVersion, osVerInfo->dwMinorVersion,
        osVerInfo->wServicePackMajor, osVerInfo->wServicePackMinor,
        osVerInfo->wProductType, osSysInfo->wProcessorArchitecture, wszArch);
}

bool scl::NtApiLoader::InitSymServ(const wchar_t *symbols_path, log_callback log_cb)
{
    auto hProc = ::GetCurrentProcess();

    ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED | SYMOPT_DEBUG);
    if (!::SymInitializeW(hProc, symbols_path, TRUE))
        return false;

    return ::SymRegisterCallbackW64(hProc, SymServCallbackLogger, (ULONG64)log_cb) == TRUE;
}

BOOL CALLBACK scl::NtApiLoader::SymServCallbackLogger(HANDLE hProcess, ULONG uActionCode, ULONG64 pCallbackData, ULONG64 pUserContext)
{
    auto log_cb = (log_callback *)pUserContext;

    switch (uActionCode)
    {
    case CBA_EVENT: {
        auto evt = (PIMAGEHLP_CBA_EVENT)pCallbackData;
        if (log_cb)
            log_cb((const wchar_t *)evt->desc);
        return TRUE;
    }

    case CBA_DEBUG_INFO:
        if (log_cb)
            log_cb((const wchar_t *)pCallbackData);
        return TRUE;

    default:
        return FALSE;
    }
}

ULONG64 scl::NtApiLoader::GetSymbolAddressFromPDB(HMODULE hModule, const wchar_t *symbol_name)
{
    static ULONG64 buffer[(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t) + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
    auto pSymbol = (SYMBOL_INFOW *)buffer;

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    pSymbol->ModBase = (ULONG64)hModule;

    if (!::SymFromNameW(::GetCurrentProcess(), symbol_name, pSymbol))
        return 0;

    return pSymbol->Address;
}

std::pair<bool, std::wstring> scl::NtApiLoader::Resolve(log_callback log_cb)
{
    // Load all libraries before InitSymServ()
    for (auto dll : fun_names_)
    {
        if (!::LoadLibraryW(dll.first.c_str()))
            return std::make_pair(false, fmtw(L"Failed to load library %s: %s", dll.first.c_str(), FormatMessageW(::GetLastError()).c_str()));
    }

    auto curr_path = GetModuleFileNameW();
    curr_path.resize(curr_path.find_last_of(L"\\"));

    auto symbols_path = scl::fmtw(L"srv*%s*http://msdl.microsoft.com/download/symbols", curr_path.c_str());

    if (!InitSymServ(symbols_path.c_str(), log_cb))
        return std::make_pair(false, fmtw(L"Failed to initialize symbol server API: %s\n", FormatMessageW(::GetLastError()).c_str()));

    for (auto dll : fun_names_)
    {
        for (auto fun_name : dll.second)
        {
            auto hDll = ::GetModuleHandleW(dll.first.c_str());
            auto fun_va = GetSymbolAddressFromPDB(hDll, fun_name.c_str());

            if (!fun_va)
            {
                if (log_cb != nullptr)
                {
                    auto msg = fmtw(L"Failed to get VA for %s: %s\n", fun_name.c_str(), FormatMessageW(::GetLastError()).c_str());
                    log_cb(msg.c_str());
                }
                fun_rvas_[dll.first][fun_name] = 0;

            }
            else
            {
                fun_rvas_[dll.first][fun_name] = fun_va - (ULONG64)hDll;
            }
        }
    }

    ::SymCleanup(::GetCurrentProcess());

    return std::make_pair(true, L"");
}

std::pair<bool, std::wstring> scl::NtApiLoader::Save(const wchar_t *file) const
{
    const auto os_id = GetOsId();

    for (auto dll : fun_rvas_)
    {
        auto pDllDos = (IMAGE_DOS_HEADER *)::LoadLibraryW(dll.first.c_str());
        if (!pDllDos)
            return std::make_pair(false, fmtw(L"Failed to load library %s: %s", dll.first.c_str(), FormatMessageW(::GetLastError()).c_str()));

        auto pDllNt = (IMAGE_NT_HEADERS *)((DWORD_PTR)pDllDos + pDllDos->e_lfanew);
        if (pDllNt->Signature != IMAGE_NT_SIGNATURE)
            return std::make_pair(false, fmtw(L"Invalid %s NT Header", dll.first.c_str()));

        for (auto fun_rva : dll.second)
        {
            auto key = fmtw(L"%s!%x!%s", dll.first.c_str(), pDllNt->OptionalHeader.AddressOfEntryPoint, fun_rva.first.c_str());
            if (!IniSaveNum<16>(file, os_id.c_str(), key.c_str(), fun_rva.second))
                return std::make_pair(false, fmtw(L"Failed to write to ini file %s: %s", file, FormatMessageW(::GetLastError())));
        }
    }

    return std::make_pair(true, L"");
}

std::pair<bool, std::wstring> scl::NtApiLoader::Load(const wchar_t *file)
{
    const auto os_id = GetOsId();

    for (auto dll : fun_names_)
    {
        auto pDllDos = (IMAGE_DOS_HEADER *)::LoadLibraryW(dll.first.c_str());
        if (!pDllDos)
            return std::make_pair(false, fmtw(L"Failed to load library %s: %s", dll.first.c_str(), FormatMessageW(::GetLastError()).c_str()));

        auto pDllNt = (IMAGE_NT_HEADERS *)((DWORD_PTR)pDllDos + pDllDos->e_lfanew);
        if (pDllNt->Signature != IMAGE_NT_SIGNATURE)
            return std::make_pair(false, fmtw(L"Invalid %s NT Header", dll.first.c_str()));

        for (auto fun_name : dll.second)
        {
            auto key = fmtw(L"%s!%x!%s", dll.first.c_str(), pDllNt->OptionalHeader.AddressOfEntryPoint, fun_name.c_str());
            fun_rvas_[dll.first][fun_name] = IniLoadNum<16>(file, os_id.c_str(), key.c_str(), (ULONG64)0);
        }
    }

    return std::make_pair(true, L"");
}
