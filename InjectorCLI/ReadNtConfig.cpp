#include "ReadNtConfig.h"
#include <Scylla/OsInfo.h>
#include <Scylla/Util.h>



bool ReadNtApiInformation(const wchar_t *szFilePath, HOOK_DLL_EXCHANGE *pDllExchangeLoader)
{
    const auto osVerInfo = Scylla::GetVersionExW();
    const auto osSysInfo = Scylla::GetNativeSystemInfo();

    auto hUser = GetModuleHandleW(L"user32.dll");
    auto pDosUser = (PIMAGE_DOS_HEADER)hUser;
    auto pNtUser = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosUser + pDosUser->e_lfanew);

    if (pNtUser->Signature != IMAGE_NT_SIGNATURE)
    {
        MessageBoxW(HWND_DESKTOP, L"Wrong user32.dll IMAGE_NT_SIGNATURE", L"ERROR", MB_ICONERROR);
        return false;
    }

#ifdef _WIN64
    const wchar_t wszArch[] = L"x64";
#else
    const wchar_t wszArch[] = L"x86";
#endif

    auto wstrSection = Scylla::format_wstring(L"%02X%02X%02X%02X%02X%02X_%s_%08X",
        osVerInfo->dwMajorVersion, osVerInfo->dwMinorVersion,
        osVerInfo->wServicePackMajor, osVerInfo->wServicePackMinor,
        osVerInfo->wProductType, osSysInfo->wProcessorArchitecture, wszArch,
        pNtUser->OptionalHeader.AddressOfEntryPoint);

    pDllExchangeLoader->NtUserBuildHwndListRVA = Scylla::IniLoadNum<16>(szFilePath, wstrSection.c_str(), L"NtUserBuildHwndList", 0);
    pDllExchangeLoader->NtUserFindWindowExRVA = Scylla::IniLoadNum<16>(szFilePath, wstrSection.c_str(), L"NtUserFindWindowEx", 0);
    pDllExchangeLoader->NtUserQueryWindowRVA = Scylla::IniLoadNum<16>(szFilePath, wstrSection.c_str(), L"NtUserQueryWindow", 0);

    if (!pDllExchangeLoader->NtUserBuildHwndListRVA || !pDllExchangeLoader->NtUserFindWindowExRVA || !pDllExchangeLoader->NtUserQueryWindowRVA)
    {
        auto strMessage = Scylla::format_wstring(
            L"NtUser* API Addresses missing!\r\n"
            L"File: %s\r\n"
            L"Section: %s\r\n"
            L"\r\n"
            L"Please read the documentation to fix this problem! https://bitbucket.org/NtQuery/scyllahide/downloads/ScyllaHide.pdf",
            szFilePath, wstrSection.c_str());
        MessageBoxW(HWND_DESKTOP, strMessage.c_str(), L"ERROR", MB_ICONERROR);
        return false;
    }

    return true;
}
