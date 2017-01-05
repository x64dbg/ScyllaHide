#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace Scylla
{
    std::wstring format_wstring(const wchar_t *fmt, ...);
    std::wstring vformat_wstring(const wchar_t *fmt, va_list ap);

    std::wstring GetModuleFileNameW(HMODULE hModule = nullptr);

    std::wstring FormatMessageW(DWORD dwErrnum);

    std::wstring GetWindowTextW(HWND hWnd);
    std::wstring GetDlgItemTextW(HWND hDlg, int nIDDlgItem);

    bool FileExistsW(const wchar_t *wszPath);

    std::vector<std::wstring> GetPrivateProfileSectionNamesW(const wchar_t *wszIniFile);
    std::wstring GetPrivateProfileStringW(const wchar_t *wszProfile, const wchar_t *wszKey, const wchar_t *wszDefaultValue, const wchar_t *wszIniFile);
    bool WritePrivateProfileIntW(const wchar_t *wszProfile, const wchar_t *wszKey, int nValue, const wchar_t *wszIniFile);
};
