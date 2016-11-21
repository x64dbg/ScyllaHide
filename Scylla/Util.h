#pragma once

#include <Windows.h>
#include <string>

namespace Scylla
{
    std::wstring format_wstring(const wchar_t *fmt, ...);
    std::wstring vformat_wstring(const wchar_t *fmt, va_list ap);
    std::wstring GetModuleFileNameW(HMODULE hModule = nullptr);
    std::wstring FormatMessageW(DWORD dwErrnum);
};