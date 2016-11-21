#include "Util.h"
#include <cstdio>
#include <memory>

std::wstring Scylla::format_wstring(const wchar_t *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    auto str = vformat_wstring(fmt, ap);
    va_end(ap);

    return str;
}

std::wstring Scylla::vformat_wstring(const wchar_t *fmt, va_list ap)
{
    va_list vap;

    va_copy(vap, ap);
    auto size = _vsnwprintf(nullptr, 0, fmt, vap);
    va_end(vap);

    std::wstring wstr;
    wstr.resize(size + 1);

    va_copy(vap, ap);
    _vsnwprintf(&wstr[0], wstr.size(), fmt, vap);
    va_end(vap);

    return wstr;
}

std::wstring Scylla::GetModuleFileNameW(HMODULE hModule)
{
    std::wstring wstrFileName;
    DWORD copied = 0;
    do {
        wstrFileName.resize(wstrFileName.size() + MAX_PATH);
        copied = ::GetModuleFileNameW(0, &wstrFileName[0], (DWORD)wstrFileName.size());
    } while (copied >= wstrFileName.size());

    wstrFileName.resize(copied);
    return wstrFileName;
}

std::wstring Scylla::FormatMessageW(DWORD dwErrnum)
{
    wchar_t *wszBuffer = nullptr;

    ::FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, dwErrnum, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPWSTR)&wszBuffer, 0, nullptr);

    std::wstring wstrError;
    if (wszBuffer) {
        wstrError = wszBuffer;
        wstrError.resize(wstrError.size() - 1); // remove trailing \n
        LocalFree(wszBuffer);
    }
    else
    {
        wstrError = L"<FAILED TO RETRIEVE ERROR STRING>";
    }

    return wstrError;
}