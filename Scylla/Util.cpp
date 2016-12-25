#include "Util.h"
#include <cstdio>

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
    auto size = ::_vsnwprintf(nullptr, 0, fmt, vap);
    va_end(vap);

    std::wstring wstr;
    wstr.resize(size + 1);

    va_copy(vap, ap);
    ::_vsnwprintf(&wstr[0], wstr.size(), fmt, vap);
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
        ::LocalFree(wszBuffer);
    }
    else
    {
        wstrError = L"<FAILED TO RETRIEVE ERROR STRING>";
    }

    return wstrError;
}

std::wstring Scylla::GetWindowTextW(HWND hWnd)
{
    std::wstring wstr;
    auto len = ::GetWindowTextLengthW(hWnd) + 1;
    wstr.resize(len);
    ::GetWindowTextW(hWnd, &wstr[0], len);
    return wstr;
}

std::wstring Scylla::GetDlgItemTextW(HWND hDlg, int nIDDlgItem)
{
    return GetWindowTextW(::GetDlgItem(hDlg, nIDDlgItem));
}

bool Scylla::FileExistsW(const wchar_t *wszPath)
{
    auto dwAttrib = ::GetFileAttributesW(wszPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

std::vector<std::wstring> Scylla::GetPrivateProfileSectionNamesW(const wchar_t *wszIniFile)
{
    std::wstring buf;
    DWORD ret = 0;
    while (((DWORD)buf.size() - ret) < 3) {
        buf.resize(buf.size() + MAX_PATH);
        ret = ::GetPrivateProfileSectionNamesW(&buf[0], (DWORD)buf.size(), wszIniFile);
    }

    std::vector<std::wstring> sections;
    auto data = buf.c_str();
    for (; data[0]; data += lstrlenW(data) + 1) {
        sections.push_back(data);
    }

    return sections;
}

std::wstring Scylla::GetPrivateProfileStringW(const wchar_t *wszProfile, const wchar_t *wszKey, const wchar_t *wszDefaultValue, const wchar_t *wszIniFile)
{
    std::wstring buf;
    DWORD ret = 0;

    while (((DWORD)buf.size() - ret) < 3) {
        buf.resize(buf.size() + MAX_PATH);
        ret = ::GetPrivateProfileStringW(wszProfile, wszKey, wszDefaultValue, &buf[0], (DWORD)buf.size(), wszIniFile);
    }
    buf.resize(ret);

    return buf;
}

bool Scylla::WritePrivateProfileIntW(const wchar_t *wszProfile, const wchar_t *wszKey, int nValue, const wchar_t *wszIniFile)
{
    auto strValue = format_wstring(L"%d", nValue);
    return WritePrivateProfileStringW(wszProfile, wszKey, strValue.c_str(), wszIniFile) == TRUE;
}