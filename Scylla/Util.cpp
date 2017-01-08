#include "Util.h"
#include <cstdio>

std::wstring scl::fmtw(const wchar_t *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    auto str = vfmtw(fmt, ap);
    va_end(ap);

    return str;
}

std::wstring scl::vfmtw(const wchar_t *fmt, va_list ap)
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

std::wstring scl::GetModuleFileNameW(HMODULE hModule)
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

std::wstring scl::FormatMessageW(DWORD dwErrnum)
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

std::wstring scl::GetWindowTextW(HWND hWnd)
{
    std::wstring wstr;
    auto len = ::GetWindowTextLengthW(hWnd) + 1;
    wstr.resize(len);
    ::GetWindowTextW(hWnd, &wstr[0], len);
    return wstr;
}

std::wstring scl::GetDlgItemTextW(HWND hDlg, int nIDDlgItem)
{
    return GetWindowTextW(::GetDlgItem(hDlg, nIDDlgItem));
}

bool scl::FileExistsW(const wchar_t *wszPath)
{
    auto dwAttrib = ::GetFileAttributesW(wszPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

bool scl::GetFileDialogW(wchar_t *buffer, DWORD buffer_size)
{
    OPENFILENAMEW sOpenFileName = { 0 };
    const wchar_t szFilterString[] = L"DLL \0*.dll\0\0";
    const wchar_t szDialogTitle[] = L"ScyllaHide";

    buffer[0] = 0;

    sOpenFileName.lStructSize = sizeof(sOpenFileName);
    sOpenFileName.lpstrFilter = szFilterString;
    sOpenFileName.lpstrFile = buffer;
    sOpenFileName.nMaxFile = buffer_size;
    sOpenFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_EXPLORER | OFN_HIDEREADONLY;
    sOpenFileName.lpstrTitle = szDialogTitle;

    return (TRUE == GetOpenFileNameW(&sOpenFileName));
}


std::vector<std::wstring> scl::IniLoadSectionNames(const wchar_t *file)
{
    std::wstring buf;
    DWORD ret = 0;
    while (((DWORD)buf.size() - ret) < 3) {
        buf.resize(buf.size() + MAX_PATH);
        ret = ::GetPrivateProfileSectionNamesW(&buf[0], (DWORD)buf.size(), file);
    }

    std::vector<std::wstring> sections;
    auto data = buf.c_str();
    for (; data[0]; data += lstrlenW(data) + 1) {
        sections.push_back(data);
    }

    return sections;
}

std::wstring scl::IniLoadString(const wchar_t *file, const wchar_t *section, const wchar_t *key, const wchar_t *default_value)
{
    std::wstring buf;
    DWORD ret = 0;

    while (((DWORD)buf.size() - ret) < 3) {
        buf.resize(buf.size() + MAX_PATH);
        ret = ::GetPrivateProfileStringW(section, key, default_value, &buf[0], (DWORD)buf.size(), file);
    }
    buf.resize(ret);

    return buf;
}

bool scl::IniSaveString(const wchar_t *file, const wchar_t *section, const wchar_t *key, const wchar_t *value)
{
    return WritePrivateProfileStringW(section, key, value, file) == TRUE;
}

std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> &scl::wstr_conv()
{
    static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv;
}
