#include "Peb.h"
#include <Scylla/NtApiShim.h>
#include <Scylla/OsInfo.h>

#ifdef _WIN64
#pragma comment(lib, "ntdll\\ntdll_x64.lib")
#else
#pragma comment(lib, "ntdll\\ntdll_x86.lib")
#endif

scl::PEB *scl::GetPebAddress(HANDLE hProcess)
{
    ::PROCESS_BASIC_INFORMATION pbi = { 0 };

    auto status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    return NT_SUCCESS(status) ? (PEB *)pbi.PebBaseAddress : nullptr;
}

/**
 * Get PEB64 address of WOW64 process.
 */
PVOID64 scl::GetPeb64Address(HANDLE hProcess)
{
#ifndef _WIN64
    if (IsWow64Process(hProcess))
    {
        auto _NtWow64QueryInformationProcess64 = (t_NtWow64QueryInformationProcess64)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64QueryInformationProcess64");
        if (!_NtWow64QueryInformationProcess64)
            return nullptr;

        PROCESS_BASIC_INFORMATION<DWORD64> pbi = { 0 };

        auto status = _NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

        return NT_SUCCESS(status) ? (PVOID64)pbi.PebBaseAddress : nullptr;
    }
#endif

    return 0;
}

std::shared_ptr<scl::PEB> scl::GetPeb(HANDLE hProcess)
{
    auto peb_addr = GetPebAddress(hProcess);
    if (!peb_addr)
        return nullptr;

    auto peb = std::make_shared<PEB>();
    if (!ReadProcessMemory(hProcess, peb_addr, peb.get(), sizeof(PEB), nullptr))
        return nullptr;

    return peb;
}

/**
 * @remark Use only real process handles.
 */
std::shared_ptr<scl::PEB64> scl::GetPeb64(HANDLE hProcess)
{
    auto peb64_addr = GetPeb64Address(hProcess);
    if (!peb64_addr)
        return nullptr;

    auto peb64 = std::make_shared<PEB64>();

    auto _NtWow64ReadVirtualMemory64 = (t_NtWow64ReadVirtualMemory64)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64ReadVirtualMemory64");
    if (_NtWow64ReadVirtualMemory64) {
        auto status = _NtWow64ReadVirtualMemory64(hProcess, peb64_addr, peb64.get(), sizeof(PEB64), nullptr);
        return NT_SUCCESS(status) ? peb64 : nullptr;
    }
    else if (peb64_addr < (PVOID64)0xffffffff)
    {
        auto ok = ReadProcessMemory(hProcess, (PVOID)peb64_addr, peb64.get(), sizeof(PEB64), nullptr);
        return ok ? peb64 : nullptr;
    }

    return nullptr;
}

bool scl::SetPeb(HANDLE hProcess, const PEB *pPeb)
{
    auto peb_addr = GetPebAddress(hProcess);
    if (!peb_addr)
        return false;

    return WriteProcessMemory(hProcess, peb_addr, pPeb, sizeof(*pPeb), nullptr) == TRUE;
}

/**
 * @remark Use only real process handles.
 */
bool scl::SetPeb64(HANDLE hProcess, const PEB64 *pPeb64)
{
    auto peb64_addr = GetPeb64Address(hProcess);
    if (!peb64_addr)
        return false;

    auto _NtWow64WriteVirtualMemory64 = (t_NtWow64WriteVirtualMemory64)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64WriteVirtualMemory64");
    if (!_NtWow64WriteVirtualMemory64)
        return false;

    return NT_SUCCESS(_NtWow64WriteVirtualMemory64(hProcess, peb64_addr, pPeb64, sizeof(*pPeb64), nullptr));
}

DWORD scl::GetHeapFlagsOffset(bool x64)
{
    if (x64)
    {
        if (scl::GetWindowsVersion() >= scl::OS_WIN_VISTA)
            return 0x70;
        else
            return 0x14;
    }
    else
    {
        if (scl::GetWindowsVersion() >= scl::OS_WIN_VISTA)
            return 0x40;
        else
            return 0x0C;
    }
}

DWORD scl::GetHeapForceFlagsOffset(bool x64)
{
    if (x64)
    {
        if (scl::GetWindowsVersion() >= scl::OS_WIN_VISTA)
            return 0x74;
        else
            return 0x18;
    }
    else
    {
        if (scl::GetWindowsVersion() >= scl::OS_WIN_VISTA)
            return 0x44;
        else
            return 0x10;
    }
}
