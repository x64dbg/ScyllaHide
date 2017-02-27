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

scl::PEB64* scl::GetPeb64Address(HANDLE hProcess)
{
#ifndef _WIN64
    if (IsWow64Process(hProcess))
    {
        auto _NtWow64QueryInformationProcess64 = (t_NtWow64QueryInformationProcess64)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWow64QueryInformationProcess64");
        if (!_NtWow64QueryInformationProcess64)
            return nullptr;

        PROCESS_BASIC_INFORMATION<DWORD64> pbi = { 0 };

        auto status = _NtWow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

        return NT_SUCCESS(status) ? (PEB64 *)pbi.PebBaseAddress : nullptr;
    }
#endif

    return nullptr;
}

std::shared_ptr<scl::PEB> scl::GetPeb(HANDLE hProcess)
{
    auto *pPebPtr = GetPebAddress(hProcess);
    if (!pPebPtr)
    {
        return nullptr;
    }

    auto peb = std::make_shared<PEB>();
    if (!ReadProcessMemory(hProcess, pPebPtr, peb.get(), sizeof(PEB), nullptr))
    {
        return nullptr;
    }

    return peb;
}

std::shared_ptr<scl::PEB64> scl::GetPeb64(HANDLE hProcess)
{
    auto *pPebPtr = GetPeb64Address(hProcess);
    if (!pPebPtr)
    {
        return nullptr;
    }

    auto peb = std::make_shared<PEB64>();
    if (!ReadProcessMemory(hProcess, pPebPtr, peb.get(), sizeof(PEB64), nullptr))
    {
        return nullptr;
    }

    return peb;
}

bool scl::SetPeb(HANDLE hProcess, const PEB *pPeb)
{
    auto *pPebPtr = GetPebAddress(hProcess);
    if (!pPebPtr)
    {
        return false;
    }

    return WriteProcessMemory(hProcess, pPebPtr, pPeb, sizeof(*pPeb), nullptr) == TRUE;
}

bool scl::SetPeb64(HANDLE hProcess, const PEB64 *pPeb64)
{
    auto *pPeb64Ptr = GetPeb64Address(hProcess);
    if (!pPeb64Ptr)
    {
        return false;
    }

    return WriteProcessMemory(hProcess, pPeb64Ptr, pPeb64, sizeof(*pPeb64), nullptr) == TRUE;
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
