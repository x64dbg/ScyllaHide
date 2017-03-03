#include "Peb.h"
#include <Scylla/NtApiShim.h>
#include <Scylla/OsInfo.h>
#include "Util.h"

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
    PROCESS_BASIC_INFORMATION<DWORD64> pbi = { 0 };

    auto status = Wow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    return NT_SUCCESS(status) ? (PVOID64)pbi.PebBaseAddress : nullptr;
#endif

    return nullptr;
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
std::shared_ptr<scl::PEB64> scl::Wow64GetPeb64(HANDLE hProcess)
{
#ifndef _WIN64
    auto peb64_addr = GetPeb64Address(hProcess);
    if (!peb64_addr)
        return nullptr;

    auto peb64 = std::make_shared<PEB64>();

    if (Wow64ReadProcessMemory64(hProcess, peb64_addr, peb64.get(), sizeof(PEB64), nullptr))
        return peb64;
#endif

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
bool scl::Wow64SetPeb64(HANDLE hProcess, const PEB64 *pPeb64)
{
#ifndef _WIN64
    auto peb64_addr = GetPeb64Address(hProcess);
    if (!peb64_addr)
        return false;

    return NT_SUCCESS(Wow64WriteProcessMemory64(hProcess, peb64_addr, pPeb64, sizeof(*pPeb64), nullptr));
#endif

    return false;
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
