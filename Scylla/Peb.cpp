#include "Peb.h"
#include <Scylla/NtApiShim.h>
#include <Scylla/OsInfo.h>
#include "Util.h"

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

    bool success = Wow64QueryInformationProcess64(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    return success ? (PVOID64)pbi.PebBaseAddress : nullptr;
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

PVOID64 scl::Wow64GetModuleHandle64(HANDLE hProcess, const wchar_t* moduleName)
{
    const auto Peb64 = Wow64GetPeb64(hProcess);
    if (Peb64 == nullptr)
        return nullptr;

    PEB_LDR_DATA64 LdrData64;
    if (!Wow64ReadProcessMemory64(hProcess, (PVOID64)Peb64->Ldr, &LdrData64, sizeof(LdrData64), nullptr))
        return nullptr;

    PVOID64 DllBase = nullptr;
    const ULONG64 LastEntry = Peb64->Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
    LDR_DATA_TABLE_ENTRY64 Head;
    Head.InLoadOrderLinks.Flink = LdrData64.InLoadOrderModuleList.Flink;

    do
    {
        if (!Wow64ReadProcessMemory64(hProcess, (PVOID64)Head.InLoadOrderLinks.Flink, &Head, sizeof(Head), nullptr))
            break;

        wchar_t* BaseDllName = (wchar_t*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, Head.BaseDllName.MaximumLength);
        if (BaseDllName == nullptr ||
            !Wow64ReadProcessMemory64(hProcess, (PVOID64)Head.BaseDllName.Buffer, BaseDllName, Head.BaseDllName.MaximumLength, nullptr))
            break;

        if (_wcsicmp(moduleName, BaseDllName) == 0)
        {
            DllBase = (PVOID64)Head.DllBase;
        }

        RtlFreeHeap(RtlProcessHeap(), 0, BaseDllName);

    } while (Head.InLoadOrderLinks.Flink != LastEntry && DllBase == nullptr);

    return DllBase;
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
