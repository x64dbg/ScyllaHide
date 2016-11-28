#include "Peb.h"
#include <Winternl.h>
#include <Scylla/OsInfo.h>

#ifdef _WIN64
#pragma comment(lib, "ntdll\\ntdll_x64.lib")
#else
#pragma comment(lib, "ntdll\\ntdll_x86.lib")
#endif

Scylla::PEB *Scylla::GetPebAddress(HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION pbi = { nullptr };

    auto status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    return NT_SUCCESS(status) ? (PEB *)pbi.PebBaseAddress : nullptr;
}

Scylla::PEB64* Scylla::GetPeb64Address(HANDLE hProcess)
{
#ifndef _WIN64
    if (IsWow64Process(hProcess))
    {
        auto peb32 = GetPebAddress(hProcess);
        if (!peb32)
            return nullptr;

        return (PEB64 *)((BYTE*)peb32 + 0x1000);
    }
#endif

    return nullptr;
}

std::shared_ptr<Scylla::PEB> Scylla::GetPeb(HANDLE hProcess)
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

std::shared_ptr<Scylla::PEB64> Scylla::GetPeb64(HANDLE hProcess)
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

bool Scylla::SetPeb(HANDLE hProcess, const PEB *pPeb)
{
    auto *pPebPtr = GetPebAddress(hProcess);
    if (!pPebPtr)
    {
        return false;
    }

    return WriteProcessMemory(hProcess, pPebPtr, pPeb, sizeof(*pPeb), nullptr) == TRUE;
}

bool Scylla::SetPeb64(HANDLE hProcess, const PEB64 *pPeb64)
{
    auto *pPeb64Ptr = GetPeb64Address(hProcess);
    if (!pPeb64Ptr)
    {
        return false;
    }

    return WriteProcessMemory(hProcess, pPeb64Ptr, pPeb64, sizeof(*pPeb64), nullptr) == TRUE;
}