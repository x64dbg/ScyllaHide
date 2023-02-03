#include "VersionPatch.h"

#define STR(x) #x
#define VERSTR(x) STR(x)
#define FAKE_VERSION_WCHAR L"" VERSTR(FAKE_VERSION)

bool NtVirtualProtect(HANDLE hProcess, PVOID Address, SIZE_T Size, ULONG NewProtect, PULONG OldProtect)
{
    PVOID BaseAddress = Address;
    SIZE_T RegionSize = Size;
    return NT_SUCCESS(NtProtectVirtualMemory(hProcess, &BaseAddress, &RegionSize, NewProtect, OldProtect));
}

void PatchFixedFileInfoVersion(HANDLE hProcess, PVOID Address, ULONG Size)
{
    BOOL found = FALSE;
    PUCHAR P;
    for (P = (PUCHAR)Address; P < (PUCHAR)Address + Size; ++P)
    {
        if (*(PDWORD)P == 0xFEEF04BD) // VS_FIXEDFILEINFO signature
        {
            found = TRUE;
            break;
        }
    }
    if (!found)
    {
        DbgPrint("Failed to find fixed version info signature in ntdll.dll VS_VERSION_INFO");
        return;
    }

    P += 14; // Skip to FileVersion build number
    ULONG OldProtect;
    if (NtVirtualProtect(hProcess, P, 10, PAGE_READWRITE, &OldProtect))
    {
        WORD Version = FAKE_VERSION;
        NtWriteVirtualMemory(hProcess, P, &Version, 2, nullptr); // FileVersion
        NtWriteVirtualMemory(hProcess, P + 8, &Version, 2, nullptr); // ProductVersion
        NtVirtualProtect(hProcess, P, 10, OldProtect, &OldProtect);
    }
    else
    {
        DbgPrint("VirtualProtectEx failed on ntdll");
    }
}

void PatchVersionString(HANDLE hProcess, PVOID Address, ULONG Size, const WCHAR* Property)
{
    // VS_VERSIONINFO is a mess to navigate because it is a nested struct of variable size with (grand)children all of variable sizes
    // See: https://docs.microsoft.com/en-gb/windows/win32/menurc/vs-versioninfo
    // Instead of finding VS_VERSIONINFO -> StringFileInfo[] -> StringTable[] -> String (-> WCHAR[]) properly, just do it the memcmp way
    size_t propertyLen = (wcslen(Property) + 1) * 2;
    PUCHAR P = (PUCHAR)Address;
    BOOL found = FALSE;
    for (; P < (PUCHAR)Address + Size - propertyLen; ++P)
    {
        if (memcmp(P, Property, propertyLen) == 0)
        {
            found = TRUE;
            break;
        }
    }
    if (!found)
    {
        DbgPrint("Failed to find %ws in ntdll.dll VS_VERSION_INFO", Property);
        return;
    }

    // Skip to the version number and discard extra nulls
    P += propertyLen;
    while (*(PWCHAR)P == L'\0')
    {
        P += sizeof(WCHAR);
    }

    // P now points at e.g. 6.1.xxxx.yyyy or 10.0.xxxxx.yyyy. Skip the major and minor version numbers to get to the build number xxxx
    const ULONG Skip = NtCurrentPeb()->OSMajorVersion >= 10 ? 5 * sizeof(WCHAR) : 4 * sizeof(WCHAR);
    P += Skip;

    // Write a new bogus build number
    WCHAR NewBuildNumber[] = FAKE_VERSION_WCHAR;
    ULONG OldProtect;
    if (NtVirtualProtect(hProcess, P, sizeof(NewBuildNumber) - sizeof(WCHAR), PAGE_READWRITE, &OldProtect))
    {
        SIZE_T NumWritten;
        NtWriteVirtualMemory(hProcess, P, NewBuildNumber, sizeof(NewBuildNumber) - sizeof(WCHAR), &NumWritten);
        NtVirtualProtect(hProcess, P, sizeof(NewBuildNumber) - sizeof(WCHAR), OldProtect, &OldProtect);
    }
}

void ApplyNtdllVersionPatch(HANDLE hProcess, PVOID Ntdll)
{
    // Get the resource data entry for VS_VERSION_INFO
    LDR_RESOURCE_INFO ResourceIdPath;
    ResourceIdPath.Type = (ULONG_PTR)RT_VERSION;
    ResourceIdPath.Name = VS_VERSION_INFO;
    ResourceIdPath.Language = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
    PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = nullptr;
    NTSTATUS Status = LdrFindResource_U(Ntdll, &ResourceIdPath, 3, &ResourceDataEntry);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("Failed to find VS_VERSION_INFO resource in ntdll.dll: %08X", Status);
        return;
    }

    // Get the address and size of VS_VERSION_INFO
    PVOID Address = nullptr;
    ULONG Size = 0;
    Status = LdrAccessResource(Ntdll, ResourceDataEntry, &Address, &Size);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("Failed to obtain size of VS_VERSION_INFO resource in ntdll.dll: %08X", Status);
        return;
    }
    if (Address == nullptr || Size == 0)
    {
        DbgPrint("VS_VERSION_INFO resource in ntdll.dll has size zero");
        return;
    }

    PatchFixedFileInfoVersion(hProcess, Address, Size);
    PatchVersionString(hProcess, Address, Size, L"FileVersion");
    PatchVersionString(hProcess, Address, Size, L"ProductVersion");
}
