#include "RemotePebHider.h"
#include "..\ntdll\ntdll.h"

static bool isAtleastVista()
{
    static bool isAtleastVista = false;
    static bool isSet = false;
    if (isSet)
        return isAtleastVista;
    OSVERSIONINFO versionInfo = { 0 };
    versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&versionInfo);
    isAtleastVista = versionInfo.dwMajorVersion >= 6;
    isSet = true;
    return isAtleastVista;
}

void* GetPEBLocation(HANDLE hProcess)
{
    ULONG RequiredLen = 0;
    void * PebAddress = 0;
    PROCESS_BASIC_INFORMATION myProcessBasicInformation[5] = { 0 };

    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &RequiredLen) == STATUS_SUCCESS)
    {
        PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
    }
    else
    {
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen) == STATUS_SUCCESS)
        {
            PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
        }
    }

    return PebAddress;
}
#ifndef _WIN64
bool IsThisProcessWow64()
{
    typedef BOOL(WINAPI * tIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
    BOOL bIsWow64 = FALSE;
    tIsWow64Process fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if (fnIsWow64Process)
    {
        fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
    }

    return (bIsWow64 != FALSE);
}
#endif
void* GetPEBLocation64(HANDLE hProcess)
{
#ifndef _WIN64
    if (IsThisProcessWow64())
    {
        //Only WOW64 processes have 2 PEBs
        DWORD peb32 = (DWORD)GetPEBLocation(hProcess);
        if (peb32)
        {
            peb32 += 0x1000; //PEB64 after PEB32
            return (void *)peb32;
        }
    }
#endif //_WIN64
    return 0;
}



//TODO: unclear behaviour, will return true when on wow64, but should not return true, because the system structures are x32 in that case
static bool isWindows64()
{
    SYSTEM_INFO si = { 0 };
    typedef void (WINAPI *tGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
    tGetNativeSystemInfo _GetNativeSystemInfo = (tGetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetNativeSystemInfo");

    if (_GetNativeSystemInfo)
    {
        _GetNativeSystemInfo(&si);
    }
    else
    {
        GetSystemInfo(&si);
    }

    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}


//Quote from The Ultimate Anti-Debugging Reference by Peter Ferrie
//Flags field exists at offset 0x0C in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x40 on the 32-bit versions of Windows Vista and later.
//Flags field exists at offset 0x14 in the heap on the 64-bit versions of Windows XP, and at offset 0x70 in the heap on the 64-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x10 in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x44 on the 32-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x18 in the heap on the 64-bit versions of Windows XP, and at offset 0x74 in the heap on the 64-bit versions of Windows Vista and later.

static int getHeapFlagsOffset(bool x64)
{
    if (x64) //x64 offsets
    {
        if (isAtleastVista())
        {
            return 0x70;
        }
        else
        {
            return 0x14;
        }
    }
    else //x86 offsets
    {
        if (isAtleastVista())
        {
            return 0x40;
        }
        else
        {
            return 0x0C;
        }
    }
}

static int getHeapForceFlagsOffset(bool x64)
{
    if (x64) //x64 offsets
    {
        if (isAtleastVista())
        {
            return 0x74;
        }
        else
        {
            return 0x18;
        }
    }
    else //x86 offsets
    {
        if (isAtleastVista())
        {
            return 0x44;
        }
        else
        {
            return 0x10;
        }
    }
}

bool FixStartUpInfo( PEB_CURRENT* myPEB, HANDLE hProcess )
{
	RTL_USER_PROCESS_PARAMETERS * rtlProcessParam = (RTL_USER_PROCESS_PARAMETERS *)myPEB->ProcessParameters;

	DWORD_PTR startOffset = (DWORD_PTR)&rtlProcessParam->StartingX;
	DWORD patchSize = (DWORD_PTR)&rtlProcessParam->WindowFlags - (DWORD_PTR)&rtlProcessParam->StartingX;

	LPVOID memoryZero = calloc(patchSize, 1);

	bool retVal = (WriteProcessMemory(hProcess, (LPVOID)startOffset, memoryZero, patchSize, 0) != FALSE);
	free(memoryZero);

	return retVal;
}

bool FixPebInProcess(HANDLE hProcess)
{
    PEB_CURRENT myPEB = { 0 };
    SIZE_T ueNumberOfBytesRead = 0;
    void * heapFlagsAddress = 0;
    DWORD heapFlags = 0;
    void * heapForceFlagsAddress = 0;
    DWORD heapForceFlags = 0;

#ifndef _WIN64
    PEB64 myPEB64 = { 0 };
    void * AddressOfPEB64 = GetPEBLocation64(hProcess);
#endif

    void * AddressOfPEB = GetPEBLocation(hProcess);

    if (!AddressOfPEB)
        return false;

    if (ReadProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
    {
#ifndef _WIN64
        if (AddressOfPEB64)
        {
            ReadProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
        }
#endif

		FixStartUpInfo(&myPEB, hProcess);

        //TODO: backup GlobalFlag
        //myPEB.BeingDebugged = FALSE;
        myPEB.NtGlobalFlag &= ~0x70;

#ifndef _WIN64
        myPEB64.BeingDebugged = FALSE;
        myPEB64.NtGlobalFlag &= ~0x70;
#endif

        //TODO: backup heap flags
#ifdef _WIN64
        heapFlagsAddress = (void *)((LONG_PTR)myPEB.ProcessHeap + getHeapFlagsOffset(true));
        heapForceFlagsAddress = (void *)((LONG_PTR)myPEB.ProcessHeap + getHeapForceFlagsOffset(true));
#else
        heapFlagsAddress = (void *)((LONG_PTR)myPEB.ProcessHeap + getHeapFlagsOffset(false));
        heapForceFlagsAddress = (void *)((LONG_PTR)myPEB.ProcessHeap + getHeapForceFlagsOffset(false));
#endif //_WIN64
        ReadProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
        ReadProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);

        heapFlags &= HEAP_GROWABLE;
        heapForceFlags = 0;

        WriteProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
        WriteProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);


        if (WriteProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
        {
#ifndef _WIN64
            if (AddressOfPEB64)
            {
                WriteProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
            }
#endif
            return true;
        }
    }
    return false;
}
