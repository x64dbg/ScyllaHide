#include "RemotePebHider.h"
#include <ntdll/ntdll.h>
#include "Logger.h"
#include "OperatingSysInfo.h"

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
	NTSTATUS ntstat = 0;
    ULONG RequiredLen = 0;
    void * PebAddress = 0;
    PROCESS_BASIC_INFORMATION myProcessBasicInformation = { 0 };

	ntstat = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &RequiredLen);

    if (ntstat == STATUS_SUCCESS)
    {
        PebAddress = (void*)myProcessBasicInformation.PebBaseAddress;
    }
	else
	{
		LogError("NtQueryInformationProcess failed with status %X", ntstat);
	}

	if (!PebAddress)
	{
		LogErrorBox("GetPEBLocation PEB Address is 0");
	}

    return PebAddress;
}


bool IsThisProcessWow64()
{
    return IsProcessWOW64(GetCurrentProcess());
}


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
		else
		{
			LogDebug("GetPEBLocation64->GetPEBLocation returns NULL");
		}
    }
#endif //_WIN64
    return 0;
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

//some debuggers manipulate StartUpInfo to start the debugged process and therefore can be detected...
bool FixStartUpInfo( PEB_CURRENT* myPEB, HANDLE hProcess )
{
	RTL_USER_PROCESS_PARAMETERS * rtlProcessParam = (RTL_USER_PROCESS_PARAMETERS *)myPEB->ProcessParameters;

	DWORD_PTR startOffset = (DWORD_PTR)&rtlProcessParam->StartingX;
	DWORD_PTR patchSize = (DWORD_PTR)&rtlProcessParam->WindowFlags - (DWORD_PTR)&rtlProcessParam->StartingX;

	LPVOID memoryZero = calloc(patchSize, 1);

	bool retVal = (WriteProcessMemory(hProcess, (LPVOID)startOffset, memoryZero, patchSize, 0) != FALSE);
	free(memoryZero);

	return retVal;
}

void ReadPebToBuffer(HANDLE hProcess, unsigned char * buffer, int bufferSize)
{
	void * AddressOfPEB = GetPEBLocation(hProcess);
	if (AddressOfPEB)
	{
		if (!ReadProcessMemory(hProcess, AddressOfPEB, (void*)buffer, bufferSize, 0))
		{
			LogError("ReadPebToBuffer->ReadProcessMemory failed");
		}
	}
	else
	{
		LogErrorBox("ReadPebToBuffer->GetPEBLocation returns NULL");
	}	
}

void FixHeapFlag(HANDLE hProcess, DWORD_PTR heapBase, bool isDefaultHeap)
{
	void * heapFlagsAddress = 0;
	DWORD heapFlags = 0;
	void * heapForceFlagsAddress = 0;
	DWORD heapForceFlags = 0;
#ifdef _WIN64
	heapFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapFlagsOffset(true));
	heapForceFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapForceFlagsOffset(true));
#else
	heapFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapFlagsOffset(false));
	heapForceFlagsAddress = (void *)((LONG_PTR)heapBase + getHeapForceFlagsOffset(false));
#endif //_WIN64

	if (ReadProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0))
	{
		if (isDefaultHeap)
		{
			heapFlags &= HEAP_GROWABLE;
		}
		else
		{
			//user defined heaps with user defined flags
			//flags from RtlCreateHeap/HeapCreate
			heapFlags &= (HEAP_GROWABLE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE | HEAP_CREATE_ENABLE_EXECUTE);
		}
		WriteProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
	}
	if (ReadProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0))
	{
		heapForceFlags = 0;
		WriteProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);
	}	
}

void FixPebBeingDebugged(HANDLE hProcess, bool SetToNull)
{
	PEB_CURRENT myPEB = { 0 };
#ifndef _WIN64
	PEB64 myPEB64 = { 0 };
	void * AddressOfPEB64 = GetPEBLocation64(hProcess);
#endif
	void * AddressOfPEB = GetPEBLocation(hProcess);
	ReadProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, 0x10, 0);

#ifndef _WIN64
	if (AddressOfPEB64)
	{
		ReadProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, 0x10, 0);
	}
#endif

	if (SetToNull)
	{
		myPEB.BeingDebugged = FALSE;
#ifndef _WIN64
		myPEB64.BeingDebugged = FALSE;
#endif
	}
	else
	{
		myPEB.BeingDebugged = TRUE;
#ifndef _WIN64
		myPEB64.BeingDebugged = TRUE;
#endif
	}
	WriteProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, 0x10, 0);

#ifndef _WIN64
	if (AddressOfPEB64)
	{
		WriteProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, 0x10, 0);
	}
#endif
}

bool FixPebInProcess(HANDLE hProcess, DWORD EnableFlags)
{
    PEB_CURRENT myPEB = { 0 };
    SIZE_T ueNumberOfBytesRead = 0;


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

		if (EnableFlags & PEB_PATCH_StartUpInfo) FixStartUpInfo(&myPEB, hProcess);

		if (EnableFlags & PEB_PATCH_BeingDebugged) myPEB.BeingDebugged = FALSE;
        if (EnableFlags & PEB_PATCH_NtGlobalFlag) myPEB.NtGlobalFlag &= ~0x70;

#ifndef _WIN64
        if (EnableFlags & PEB_PATCH_BeingDebugged) myPEB64.BeingDebugged = FALSE;
        if (EnableFlags & PEB_PATCH_NtGlobalFlag) myPEB64.NtGlobalFlag &= ~0x70;
#endif

		if (EnableFlags & PEB_PATCH_HeapFlags)
		{
			//handle to the default heap of the calling process
			FixHeapFlag(hProcess, myPEB.ProcessHeap, true);

			if (myPEB.NumberOfHeaps > 1) //first is always default heap -> myPEB.ProcessHeap
			{
				PVOID * heapArray = (PVOID *)calloc(myPEB.NumberOfHeaps, sizeof(PVOID));
				if (heapArray)
				{
					ReadProcessMemory(hProcess, (PVOID)myPEB.ProcessHeaps, heapArray, myPEB.NumberOfHeaps*sizeof(PVOID), 0);

					//skip index 0 same as default heap myPEB.ProcessHeap
					for (DWORD i = 1; i < myPEB.NumberOfHeaps; i++)
					{
						FixHeapFlag(hProcess, (DWORD_PTR)heapArray[i], false);
					}
				}
				free(heapArray);
			}
		}

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
