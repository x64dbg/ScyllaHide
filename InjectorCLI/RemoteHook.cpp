#include "RemoteHook.h"
#include <windows.h>


void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo)
{
#ifdef _WIN64
    lpbFrom[0] = 0xFF;
    lpbFrom[1] = 0x25;
    *(DWORD*)&lpbFrom[2] = 0;
    *(DWORD_PTR*)&lpbFrom[6] = (DWORD_PTR)lpbTo;
#else
    lpbFrom[0] = 0xE9;
    *(DWORD*)&lpbFrom[1] = (DWORD)((DWORD)lpbTo - (DWORD)lpbFrom - 5);
#endif

}

void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo, unsigned char * buf)
{
#ifdef _WIN64
    buf[0] = 0xFF;
    buf[1] = 0x25;
    *(DWORD*)&buf[2] = 0;
    *(DWORD_PTR*)&buf[6] = (DWORD_PTR)lpbTo;
#else
    buf[0] = 0xE9;
    *(DWORD*)&buf[1] = (DWORD)((DWORD)lpbTo - (DWORD)lpbFrom - 5);
#endif

}

void * FixWindowsRedirects(void * address)
{
    BYTE * pb = (BYTE *)address;
    int len = (int)LDE((void *)address, 0);

    if (len == 2 && pb[0] == 0xEB) //JMP SHORT
    {
        return (pb + 2 + pb[1]);
    }
    else if (len == 6 && pb[0] == 0xFF && pb[1] == 0x25) //JMP DWORD PTR
    {
        return (pb + 2 + pb[1]);
    }

    return address;
}

#ifdef _WIN64
const int minDetourLen = 2 + sizeof(DWORD)+sizeof(DWORD_PTR); //8+4+2=14
#else
const int minDetourLen = sizeof(DWORD)+1;
#endif


void * DetourCreateRemote(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp)
{
    BYTE originalBytes[50] = { 0 };
    BYTE tempSpace[1000] = { 0 };
    PBYTE trampoline = 0;
    DWORD protect;

    bool success = false;

    ReadProcessMemory(hProcess, lpFuncOrig, originalBytes, sizeof(originalBytes), 0);

    int detourLen = GetDetourLen(originalBytes, minDetourLen);

    if (createTramp)
    {
        trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, detourLen + minDetourLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        WriteProcessMemory(hProcess, trampoline, originalBytes, detourLen, 0);

        ZeroMemory(tempSpace, sizeof(tempSpace));
        WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen, tempSpace);
        WriteProcessMemory(hProcess, trampoline + detourLen, tempSpace, minDetourLen, 0);
    }

    if (VirtualProtectEx(hProcess, lpFuncOrig, detourLen, PAGE_EXECUTE_READWRITE, &protect))
    {
        ZeroMemory(tempSpace, sizeof(tempSpace));
        WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour, tempSpace);
        WriteProcessMemory(hProcess, lpFuncOrig, tempSpace, minDetourLen, 0);

        VirtualProtectEx(hProcess, lpFuncOrig, detourLen, protect, &protect);
        FlushInstructionCache(hProcess, lpFuncOrig, detourLen);
        success = true;
    }

    if (createTramp)
    {
        if (!success)
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            trampoline = 0;
        }
        return trampoline;
    }
    else
    {
        return 0;
    }
}

void * DetourCreate(void * lpFuncOrig, void * lpFuncDetour, bool createTramp)
{
    PBYTE trampoline = 0;
    DWORD protect;

    bool success = false;

    //lpFuncOrig = FixWindowsRedirects(lpFuncOrig);

    int detourLen = GetDetourLen(lpFuncOrig, minDetourLen);


    if (createTramp)
    {
        trampoline = (PBYTE)VirtualAlloc(0, detourLen + minDetourLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        memcpy(trampoline, lpFuncOrig, detourLen);
        WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen);
    }


    if (VirtualProtect(lpFuncOrig, detourLen, PAGE_EXECUTE_READWRITE, &protect))
    {
        WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour);

        VirtualProtect(lpFuncOrig, detourLen, protect, &protect);
        FlushInstructionCache(GetCurrentProcess(), lpFuncOrig, detourLen);
        success = true;
    }

    if (createTramp)
    {
        if (!success)
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            trampoline = 0;
        }
        return trampoline;
    }
    else
    {
        return 0;
    }
}

int GetDetourLen(const void * lpStart, const int minSize)
{
    int len = 0;
    int totalLen = 0;
    unsigned char * lpDataPos = (unsigned char *)lpStart;

    while (totalLen < minSize)
    {
        len = (int)LDE((void *)lpDataPos, 0);
        lpDataPos += len;
        totalLen += len;
    }

    return totalLen;
}
