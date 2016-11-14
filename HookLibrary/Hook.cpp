#include "Hook.h"

#ifdef _WIN64
#pragma comment(lib, "LDE64x64")
extern "C" unsigned __fastcall LDE(LPCBYTE lpData, unsigned uArch);
#define SCYLLA_LDE_ARCH     64
#define SCYLLA_DETOUR_SIZE  (2 + sizeof(DWORD) + sizeof(DWORD_PTR)) // 2 + 4 + 8 = 14
#else
#pragma comment(lib, "LDE64")
extern "C" unsigned __stdcall LDE(LPCBYTE lpData, unsigned uArch);
#define SCYLLA_LDE_ARCH 0
#define SCYLLA_DETOUR_SIZE  (1 + sizeof(DWORD)) // 1 + 4 = 5
#endif

void WriteJumper(LPBYTE lpbFrom, LPCBYTE lpcbTo)
{
#ifdef _WIN64
    lpbFrom[0] = 0xFF;
    lpbFrom[1] = 0x25;
    *(DWORD*)&lpbFrom[2] = 0;
    *(DWORD_PTR*)&lpbFrom[6] = (DWORD_PTR)lpcbTo;
#else
    lpbFrom[0] = 0xE9;
    *(DWORD*)&lpbFrom[1] = (DWORD)lpcbTo - (DWORD)lpbFrom - 5;
#endif
}

LPBYTE DetourCreate(LPBYTE lpbFuncOrig, LPCBYTE lpcbFuncDetour, BOOL fCreateTramp)
{
    DWORD dwProtect;
    LPBYTE lpbTrampoline = NULL;

    unsigned uDetourLen = GetDetourLen(lpbFuncOrig, SCYLLA_DETOUR_SIZE);

    if (fCreateTramp) {
        lpbTrampoline = (LPBYTE)VirtualAlloc(0, uDetourLen + SCYLLA_DETOUR_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!lpbTrampoline)
            return NULL;

        RtlCopyMemory(lpbTrampoline, lpbFuncOrig, uDetourLen);
        WriteJumper(lpbTrampoline + uDetourLen, lpbFuncOrig + uDetourLen);
    }

    if (VirtualProtect(lpbFuncOrig, uDetourLen, PAGE_EXECUTE_READWRITE, &dwProtect)) {
        WriteJumper(lpbFuncOrig, lpcbFuncDetour);
        VirtualProtect(lpbFuncOrig, uDetourLen, dwProtect, &dwProtect);
        FlushInstructionCache(GetCurrentProcess(), lpbFuncOrig, uDetourLen);
    }
    else if (lpbTrampoline) {
        VirtualFree(lpbTrampoline, 0, MEM_RELEASE);
        lpbTrampoline = NULL;
    }

    return lpbTrampoline;
}

unsigned GetDetourLen(LPCBYTE lpcbStart, unsigned uMinSize) {
    unsigned len = 0;

    while (len < uMinSize) {
        len += LDE(lpcbStart + len, SCYLLA_LDE_ARCH);
        if (!len) len++; // prevent infinite loop
    }

    return len;
}
