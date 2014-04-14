#include "olly1patches.h"
#include <Windows.h>

//taken from strongOD
void fixBadPEBugs()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);
    BOOL fixed = false;

    BYTE peBug1Fix[] = {0xEB}; //JE (74 1C) to JMP (EB 1C)
    LPVOID patchAddr = (LPVOID)(lpBaseAddr+0x5C671);
    fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0x5C671), &peBug1Fix, sizeof(peBug1Fix), NULL);
    if(fixed) _Addtolist(0,-1,"Fixed PE-Bug at 0x5C671");

    /*
    Fixed:
    0045D827  |. 74 79          ||JE SHORT OLLYDBG.0045D8A2
    0045D829  |? 893CCA         MOV DWORD PTR DS:[EDX+ECX*8],EDI
    Unpatched:
    0045D827  |. 893CCA         ||MOV DWORD PTR DS:[EDX+ECX*8],EDI
    0045D82A  |. 74 76          ||JE SHORT OLLYDBG.0045D8A2
    */
    BYTE peBug2Fix[] = {0x74,0x79,0x89,0x3C,0xCA};
    fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0x5D827), &peBug2Fix, sizeof(peBug2Fix), NULL);
    if(fixed) _Addtolist(0,-1,"Fixed PE-Bug at 0x5D827");

    /*
    0045D8B7  |> 90             |NOP
    0045D8B8  |? 90             NOP
    0045D8B9  |? 90             NOP
    0045D8BA  |. 90             |NOP
    0045D8BB  |? 90             NOP
    0045D8BC  |? 90             NOP
    Unpatched:
    0045D8B7  |> 83C0 03        |ADD EAX,3
    0045D8BA  |. 83E0 FC        |AND EAX,FFFFFFFC
    */
    BYTE peBug3Fix[] = {0x90,0x90,0x90,0x90,0x90,0x90};
    fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0x5D8B7), &peBug3Fix, sizeof(peBug3Fix), NULL);
    if(fixed) _Addtolist(0,-1,"Fixed PE-Bug at 0x5D8B7");

    /*
    004C870A   2B31             SUB ESI,DWORD PTR DS:[ECX]
    004C870C   382B             CMP BYTE PTR DS:[EBX],CH
    004C870E   25 422A3238      AND EAX,38322A42
    004C8713   2020             AND BYTE PTR DS:[EAX],AH
    004C8715   2020             AND BYTE PTR DS:[EAX],AH
    004C8717   2020             AND BYTE PTR DS:[EAX],AH
    004C8719   2020             AND BYTE PTR DS:[EAX],AH
    004C871B   2020             AND BYTE PTR DS:[EAX],AH
    Unpatched:
    004C870A   2D 36382B5B      SUB EAX,5B2B3836
    004C870F   25 412B3734      AND EAX,34372B41
    004C8714   5D               POP EBP
    004C8715   2A38             SUB BH,BYTE PTR DS:[EAX]
    004C8717   2B25 422A3238    SUB ESP,DWORD PTR DS:[38322A42]
    */
    BYTE peBug4Fix[] = {0x2B,0x31,0x38,0x2B,0x25,0x42,0x2A,0x32,0x38,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20};
    fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0xC870A), &peBug4Fix, sizeof(peBug4Fix), NULL);
    if(fixed) _Addtolist(0,-1,"Fixed PE-Bug at 0xC870A");
}

//taken from strongOD
void fixForegroundWindow()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);
    BOOL fixed = false;

    BYTE fgWinFix[] = {0x74}; //JMP (EB 1C) to JNZ (75 1C)
    fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0x3A1FB), &fgWinFix, sizeof(fgWinFix), NULL);
    if(fixed) _Addtolist(0,-1,"Fixed ForegroundWindow at 0x3A1FB");
}

//taken from http://waleedassar.blogspot.de/2012/03/ollydbg-v110-and-wow64.html
void fixX64Bug()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);
    BOOL fixed = false;

    BYTE x64Patch[] = {0xEB}; //JE to JMP
    fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0x311C2), &x64Patch, sizeof(x64Patch), NULL);
    if(fixed) _Addtolist(0,-1,"Patched single-step break on x64 at 0x311C2");
}