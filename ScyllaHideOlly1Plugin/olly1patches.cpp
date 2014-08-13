#include "olly1patches.h"
#include <Windows.h>
#include <TlHelp32.h>
#include "resource.h"
#include "..\PluginGeneric\Injector.h"

extern struct HideOptions pHideOptions;
extern HINSTANCE hinst;
extern LPVOID ImageBase;
extern DWORD ProcessId;
extern DWORD_PTR epaddr;

//naked declarations for handleSprintf
DWORD pFormat;
DWORD retAddr;
//naked declarations for advancedCTRL-G hooks
DWORD lpBase;
HWND hGotoDialog;
MODULEENTRY32 moduleinfo;
HANDLE hSnap;
WPARAM wparam;

//taken from strongOD aka "fix NumOfRvaAndSizes"
void fixBadPEBugs()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);
    BOOL fixed = false;

    BYTE peBug1Fix[] = {0xEB}; //JE (74 1C) to JMP (EB 1C)
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

    BYTE fgWinFix[] = {0xEB}; //JNZ (75 1C) to JMP (EB 1C)
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

//taken from POISON source https://tuts4you.com/download.php?view.2281
void fixFPUBug()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);
    BOOL fixed = false;

    BYTE fpuBugFix[] = {0xDB};
    BYTE buf[1];
    ReadProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0xAA2F0), &buf, 1, NULL);
    if(buf[0] == 0xDB)
        fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0xAA2F2), &fpuBugFix, sizeof(fpuBugFix), NULL);
    if(fixed) _Addtolist(0,-1,"Fixed FPU-Bug at 0xAA2F2");
}

//taken from olly-advanced RVA 8225+385
void fixSprintfBug()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);

    DWORD sprintf = (DWORD)handleSprintf;
    DWORD patchAddr = 0xA74D0;
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr), &sprintf, 4, NULL);
    patchAddr -= 1;
    BYTE push[] = {0x68};
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr), &push, sizeof(push), NULL);
    patchAddr += 5;
    BYTE retn[] = {0xC3};
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr), &retn, sizeof(retn), NULL);

    _Addtolist(0,-1,"Patched sprintf bug at 0xA74CF");
}

//logic taken from olly-advanced RVA 76AF and modified
void __declspec(naked) handleSprintf()
{
    _asm {
        pushfd
        pushad
        mov pFormat, edx
        pushad
    };

    retAddr = (DWORD)GetModuleHandle(NULL);

    if(IsBadCodePtr((FARPROC) pFormat)==0) {
        //all good
        _asm {
            popad
            cmp byte ptr[edx], 0 //stolen bytes
            jz goback
            add retAddr, 0xa74c2
            popad
            popfd
            jmp [retAddr]

            goback:
            add retAddr, 0xa759e
        }
    } else {
        //a crash would have happened
        _asm {
            popad
            add retAddr, 0xa759e
        };

    }

    _asm {
        popad
        popfd
        jmp [retAddr]
    };
}

//taken from OllyAdvanced patch function at RVA 8225+3A0
void patchEPOutsideCode()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);
    BOOL fixed = false;

    BYTE EPOutsideFix[] = {0x83,0xC4,0x10,0x90,0x90}; //call MessageBoxA to "add esp,0x10;nop;nop"
    fixed = WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+0x5DB81), &EPOutsideFix, sizeof(EPOutsideFix), NULL);
    if(fixed) _Addtolist(0,-1,"Patched EP outside of code message at 0x3A1FB");
}

//taken from POISON source https://tuts4you.com/download.php?view.2281
void hookOllyBreakpoints()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);

    DWORD breakpoints = (DWORD)handleBreakpoints;
    DWORD patchAddr = 0x2F91D;
    breakpoints -= lpBaseAddr;
    breakpoints -= patchAddr;
    patchAddr -= 4;
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr), &breakpoints, 4, NULL);
    patchAddr -= 1;
    BYTE call[] = {0xE8};
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr), &call, sizeof(call), NULL);

    _Addtolist(0,-1,"Hooked Olly Breakpoints handler for TLS at 0x2F918");
}

void __declspec(naked) handleBreakpoints()
{
    _asm { pushad };

    if(pHideOptions.removeEPBreak)
    {
        CreateThread(NULL, NULL, removeEPBreak, NULL, NULL, NULL);
    }

    if(pHideOptions.breakTLS)
    {
        ReadTlsAndSetBreakpoints(ProcessId, (LPVOID)ImageBase);
    }

    //replay stolen bytes and adjust return address
    _asm {
        popad
        CMP DWORD PTR DS:[004D734Ch],0
        mov dword ptr [esp], 0042F91Fh
        ret
    };
}

DWORD _stdcall removeEPBreak(LPVOID lpParam)
{
    Sleep(0x200);
    _Deletebreakpoints(epaddr,epaddr+2, 0);
    return 0;
}

void ReadTlsAndSetBreakpoints(DWORD dwProcessId, LPVOID baseofImage)
{
    BYTE memory[0x1000] = {0};
    IMAGE_TLS_DIRECTORY tlsDir = {0};
    PVOID callbacks[64] = {0};

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, dwProcessId);

    if (!hProcess)
        return;

    ReadProcessMemory(hProcess, baseofImage, memory, sizeof(memory), 0);

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)memory;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDos + pDos->e_lfanew);
    if (pNt->Signature == IMAGE_NT_SIGNATURE)
    {
        if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
        {
            //_Message(0, "[ScyllaHide] TLS directory %X found", pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

            ReadProcessMemory(hProcess, (PVOID)((DWORD_PTR)baseofImage + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress), &tlsDir, sizeof(IMAGE_TLS_DIRECTORY), 0);

            if (tlsDir.AddressOfCallBacks)
            {
                //_Message(0, "[ScyllaHide] TLS AddressOfCallBacks %X found", tlsDir.AddressOfCallBacks);

                ReadProcessMemory(hProcess, (PVOID)tlsDir.AddressOfCallBacks, callbacks, sizeof(callbacks), 0);

                for (int i = 0; i < _countof(callbacks); i++)
                {
                    if (callbacks[i])
                    {
                        _Message(0, "[ScyllaHide] TLS callback found: Index %d Address %X", i, callbacks[i]);
                        _Tempbreakpoint((DWORD)callbacks[i], TY_ONESHOT);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);
}

//NOTE: for this to work IDC_EXPRESSION _NEEDS_ to be 5101, same as equivalent control in orig Olly
void advcancedCtrlG()
{
    HANDLE hOlly = GetCurrentProcess();
    DWORD lpBaseAddr = (DWORD)GetModuleHandle(NULL);

    DWORD patchAddr = 0x4376C;
    BYTE push[] = {0x68};
    BYTE nopnop[] = {0x90,0x90};
    //patch Hinstance param of DialogBoxParamA call
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr), &push, sizeof(push), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr+1), &hinst, sizeof(HINSTANCE), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr+5), &nopnop, sizeof(nopnop), NULL);
    //patch templatename
    DWORD resourceId = (DWORD)MAKEINTRESOURCE(IDD_GOTO);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+patchAddr-4), &resourceId, sizeof(DWORD), NULL);

    //hook WMCOMMAND and WMINIT and forwarding of entered value for the goto dialog
    BYTE retn[] = {0xC3};
    DWORD hookWMINITaddr = 0x432D0;
    DWORD hookWMINIT = (DWORD)advancedCtrlG_WMINIT;
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookWMINITaddr), &push, sizeof(push), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookWMINITaddr+1), &hookWMINIT, sizeof(DWORD), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookWMINITaddr+5), &retn, sizeof(retn), NULL);

    DWORD hookWMCOMMANDaddr = 0x4349A;
    DWORD hookWMCOMMAND = (DWORD)advancedCtrlG_WMCOMMAND;
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookWMCOMMANDaddr), &push, sizeof(push), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookWMCOMMANDaddr+1), &hookWMCOMMAND, sizeof(DWORD), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookWMCOMMANDaddr+5), &retn, sizeof(retn), NULL);

    DWORD hookSaveAddr = 0x43682;
    DWORD hookSave = (DWORD)advancedCtrlG_Save;
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookSaveAddr), &push, sizeof(push), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookSaveAddr+1), &hookSave, sizeof(DWORD), NULL);
    WriteProcessMemory(hOlly, (LPVOID)(lpBaseAddr+hookSaveAddr+5), &retn, sizeof(retn), NULL);
}

void __declspec(naked) advancedCtrlG_WMINIT()
{
    lpBase = (DWORD)GetModuleHandle(NULL);
    _asm { mov hGotoDialog, esi };

    //stolen bytes
    _asm {
        mov edx,lpBase
        add edx,0e3B68h
        mov edx,dword ptr [edx]
        push edx
    };
    _asm { pushad };

    //handle WM_INIT
    CheckDlgButton(hGotoDialog, IDC_RADIOVA, BST_CHECKED);

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
    moduleinfo.dwSize = sizeof(MODULEENTRY32);
    Module32First(hSnap, &moduleinfo);

    do {
        SendMessage(GetDlgItem(hGotoDialog, IDC_MODULES), CB_ADDSTRING, 0, (LPARAM)moduleinfo.szModule);
    }
    while(Module32Next(hSnap, &moduleinfo) == TRUE);
    CloseHandle(hSnap);
    SendMessageW(GetDlgItem(hGotoDialog, IDC_MODULES), CB_SETCURSEL, 0, 0);
    //end handle WM_INIT

    _asm {
        add lpBase, 0x432d7
        popad
        jmp [lpBase]
    };
}

void __declspec(naked) advancedCtrlG_WMCOMMAND()
{
    //stolen bytes
    _asm {
        mov edx,ebx
        and dx,0FFFFh
    };
    //end stolen bytes

    lpBase = (DWORD)GetModuleHandle(NULL);
    _asm {
        mov hGotoDialog, esi
        mov wparam, edx
    };

    //handle WM_COMMAND
    if(wparam == IDC_RADIOVA) {
        ShowWindow(GetDlgItem(hGotoDialog, IDC_MODULES), SW_HIDE);
    }
    else if(wparam == IDC_RADIORVA || wparam == IDC_RADIOOFFSET) {
        ShowWindow(GetDlgItem(hGotoDialog, IDC_MODULES), SW_SHOW);
    }

    if(wparam == IDOK ) {
        _asm { pushad };

        if(IsDlgButtonChecked(hGotoDialog, IDC_RADIOVA) == 1) {
            //do nothing, VA is same as original olly does, so just jump back
            _asm {
                popad
                add lpBase, 0x434ab
                jmp [lpBase]
            };
        }
        else if(IsDlgButtonChecked(hGotoDialog, IDC_RADIORVA) == 1) {
            advancedCtrlG_handleGotoExpression(ADDR_TYPE_RVA);
            _asm {
                popad
                add lpBase, 0x434ab
                jmp [lpBase]
            };
        }
        else if(IsDlgButtonChecked(hGotoDialog, IDC_RADIORVA) == 1) {
            advancedCtrlG_handleGotoExpression(ADDR_TYPE_OFFSET);
            _asm {
                popad
                add lpBase, 0x434ab
                jmp [lpBase]
            };
        }

        _asm { popad };
    }
    //end handle WM_COMMAND

    _asm {
        add lpBase, 0x434a5
        jmp [lpBase]
    };
}

void advancedCtrlG_handleGotoExpression(int addrType)
{

}

void __declspec(naked) advancedCtrlG_Save()
{
    lpBase = (DWORD)GetModuleHandle(NULL);

    _asm {
        mov eax,lpBase
        add eax,0063EFCh
        call eax
        add esp,0ch
        add lpBase, 4368ah
        jmp [lpBase]
    };
}