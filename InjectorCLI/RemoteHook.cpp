#include "RemoteHook.h"
#include <distorm/distorm.h>
#include <distorm/mnemonics.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include "ApplyHooking.h"
#include <stdio.h>

#pragma comment(lib, "distorm.lib")

// GDT selector numbers on AMD64
#define KGDT64_R3_CMCODE (2 * 16)   // user mode 32-bit code
#define KGDT64_R3_CODE (3 * 16)     // user mode 64-bit code
#define RPL_MASK 3

#if !defined(_WIN64)
_DecodeType DecodingType = Decode32Bits;
#else
_DecodeType DecodingType = Decode64Bits;
#endif

#ifdef _WIN64
const int minDetourLen = 2 + sizeof(DWORD)+sizeof(DWORD_PTR) + 1; //8+4+2+1=15
#else
const int minDetourLen = sizeof(DWORD) + 1;
const int detourLenWow64IndirectJmp = 2 + sizeof(DWORD) + sizeof(DWORD); // FF 25 jmp
const int detourLenWow64FarJmp = 1 + sizeof(DWORD) + sizeof(USHORT); // EA far jmp
#endif


extern scl::Settings g_settings;
extern void * HookedNativeCallInternal;
extern void * NativeCallContinue;
extern HOOK_NATIVE_CALL32 * HookNative;
extern int countNativeHooks;
extern bool onceNativeCallContinue;
extern bool fatalFindSyscallIndexFailure;
extern bool fatalAlreadyHookedFailure;

BYTE originalBytes[60] = { 0 };
BYTE changedBytes[60] = { 0 };
BYTE tempSpace[1000] = { 0 };

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

void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo, unsigned char * buf, bool prefixNop)
{
#ifdef _WIN64
    UNREFERENCED_PARAMETER(lpbFrom);

    ULONG i = 0;
    if (prefixNop)
        buf[i++] = 0x90;

    buf[i] = 0xFF;
    buf[i + 1] = 0x25;
    *(DWORD*)&buf[i + 2] = 0;
    *(DWORD_PTR*)&buf[i + 6] = (DWORD_PTR)lpbTo;
#else
    UNREFERENCED_PARAMETER(prefixNop);

    buf[0] = 0xE9;
    *(DWORD*)&buf[1] = (DWORD)((DWORD)lpbTo - (DWORD)lpbFrom - 5);
#endif
}

#ifndef _WIN64
void WriteWow64Jumper(unsigned char * lpbFrom, unsigned char * lpbTo, unsigned char * buf, bool farJmp)
{
    if (!farJmp)
    {
        // Preserve FF 25 prefix (absolute indirect far jmp) at the cost of wasted bytes
        buf[0] = 0xFF;
        buf[1] = 0x25;
        *(DWORD*)&buf[2] = (DWORD)((DWORD)lpbFrom + 6); // +instruction length
        *(DWORD*)&buf[6] = (DWORD)lpbTo;
    }

    // Preserve EA prefix (absolute far jmp), but use the 32 bit segment selector to avoid transitioning into x64 mode
    buf[0] = 0xEA;
    *(DWORD*)&buf[1] = (DWORD)lpbTo;
    *(USHORT*)&buf[5] = (USHORT)(KGDT64_R3_CMCODE | RPL_MASK);
}
#endif

void ClearSyscallBreakpoint(const char* funcName, unsigned char* funcBytes)
{
    // Do nothing if this is not a syscall stub
    if ((funcName == nullptr || funcName[0] == '\0') ||
        (funcName[0] != 'N' || funcName[1] != 't') &&
        (funcName[0] != 'Z' || funcName[1] != 'w'))
        return;

    if (funcBytes[0] == 0xCC || // int 3
        (funcBytes[0] == 0xCD && funcBytes[1] == 0x03) || // long int 3
        (funcBytes[0] == 0xF0 && funcBytes[1] == 0x0B)) // UD2
    {
#ifdef _WIN64
        // x64 stubs always start with 'mov r10, rcx'
        funcBytes[0] = 0x4C;
        funcBytes[1] = 0x8B;
#else
        // For x86 and WOW64 stubs, we can only restore int 3 breakpoints since the second byte is the (unknown) syscall number
        if (funcBytes[0] != 0xCC)
            MessageBoxA(nullptr, "ClearSyscallBreakpoint failed! Please use INT 3 breakpoints instead of long INT 3 or UD2.", "ScyllaHide", MB_ICONERROR);
        else
            funcBytes[0] = 0xB8; // mov eax, <syscall num>
#endif
    }
}

#ifndef _WIN64

DWORD GetEcxSysCallIndex32(const BYTE * data, int dataSize)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[10] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (decomposerResult[0].flags != FLAG_NOT_DECODABLE && decomposerResult[1].flags != FLAG_NOT_DECODABLE)
        {
            if (decomposerResult[0].opcode == I_MOV && decomposerResult[1].opcode == I_MOV)
            {
                if (decomposerResult[1].ops[0].index == R_ECX)
                {
                    return decomposerResult[1].imm.dword;
                }
            }
        }
    }

    return 0;
}

DWORD GetSysCallIndex32(const BYTE * data)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[1] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = MAXIMUM_INSTRUCTION_SIZE;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (decomposerResult[0].flags != FLAG_NOT_DECODABLE)
        {
            if (decomposerResult[0].opcode == I_MOV)
            {
                return decomposerResult[0].imm.dword;
            }
            else
            {
                MessageBoxA(0, "GetSysCallIndex32: Opcode is not I_MOV", "Distorm ERROR", MB_ICONERROR);
            }
        }
        else
        {
            MessageBoxA(0, "GetSysCallIndex32: Distorm flags == FLAG_NOT_DECODABLE", "Distorm ERROR", MB_ICONERROR);
        }
    }
    else
    {
        MessageBoxA(0, "GetSysCallIndex32: distorm_decompose() returned DECRES_INPUTERR", "Distorm ERROR", MB_ICONERROR);
    }

    return (DWORD)-1; // Don't return 0 here, it is a valid syscall index
}

DWORD GetCallDestination(HANDLE hProcess, const BYTE * data, int dataSize)
{
    // Colin Edit, hacky
    if (scl::GetWindowsVersion() < scl::OS_WIN_10) {
        DWORD SysWow64 = (DWORD)__readfsdword(0xC0);
        if (SysWow64) {
            return SysWow64;
        }
    }

    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[100] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (DecodedInstructionsCount > 2)
        {
            // Windows 10 NtQueryInformationProcess specific
            /*
            CPU Disasm
            Address                                      Hex dump                                   Command                                                                        Comments
            77C86C60 NtQueryInformationProcess               B8 19000000                            MOV EAX,19                                                                     ; NTSTATUS ntdll.NtQueryInformationProcess(ProcessHandle,ProcessInfoClass,Buffer,Bufsize,pLength)
            77C86C65                                         E8 04000000                            CALL 77C86C6E
            77C86C6A                                         0000                                   ADD [EAX],AL
            77C86C6C                                         C177 5A 80                             SAL DWORD PTR [EDI+5A],80                                                      ; Shift out of range
            77C86C70                                         7A 03                                  JPE SHORT 77C86C75
            77C86C72                                         4B                                     DEC EBX
            77C86C73                                         75 0A                                  JNE SHORT 77C86C7F
            77C86C75                                         64:FF15 C0000000                       CALL FS:[0C0]
            77C86C7C                                         C2 1400                                RETN 14						    <<<< thinks this is the end of the function
            77C86C7F                                         BA C0B4C977                            MOV EDX,gateway					<<<< Expecting this, finding nothing
            77C86C84                                         FFD2                                   CALL EDX
            77C86C86                                         C2 1400                                RETN 14
            */

            //B8 EA000000      MOV EAX,0EA
            //BA 0003FE7F      MOV EDX,7FFE0300
            //FF12             CALL DWORD PTR DS:[EDX]
            //C2 1400          RETN 14
            //0xB8,0xEA,0x00,0x00,0x00,0xBA,0x00,0x03,0xFE,0x7F,0xFF,0x12,0xC2,0x14,0x00

            //MOV EAX,0EA
            //MOV EDX, 7FFE0300h ; EDX = 7FFE0300h
            //	CALL EDX ; call 7FFE0300h
            //	RETN 14
            //0xB8,0xEA,0x00,0x00,0x00,0xBA,0x00,0x03,0xFE,0x7F,0xFF,0xD2,0xC2,0x14,0x00

            if (decomposerResult[0].flags != FLAG_NOT_DECODABLE && decomposerResult[1].flags != FLAG_NOT_DECODABLE)
            {
                if (decomposerResult[0].opcode == I_MOV && decomposerResult[1].opcode == I_MOV && decomposerResult[2].opcode == I_CALL)
                {
                    if (decomposerResult[2].ops[0].type == O_SMEM) //CALL DWORD PTR DS:[EDX]
                    {
                        DWORD pKUSER_SHARED_DATASysCall = decomposerResult[1].imm.dword;
                        if (pKUSER_SHARED_DATASysCall)
                        {
                            DWORD callDestination = 0;
                            ReadProcessMemory(hProcess, (void*)pKUSER_SHARED_DATASysCall, &callDestination, sizeof(DWORD), 0);
                            return callDestination;
                        }
                    }
                    else if (decomposerResult[2].ops[0].type == O_REG) //CALL EDX
                    {
                        return decomposerResult[1].imm.dword;
                    }
                }
            }


            MessageBoxA(0, "Unknown syscall structure!", "ERROR", 0);
        }
    }

    return NULL;
}

DWORD GetFunctionSizeRETN(BYTE * data, int dataSize)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[100] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        for (unsigned int i = 0; i < DecodedInstructionsCount; i++)
        {
            if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
            {
                if (decomposerResult[i].opcode == I_RET)
                {
                    return (DWORD)(((DWORD_PTR)decomposerResult[i].addr + (DWORD_PTR)decomposerResult[i].size) - (DWORD_PTR)data);
                }
            }
        }

    }

    return 0;
}

DWORD GetCallOffset(const BYTE * data, int dataSize, DWORD * callSize)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[100] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        for (unsigned int i = 0; i < DecodedInstructionsCount; i++)
        {
            if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
            {
                if (decomposerResult[i].opcode == I_CALL || decomposerResult[i].opcode == I_CALL_FAR)
                {
                    *callSize = decomposerResult[i].size;
                    return (DWORD)((DWORD_PTR)decomposerResult[i].addr - (DWORD_PTR)data);
                }
            }
        }

    }

    return 0;
}

// EA 1E 27 E5 74 33 00              JMP FAR 0033:74E5271E ; Far jump
// FF 25 18 12 39 4B                 jmp     ds:_Wow64Transition
BYTE sysWowSpecialJmp[7] = { 0 };
DWORD sysWowSpecialJmpAddress = 0;

void * DetourCreateRemoteNativeSysWow64(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize)
{
    PBYTE trampoline = 0;
    DWORD protect;
    bool detouringFarJmp = true; // TODO: we should always find and hook the true (non-indirect) far jmp into x64 mode. ('jmp Wow64Transition' will also lead to a far jmp eventually)
    bool onceNativeCallContinueWasSet = onceNativeCallContinue;
    onceNativeCallContinue = true;

    // NtQueryInformationProcess on Windows 10 under sysWow64 has an irregular structure, this is a call at +4 or bytes from itself
    // Another case for Windows 10 is 'call $+5'
    bool bSpecialSyscallStructure = (originalBytes[5] == 0xE8 && (originalBytes[6] == 0x04 || originalBytes[6] == 0x00));

    // We're "borrowing" another api's code as a template, the ret must match
    if (bSpecialSyscallStructure)
    {
        //g_log.LogDebug(L"NtQueryInformationProcess Windows 10 detected");

        BYTE syscallAddressBytes[5];	// save syscall id eg. Mov eax, 0x19

        memcpy(syscallAddressBytes, originalBytes, sizeof(syscallAddressBytes));			// Copy the syscall id bytes

        //g_log.LogDebug(L"syscallAddressBytes: %x", syscallAddressBytes);

        // This is a "normal" function and both have a ret 14
        DWORD ntQueryKey = (DWORD)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryKey");

        //g_log.LogDebug(L"NtQueryKey address: %x", ntQueryKey);

        ReadProcessMemory(hProcess, (LPCVOID)ntQueryKey, &originalBytes, sizeof(originalBytes), 0);
        ReadProcessMemory(hProcess, (LPCVOID)ntQueryKey, &changedBytes, sizeof(originalBytes), 0);

        memcpy(originalBytes, syscallAddressBytes, sizeof(syscallAddressBytes));
        memcpy(changedBytes, syscallAddressBytes, sizeof(syscallAddressBytes));
    }

    DWORD funcSize = GetFunctionSizeRETN(originalBytes, sizeof(originalBytes));
    DWORD callSize = 0;
    DWORD callOffset = GetCallOffset(originalBytes, sizeof(originalBytes), &callSize);

    // if the bytes at sysWowSpecialJmpAddress != 0xEA then take our new code path
    // Plugin is expecting something like this at sysWowSpecialJmpAddress: JMP FAR 0033:74E5271E ; Far jump
    // But on Windows 10, we have this at that address
    /*
    CPU Disasm
    77C9B4C0 syscalledx                          |.  64:8B15 30000000                       MOV EDX,FS:[30]						<<<< sysWowSpecialJmpAddress
    77C9B4C7                                     |.  8B92 64040000                          MOV EDX,[EDX+464]
    77C9B4CD                                     |.  F7C2 02000000                          TEST EDX,00000002
    77C9B4D3                                     |.- 74 03                                  JZ SHORT 77C9B4D8
    77C9B4D5                                     |.  CD 2E                                  INT 2E
    77C9B4D7                                     |.  C3                                     RETN
    77C9B4D8                                     \>  EA DFB4C977 3300                       JMP FAR 0033:77C9B4DF               <<<< Expects this
    77C9B4DF                                     /.  41                                     INC ECX
    77C9B4E0                                     \.  FFA7 F8000000                          JMP [EDI+0F8]
    */

    sysWowSpecialJmpAddress = GetCallDestination(hProcess, originalBytes, sizeof(originalBytes));

    // Windows 8.1 Gateway is just a JMP FAR 0033:77C9B4DF
    // Windows 10 Gateway has extra code before the JMP FAR
    // And some Windows 10 has JMP DS:_Wow64Transition
    // The code below adjusts the sysWowSpecialJmpAddress for windows 10
    if ((*(BYTE*)sysWowSpecialJmpAddress != 0xEA) && (*(BYTE*)sysWowSpecialJmpAddress != 0xFF))
    {
        //g_log.LogDebug(L"Adjusting address for Windows 10 gateway ");

        // Windows 10 specific
        BYTE sysWowGatewayOriginalBytes[100] = { 0 };

        ReadProcessMemory(hProcess, (LPCVOID)sysWowSpecialJmpAddress, &sysWowGatewayOriginalBytes, sizeof(sysWowGatewayOriginalBytes), 0);

        DWORD sysWowGatewayFuncSize = GetFunctionSizeRETN(sysWowGatewayOriginalBytes, sizeof(sysWowGatewayOriginalBytes));
        DWORD pActualSysWowSpecialJmpAddress = (sysWowSpecialJmpAddress + sysWowGatewayFuncSize);

        if (*(BYTE*)pActualSysWowSpecialJmpAddress != 0xEA)
        {
            // 0xEA == JMP FAR 0033:XXXXXXXXXX
            MessageBoxA(0, "Windows 10 SysWowSpecialJmpAddress was not found!", "Error", MB_OK);
        }

        sysWowSpecialJmpAddress = pActualSysWowSpecialJmpAddress;
    }

    if (!onceNativeCallContinueWasSet)
    {
        if (ReadProcessMemory(hProcess, (void*)sysWowSpecialJmpAddress, sysWowSpecialJmp, sizeof(sysWowSpecialJmp), 0))
        {
            detouringFarJmp = sysWowSpecialJmp[0] == 0xEA &&
                (sysWowSpecialJmp[5] == (KGDT64_R3_CODE | RPL_MASK) || sysWowSpecialJmp[5] == (KGDT64_R3_CMCODE | RPL_MASK));

            if (sysWowSpecialJmp[0] == 0xE9 || (detouringFarJmp && sysWowSpecialJmp[5] == (KGDT64_R3_CMCODE | RPL_MASK)))
            {
                fatalAlreadyHookedFailure = true;
                MessageBoxA(nullptr, "Function is already hooked!", "ScyllaHide", MB_ICONERROR);
                return nullptr;
            }

            NativeCallContinue = VirtualAllocEx(hProcess, 0, sizeof(sysWowSpecialJmp), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!WriteProcessMemory(hProcess, NativeCallContinue, sysWowSpecialJmp, sizeof(sysWowSpecialJmp), 0))
            {
                MessageBoxA(nullptr, "Failed to write NativeCallContinue routine", "Error", MB_ICONERROR);
                return nullptr;
            }
            VirtualProtectEx(hProcess, NativeCallContinue, sizeof(sysWowSpecialJmp), PAGE_EXECUTE_READ, &protect);
        }
        else
        {
            MessageBoxA(nullptr, "Failed to read WOW64 gateway instruction bytes", "Error", MB_ICONERROR);
            return nullptr;
        }
    }

    if (funcSize != 0 && createTramp)
    {
        trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, sizeof(changedBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (trampoline == nullptr)
            return nullptr;

        changedBytes[callOffset] = 0x68; //PUSH
        *((DWORD*)&changedBytes[callOffset + 1]) = ((DWORD)trampoline + (DWORD)callOffset + 5 + 7);
        memcpy(changedBytes + callOffset + 5, sysWowSpecialJmp, sizeof(sysWowSpecialJmp));

        memcpy(changedBytes + callOffset + 5 + sizeof(sysWowSpecialJmp), originalBytes + callOffset + callSize, funcSize - callOffset - callSize);

        WriteProcessMemory(hProcess, trampoline, changedBytes, sizeof(changedBytes), 0);
        VirtualProtectEx(hProcess, trampoline, sizeof(changedBytes), PAGE_EXECUTE_READ, &protect);
    }

    if (!onceNativeCallContinueWasSet)
    {
        const int detourLen = detouringFarJmp ? detourLenWow64FarJmp : detourLenWow64IndirectJmp;
        if (VirtualProtectEx(hProcess, (void *)sysWowSpecialJmpAddress, detourLen, PAGE_EXECUTE_READWRITE, &protect))
        {
            ZeroMemory(tempSpace, sizeof(tempSpace));
            // Write a faux WOW64 transition far jmp with disregard for space used
            WriteWow64Jumper((PBYTE)sysWowSpecialJmpAddress, (PBYTE)HookedNativeCallInternal, tempSpace, detouringFarJmp);
            if (!WriteProcessMemory(hProcess, (void *)sysWowSpecialJmpAddress, tempSpace, detourLen, 0))
            {
                MessageBoxA(0, "Failed to write new WOW64 gateway", "Error", MB_ICONERROR);
            }

            VirtualProtectEx(hProcess, (void *)sysWowSpecialJmpAddress, detourLen, protect, &protect);
        }
        else
        {
            MessageBoxA(0, "Failed to unprotect WOW64 gateway", "Error", MB_ICONERROR);
        }
    }

    return trampoline;
}

//7C91E4F0 ntdll.KiFastSystemCall  EB F9   JMP 7C91E4EB

BYTE KiSystemCallJmpPatch[] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0xEB, 0xF9 };
BYTE KiSystemCallBackup[20] = { 0 };
DWORD KiSystemCallAddress = 0;
DWORD KiSystemCallBackupSize = 0;

void * DetourCreateRemoteNative32Normal(void * hProcess, const char* funcName, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize)
{
    PBYTE trampoline = 0;
    DWORD protect;

    DWORD funcSize = GetFunctionSizeRETN(originalBytes, sizeof(originalBytes));

    DWORD callSize = 0;
    DWORD callOffset = GetCallOffset(originalBytes, sizeof(originalBytes), &callSize);
    KiSystemCallAddress = GetCallDestination(hProcess, originalBytes, sizeof(originalBytes));

    if (onceNativeCallContinue == false)
    {
        ReadProcessMemory(hProcess, (void*)KiSystemCallAddress, KiSystemCallBackup, sizeof(KiSystemCallBackup), 0);
        KiSystemCallBackupSize = GetFunctionSizeRETN(KiSystemCallBackup, sizeof(KiSystemCallBackup));
        if (KiSystemCallBackupSize)
        {
            NativeCallContinue = VirtualAllocEx(hProcess, 0, KiSystemCallBackupSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (NativeCallContinue)
            {
                WriteProcessMemory(hProcess, NativeCallContinue, KiSystemCallBackup, KiSystemCallBackupSize, 0);
                VirtualProtectEx(hProcess, NativeCallContinue, sizeof(KiSystemCallBackupSize), PAGE_EXECUTE_READ, &protect);
            }
            else
            {
                MessageBoxA(0, "DetourCreateRemoteNative32Normal -> NativeCallContinue", "ERROR", MB_ICONERROR);
            }
        }
        else
        {
            MessageBoxA(0, "DetourCreateRemoteNative32Normal -> KiSystemCallBackupSize", "ERROR", MB_ICONERROR);
        }
    }

    if (funcSize && createTramp)
    {
        trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, sizeof(changedBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        changedBytes[callOffset] = 0x68; //PUSH
        *((DWORD*)&changedBytes[callOffset + 1]) = ((DWORD)trampoline + (DWORD)callOffset + 5 + KiSystemCallBackupSize);
        memcpy(changedBytes + callOffset + 5, KiSystemCallBackup, KiSystemCallBackupSize);

        memcpy(changedBytes + callOffset + 5 + KiSystemCallBackupSize, originalBytes + callOffset + callSize, funcSize - callOffset - callSize);

        WriteProcessMemory(hProcess, trampoline, changedBytes, sizeof(changedBytes), 0);
        VirtualProtectEx(hProcess, trampoline, sizeof(changedBytes), PAGE_EXECUTE_READ, &protect);
    }

    if (onceNativeCallContinue == false)
    {
        DWORD_PTR patchAddr = (DWORD_PTR)KiSystemCallAddress - 5;

        if (VirtualProtectEx(hProcess, (void *)patchAddr, 5 + 2, PAGE_EXECUTE_READWRITE, &protect))
        {
            WriteJumper((PBYTE)patchAddr, (PBYTE)HookedNativeCallInternal, KiSystemCallJmpPatch, false);
            WriteProcessMemory(hProcess, (void *)patchAddr, KiSystemCallJmpPatch, 5 + 2, 0);

            VirtualProtectEx(hProcess, (void *)patchAddr, 5 + 2, protect, &protect);
        }
        onceNativeCallContinue = true;
    }

    return trampoline;
}

void * DetourCreateRemoteNative32(void * hProcess, const char* funcName, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize)
{
    if (!scl::IsWow64Process(hProcess))
    {
        // Handle special cases on native x86 where hooks should be placed inside the function and not at KiFastSystemCall.
        // TODO: why does DetourCreateRemoteNative32Normal even exist? DetourCreateRemote works fine on any OS
        if (scl::GetWindowsVersion() >= scl::OS_WIN_8)
        {
            // The native x86 syscall structure was changed in Windows 8. https://github.com/x64dbg/ScyllaHide/issues/49
            return DetourCreateRemote(hProcess, funcName, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
        }

        if (g_settings.profile_name().find(L"Obsidium") != std::wstring::npos)
        {
            // This is an extremely lame hack because Obsidium doesn't like where we put our hooks
            return DetourCreateRemote(hProcess, funcName, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
        }
    }

    if (fatalFindSyscallIndexFailure || fatalAlreadyHookedFailure)
        return nullptr; // Don't spam user with repeated error message boxes

    memset(changedBytes, 0x90, sizeof(changedBytes));
    memset(originalBytes, 0x90, sizeof(originalBytes));
    memset(tempSpace, 0x90, sizeof(tempSpace));

    if (!ReadProcessMemory(hProcess, lpFuncOrig, originalBytes, sizeof(originalBytes), nullptr))
    {
        MessageBoxA(nullptr, "DetourCreateRemoteNative32->ReadProcessMemory failed.", "ScyllaHide", MB_ICONERROR);
        return nullptr;
    }

    ClearSyscallBreakpoint(funcName, originalBytes);

    memcpy(changedBytes, originalBytes, sizeof(originalBytes));

    DWORD sysCallIndex = GetSysCallIndex32(originalBytes);

    if (sysCallIndex == (DWORD)-1)
    {
        fatalFindSyscallIndexFailure = true; // Do not attempt any more hooks after this
        char errorMessage[256];
        _snprintf_s(errorMessage, sizeof(errorMessage), sizeof(errorMessage) - sizeof(char),
            "Error: syscall index of %hs not found.\nThis can happen if the function is already hooked, or if it contains a breakpoint.", funcName);
        MessageBoxA(nullptr, errorMessage, "ScyllaHide", MB_ICONERROR);
        return nullptr;
    }

    HookNative[countNativeHooks].eaxValue = sysCallIndex;
    HookNative[countNativeHooks].ecxValue = 0;
    HookNative[countNativeHooks].hookedFunction = lpFuncDetour;

    PVOID result;
    if (!scl::IsWow64Process(hProcess))
    {
        result = DetourCreateRemoteNative32Normal(hProcess, funcName, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
    }
    else
    {
        HookNative[countNativeHooks].ecxValue = GetEcxSysCallIndex32(originalBytes, sizeof(originalBytes));
        result = DetourCreateRemoteNativeSysWow64(hProcess, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
    }

    countNativeHooks++;

    return result;
}

#endif

void * DetourCreateRemote(void * hProcess, const char* funcName, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, DWORD * backupSize)
{
    BYTE originalBytes[50] = { 0 };
    BYTE tempSpace[1000] = { 0 };
    PBYTE trampoline = 0;
    DWORD protect;

    bool success = false;

    if (fatalFindSyscallIndexFailure || fatalAlreadyHookedFailure)
        return nullptr; // Don't spam user with repeated error message boxes

    if (!ReadProcessMemory(hProcess, lpFuncOrig, originalBytes, sizeof(originalBytes), nullptr))
    {
        MessageBoxA(nullptr, "DetourCreateRemote->ReadProcessMemory failed.", "ScyllaHide", MB_ICONERROR);
        return nullptr;
    }

    ClearSyscallBreakpoint(funcName, originalBytes);

    // Note that this check will give a false negative in the case that a function is hooked *and* has a breakpoint set on it (now cleared).
    // We can clear the breakpoint or detect the hook, not both. (If the hook is ours, this is actually a hack because we should be properly unhooking)
#ifdef _WIN64
    const bool isHooked = (originalBytes[0] == 0xFF && originalBytes[1] == 0x25) ||
        (originalBytes[0] == 0x90 && originalBytes[1] == 0xFF && originalBytes[2] == 0x25);
#else
    const bool isHooked = originalBytes[0] == 0xE9;
#endif
    if (isHooked)
    {
        fatalAlreadyHookedFailure = true;
        char errorMessage[256];
        _snprintf_s(errorMessage, sizeof(errorMessage), sizeof(errorMessage) - sizeof(char),
            "Error: %hs is already hooked!", funcName);
        MessageBoxA(nullptr, errorMessage, "ScyllaHide", MB_ICONERROR);
        return nullptr;
    }

    int detourLen = GetDetourLen(originalBytes, minDetourLen);

    if (createTramp)
    {
        *backupSize = detourLen;

        trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, detourLen + minDetourLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        WriteProcessMemory(hProcess, trampoline, originalBytes, detourLen, 0);

        ZeroMemory(tempSpace, sizeof(tempSpace));
        WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen, tempSpace, false);
        WriteProcessMemory(hProcess, trampoline + detourLen, tempSpace, minDetourLen, 0);
        VirtualProtectEx(hProcess, trampoline, detourLen + minDetourLen, PAGE_EXECUTE_READ, &protect);
    }

    if (VirtualProtectEx(hProcess, lpFuncOrig, detourLen, PAGE_EXECUTE_READWRITE, &protect))
    {
        ZeroMemory(tempSpace, sizeof(tempSpace));
        WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour, tempSpace, scl::IsWindows64() && !scl::IsWow64Process(NtCurrentProcess));
        WriteProcessMemory(hProcess, lpFuncOrig, tempSpace, minDetourLen, 0);

        VirtualProtectEx(hProcess, lpFuncOrig, detourLen, protect, &protect);
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

    int detourLen = GetDetourLen(lpFuncOrig, minDetourLen);

    if (createTramp)
    {
        trampoline = (PBYTE)VirtualAlloc(0, detourLen + minDetourLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        memcpy(trampoline, lpFuncOrig, detourLen);
        WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen);
        VirtualProtect(trampoline, detourLen + minDetourLen, PAGE_EXECUTE_READ, &protect);
    }


    if (VirtualProtect(lpFuncOrig, detourLen, PAGE_EXECUTE_READWRITE, &protect))
    {
        WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour);

        VirtualProtect(lpFuncOrig, detourLen, protect, &protect);
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
    int totalLen = 0;
    unsigned char * lpDataPos = (unsigned char *)lpStart;

    while (totalLen < minSize)
    {
        int len = (int)LengthDisassemble((void *)lpDataPos);
        if (len < 1) //len < 1 will cause infinite loops
            len = 1;
        lpDataPos += len;
        totalLen += len;
    }

    return totalLen;
}

int LengthDisassemble(LPVOID DisassmAddress)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[1] = { 0 };

    decomposerCi.code = (BYTE *)DisassmAddress;
    decomposerCi.codeLen = MAXIMUM_INSTRUCTION_SIZE;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)DisassmAddress;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (decomposerResult[0].flags != FLAG_NOT_DECODABLE)
        {
            return decomposerResult[0].size;
        }
    }

    return -1; //this is dangerous
}
