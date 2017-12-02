#include "RemoteHook.h"
#include <distorm/distorm.h>
#include <distorm/mnemonics.h>
#include <Scylla/OsInfo.h>
#include "ApplyHooking.h"

#pragma comment(lib, "distorm.lib")

#if !defined(_WIN64)
_DecodeType DecodingType = Decode32Bits;
#else
_DecodeType DecodingType = Decode64Bits;
#endif

#ifdef _WIN64
const int minDetourLen = 2 + sizeof(DWORD)+sizeof(DWORD_PTR) + 1; //8+4+2+1=15
#else
const int minDetourLen = sizeof(DWORD) + 1 + 1;
#endif


extern void * HookedNativeCallInternal;
extern void * NativeCallContinue;
extern HOOK_NATIVE_CALL32 * HookNative;
extern int countNativeHooks;
extern bool onceNativeCallContinue;

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
    ULONG i = 0;
    if (prefixNop)
        buf[i++] = 0x90;

#ifdef _WIN64
    UNREFERENCED_PARAMETER(lpbFrom);

    buf[i] = 0xFF;
    buf[i + 1] = 0x25;
    *(DWORD*)&buf[i + 2] = 0;
    *(DWORD_PTR*)&buf[i + 6] = (DWORD_PTR)lpbTo;
#else
    buf[i] = 0xE9;
    *(DWORD*)&buf[i + 1] = (DWORD)((DWORD)lpbTo - (DWORD)lpbFrom - (i + 5));
#endif

}

void * FixWindowsRedirects(void * address)
{
    BYTE * pb = (BYTE *)address;
    int len = (int)LengthDisassemble((void *)address);

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
                MessageBoxA(0, "Distorm opcode no I_MOV", "Distorm ERROR", MB_ICONERROR);
            }
        }
        else
        {
            MessageBoxA(0, "Distorm flags FLAG_NOT_DECODABLE", "Distorm ERROR", MB_ICONERROR);
        }
    }
    else
    {
        MessageBoxA(0, "Distorm distorm_decompose error DECRES_INPUTERR", "Distorm ERROR", MB_ICONERROR);
    }

    return 0;
}

#ifndef _WIN64


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

#endif

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

#ifndef _WIN64

// EA 1E 27 E5 74 33 00              JMP FAR 0033:74E5271E ; Far jump
// FF 25 18 12 39 4B                 jmp     ds:_Wow64Transition
BYTE sysWowSpecialJmp[7] = { 0 };
DWORD sysWowSpecialJmpAddress = 0;

void * DetourCreateRemoteNativeSysWow64(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize)
{
    PBYTE trampoline = 0;
    DWORD protect;

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

    if (onceNativeCallContinue == false)
    {
        ReadProcessMemory(hProcess, (void*)sysWowSpecialJmpAddress, sysWowSpecialJmp, sizeof(sysWowSpecialJmp), 0);
        NativeCallContinue = VirtualAllocEx(hProcess, 0, sizeof(sysWowSpecialJmp), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!WriteProcessMemory(hProcess, NativeCallContinue, sysWowSpecialJmp, sizeof(sysWowSpecialJmp), 0))
        {
            MessageBoxA(0, "Failed to write NativeCallContinue routine", "Error", MB_ICONERROR);
        }
    }

    if (funcSize && createTramp)
    {
        trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, sizeof(changedBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        changedBytes[callOffset] = 0x68; //PUSH
        *((DWORD*)&changedBytes[callOffset + 1]) = ((DWORD)trampoline + (DWORD)callOffset + 5 + 7);
        memcpy(changedBytes + callOffset + 5, sysWowSpecialJmp, sizeof(sysWowSpecialJmp));

        memcpy(changedBytes + callOffset + 5 + sizeof(sysWowSpecialJmp), originalBytes + callOffset + callSize, funcSize - callOffset - callSize);

        WriteProcessMemory(hProcess, trampoline, changedBytes, sizeof(changedBytes), 0);
    }

    if (onceNativeCallContinue == false)
    {
        if (VirtualProtectEx(hProcess, (void *)sysWowSpecialJmpAddress, minDetourLen, PAGE_EXECUTE_READWRITE, &protect))
        {
            ZeroMemory(tempSpace, sizeof(tempSpace));
            WriteJumper((PBYTE)sysWowSpecialJmpAddress, (PBYTE)HookedNativeCallInternal, tempSpace, true);
            if (!WriteProcessMemory(hProcess, (void *)sysWowSpecialJmpAddress, tempSpace, minDetourLen, 0))
            {
                MessageBoxA(0, "Failed to write new WOW64 gateway", "Error", MB_ICONERROR);
            }

            VirtualProtectEx(hProcess, (void *)sysWowSpecialJmpAddress, minDetourLen, protect, &protect);
            FlushInstructionCache(hProcess, (void *)sysWowSpecialJmpAddress, minDetourLen);
        }
        else
        {
            MessageBoxA(0, "Failed to unprotect WOW64 gateway", "Error", MB_ICONERROR);
        }
        onceNativeCallContinue = true;
    }

    return trampoline;
}
#endif

//7C91E4F0 ntdll.KiFastSystemCall  EB F9   JMP 7C91E4EB

BYTE KiSystemCallJmpPatch[] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0xEB, 0xF9 };
BYTE KiSystemCallBackup[20] = { 0 };
DWORD KiSystemCallAddress = 0;
DWORD KiSystemCallBackupSize = 0;
#ifndef _WIN64
void * DetourCreateRemoteNative32Normal(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize)
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
    }

    if (onceNativeCallContinue == false)
    {
        DWORD_PTR patchAddr = (DWORD_PTR)KiSystemCallAddress - 5;

        if (VirtualProtectEx(hProcess, (void *)patchAddr, 5 + 2, PAGE_EXECUTE_READWRITE, &protect))
        {
            WriteJumper((PBYTE)patchAddr, (PBYTE)HookedNativeCallInternal, KiSystemCallJmpPatch, true);
            WriteProcessMemory(hProcess, (void *)patchAddr, KiSystemCallJmpPatch, 5 + 2, 0);

            VirtualProtectEx(hProcess, (void *)patchAddr, 5 + 2, protect, &protect);
            FlushInstructionCache(hProcess, (void *)patchAddr, 5 + 2);
        }
        onceNativeCallContinue = true;
    }

    return trampoline;
}
#endif
#ifndef _WIN64
void * DetourCreateRemoteNative32(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize)
{
    if (scl::GetWindowsVersion() >= scl::OS_WIN_8 && !scl::IsWow64Process(hProcess))
    {
        // The native x86 syscall structure was changed in Windows 8. https://github.com/x64dbg/ScyllaHide/issues/49
        return DetourCreateRemote(hProcess, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
    }

    memset(changedBytes, 0x90, sizeof(changedBytes));
    memset(originalBytes, 0x90, sizeof(originalBytes));
    memset(tempSpace, 0x90, sizeof(tempSpace));

    if (!ReadProcessMemory(hProcess, lpFuncOrig, originalBytes, sizeof(originalBytes), 0))
    {
        MessageBoxA(0, "DetourCreateRemoteNative32->ReadProcessMemory failed", "ERROR", MB_ICONERROR);
        return NULL;
    }

    memcpy(changedBytes, originalBytes, sizeof(originalBytes));

    DWORD sysCallIndex = GetSysCallIndex32(originalBytes);

    PVOID result = 0;

    if (!sysCallIndex)
    {
        MessageBoxA(0, "GetSysCallIndex32 -> sysCallIndex not found", "ERROR", MB_ICONERROR);
        return NULL;
    }

    HookNative[countNativeHooks].eaxValue = sysCallIndex;
    HookNative[countNativeHooks].ecxValue = 0;
    HookNative[countNativeHooks].hookedFunction = lpFuncDetour;

    if (!scl::IsWow64Process(hProcess))
    {
        result = DetourCreateRemoteNative32Normal(hProcess, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
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

void * DetourCreateRemote(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, DWORD * backupSize)
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
        *backupSize = detourLen;

        trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, detourLen + minDetourLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        WriteProcessMemory(hProcess, trampoline, originalBytes, detourLen, 0);

        ZeroMemory(tempSpace, sizeof(tempSpace));
        WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen, tempSpace, false);
        WriteProcessMemory(hProcess, trampoline + detourLen, tempSpace, minDetourLen, 0);
    }

    if (VirtualProtectEx(hProcess, lpFuncOrig, detourLen, PAGE_EXECUTE_READWRITE, &protect))
    {
        ZeroMemory(tempSpace, sizeof(tempSpace));
        WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour, tempSpace, true);
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
