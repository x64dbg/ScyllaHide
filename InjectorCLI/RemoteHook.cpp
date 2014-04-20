#include "RemoteHook.h"
#include <windows.h>
#include "distorm.h"
#include "mnemonics.h"
#include "ApplyHooking.h"

#if !defined(_WIN64)
_DecodeType DecodingType = Decode32Bits;
#else
_DecodeType DecodingType = Decode64Bits;
#endif

#ifdef _WIN64
const int minDetourLen = 2 + sizeof(DWORD)+sizeof(DWORD_PTR); //8+4+2=14
#else
const int minDetourLen = sizeof(DWORD)+1;
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

DWORD GetEcxSysCallIndex32(BYTE * data, int dataSize)
{
	unsigned int DecodedInstructionsCount = 0;
	_CodeInfo decomposerCi = {0};
	_DInst decomposerResult[10] = {0};

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

DWORD GetSysCallIndex32(BYTE * data)
{
	unsigned int DecodedInstructionsCount = 0;
	_CodeInfo decomposerCi = {0};
	_DInst decomposerResult[1] = {0};

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
		}
	}

	return 0;
}

#ifndef _WIN64

bool IsSysWow64()
{
	return ((DWORD)__readfsdword(0xC0) != 0);
}

DWORD GetCallDestination(HANDLE hProcess, BYTE * data, int dataSize)
{
	DWORD SysWow64 = (DWORD)__readfsdword(0xC0);
	if (SysWow64)
	{
		return SysWow64;
	}
	else
	{
		unsigned int DecodedInstructionsCount = 0;
		_CodeInfo decomposerCi = {0};
		_DInst decomposerResult[100] = {0};

		decomposerCi.code = data;
		decomposerCi.codeLen = dataSize;
		decomposerCi.dt = DecodingType;
		decomposerCi.codeOffset = (LONG_PTR)data;

		if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
		{
			if (DecodedInstructionsCount > 2)
			{

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
	}

	return 0;
}

#endif

DWORD GetFunctionSizeRETN( BYTE * data, int dataSize )
{
	unsigned int DecodedInstructionsCount = 0;
	_CodeInfo decomposerCi = {0};
	_DInst decomposerResult[100] = {0};

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

DWORD GetCallOffset( BYTE * data, int dataSize, DWORD * callSize )
{
	unsigned int DecodedInstructionsCount = 0;
	_CodeInfo decomposerCi = {0};
	_DInst decomposerResult[100] = {0};

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

BYTE sysWowSpecialJmp[7] = { 0 };//EA 1E27E574 3300              JMP FAR 0033:74E5271E ; Far jump
DWORD sysWowSpecialJmpAddress = 0;

void * DetourCreateRemoteNativeSysWow64(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp,unsigned long * backupSize)
{
	PBYTE trampoline = 0;
	DWORD protect;

	DWORD funcSize = GetFunctionSizeRETN(originalBytes, sizeof(originalBytes));

	DWORD callSize = 0;
	DWORD callOffset = GetCallOffset(originalBytes, sizeof(originalBytes), &callSize);
	sysWowSpecialJmpAddress = GetCallDestination(hProcess, originalBytes, sizeof(originalBytes));

	if (onceNativeCallContinue == false)
	{
		ReadProcessMemory(hProcess, (void*)sysWowSpecialJmpAddress, sysWowSpecialJmp, sizeof(sysWowSpecialJmp), 0);
		NativeCallContinue = VirtualAllocEx(hProcess, 0, sizeof(sysWowSpecialJmp), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(hProcess, NativeCallContinue, sysWowSpecialJmp, sizeof(sysWowSpecialJmp), 0);
	}

	if (funcSize && createTramp)
	{
		trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, sizeof(changedBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline)
			return 0;

		changedBytes[callOffset] = 0x68; //PUSH
		*((DWORD*)&changedBytes[callOffset+1]) = ((DWORD)trampoline+(DWORD)callOffset+5+7);
		memcpy(changedBytes + callOffset + 5, sysWowSpecialJmp, sizeof(sysWowSpecialJmp));

		memcpy(changedBytes + callOffset + 5 + sizeof(sysWowSpecialJmp), originalBytes + callOffset + callSize, funcSize - callOffset - callSize);

		WriteProcessMemory(hProcess, trampoline, changedBytes, sizeof(changedBytes), 0);
	}

	if (onceNativeCallContinue == false)
	{
		if (VirtualProtectEx(hProcess, (void *)sysWowSpecialJmpAddress, minDetourLen, PAGE_EXECUTE_READWRITE, &protect))
		{
			ZeroMemory(tempSpace, sizeof(tempSpace));
			WriteJumper((PBYTE)sysWowSpecialJmpAddress, (PBYTE)HookedNativeCallInternal, tempSpace);
			WriteProcessMemory(hProcess, (void *)sysWowSpecialJmpAddress, tempSpace, minDetourLen, 0);

			VirtualProtectEx(hProcess, (void *)sysWowSpecialJmpAddress, minDetourLen, protect, &protect);
			FlushInstructionCache(hProcess, (void *)sysWowSpecialJmpAddress, minDetourLen);
		}
		onceNativeCallContinue = true;
	}

	return trampoline;
}
#endif

//7C91E4F0 ntdll.KiFastSystemCall  EB F9   JMP 7C91E4EB

BYTE KiSystemCallJmpPatch[] = {0xE9, 0x00, 0x00, 0x00, 0x00, 0xEB, 0xF9};
BYTE KiSystemCallBackup[20] = {0};
DWORD KiSystemCallAddress = 0;
DWORD KiSystemCallBackupSize = 0;
#ifndef _WIN64
void * DetourCreateRemoteNative32Normal(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp,unsigned long * backupSize)
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
		NativeCallContinue = VirtualAllocEx(hProcess, 0, KiSystemCallBackupSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(hProcess, NativeCallContinue, KiSystemCallBackup, KiSystemCallBackupSize, 0);
	}

	if (funcSize && createTramp)
	{
		trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, sizeof(changedBytes), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline)
			return 0;

		changedBytes[callOffset] = 0x68; //PUSH
		*((DWORD*)&changedBytes[callOffset+1]) = ((DWORD)trampoline+(DWORD)callOffset+5+KiSystemCallBackupSize);
		memcpy(changedBytes + callOffset + 5, KiSystemCallBackup, KiSystemCallBackupSize);

		memcpy(changedBytes + callOffset + 5 + KiSystemCallBackupSize, originalBytes + callOffset + callSize, funcSize - callOffset - callSize);

		WriteProcessMemory(hProcess, trampoline, changedBytes, sizeof(changedBytes), 0);
	}

	if (onceNativeCallContinue == false)
	{
		DWORD_PTR patchAddr = (DWORD_PTR)KiSystemCallAddress - 5;

		if (VirtualProtectEx(hProcess, (void *)patchAddr, 5+2, PAGE_EXECUTE_READWRITE, &protect))
		{

			WriteJumper((PBYTE)patchAddr, (PBYTE)HookedNativeCallInternal, KiSystemCallJmpPatch);
			WriteProcessMemory(hProcess, (void *)patchAddr, KiSystemCallJmpPatch, 5+2, 0);

			VirtualProtectEx(hProcess, (void *)patchAddr, 5+2, protect, &protect);
			FlushInstructionCache(hProcess, (void *)patchAddr, 5+2);
		}
		onceNativeCallContinue = true;
	}

	return trampoline;
}
#endif
#ifndef _WIN64
void * DetourCreateRemoteNative32(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp,unsigned long * backupSize)
{
	memset(changedBytes, 0x90, sizeof(changedBytes));
	memset(originalBytes, 0x90, sizeof(originalBytes));
	memset(tempSpace, 0x90, sizeof(tempSpace));

	ReadProcessMemory(hProcess, lpFuncOrig, originalBytes, sizeof(originalBytes), 0);

	memcpy(changedBytes, originalBytes, sizeof(originalBytes));

	DWORD sysCallIndex = GetSysCallIndex32(originalBytes);

	PVOID result = 0;

	if (sysCallIndex)
	{
		HookNative[countNativeHooks].eaxValue = sysCallIndex;
		HookNative[countNativeHooks].ecxValue = 0;
		HookNative[countNativeHooks].hookedFunction = lpFuncDetour;

		if (IsSysWow64() == false)
		{
			result = DetourCreateRemoteNative32Normal(hProcess, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
		}
		else
		{
			HookNative[countNativeHooks].ecxValue = GetEcxSysCallIndex32(originalBytes, sizeof(originalBytes));
			result = DetourCreateRemoteNativeSysWow64(hProcess, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
		}
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
        len = (int)LengthDisassemble((void *)lpDataPos);
        lpDataPos += len;
        totalLen += len;
    }

    return totalLen;
}

int LengthDisassemble(LPVOID DisassmAddress)
{
	unsigned int DecodedInstructionsCount = 0;
	_CodeInfo decomposerCi = {0};
	_DInst decomposerResult[1] = {0};

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

	return -1;
}