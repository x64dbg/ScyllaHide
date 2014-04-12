#include "RemoteHook.h"
#include <windows.h>
#include "distorm.h"
#include "mnemonics.h"

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

bool IsSysWow64()
{
	return ((DWORD)__readfsdword(0xC0) != 0);
}

DWORD GetJmpTableLocation(BYTE * data, int dataSize)
{
	DWORD SysWow64 = (DWORD)__readfsdword(0xC0);
	if (SysWow64)
	{
		return SysWow64;
	}
	else
	{

	}

	return 0;
}

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
					return ((DWORD_PTR)decomposerResult[i].addr + (DWORD_PTR)decomposerResult[i].size) - (DWORD_PTR)data;
				}
			}
		}

	}

	return 0;
}

void * DetourCreateRemoteNative32(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool notUsed)
{
	BYTE originalBytes[50] = { 0 };
	BYTE tempSpace[1000] = { 0 };
	PBYTE trampoline = 0;
	DWORD protect;
	bool success = false;

	ReadProcessMemory(hProcess, lpFuncOrig, originalBytes, sizeof(originalBytes), 0);

	DWORD sysCallIndex = GetSysCallIndex32(originalBytes);
	DWORD funcSize = GetFunctionSizeRETN(originalBytes, sizeof(originalBytes));

	if (funcSize && sysCallIndex)
	{
		trampoline = (PBYTE)VirtualAllocEx(hProcess, 0, funcSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!trampoline)
			return 0;
		WriteProcessMemory(hProcess, trampoline, originalBytes, funcSize, 0);
	}

	if (!success)
	{
		VirtualFree(trampoline, 0, MEM_RELEASE);
		trampoline = 0;
	}
	return trampoline;
}


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