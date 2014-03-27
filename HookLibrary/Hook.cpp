#include "Hook.h"
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

void * DetourCreate(void * lpFuncOrig, void * lpFuncDetour)
{
	DWORD protect;
#ifdef _WIN64
	const int minDetourLen = 2 + sizeof(DWORD) + sizeof(DWORD_PTR);
#else
	const int minDetourLen = sizeof(DWORD)+1;
#endif
	bool success = false;

	//lpFuncOrig = FixWindowsRedirects(lpFuncOrig);

	int detourLen = GetDetourLen(lpFuncOrig, minDetourLen);

	PBYTE trampoline = (PBYTE)VirtualAlloc(0, detourLen + minDetourLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!trampoline)
		return 0;

	memcpy(trampoline, lpFuncOrig, detourLen);
	WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen);

	if (VirtualProtect(lpFuncOrig, detourLen, PAGE_EXECUTE_READWRITE, &protect))
	{
		WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour);

		VirtualProtect(lpFuncOrig, detourLen, protect, &protect);
		FlushInstructionCache(GetCurrentProcess(), lpFuncOrig, detourLen);
		success = true;
	}

	if (!success)
	{
		VirtualFree(trampoline, 0, MEM_RELEASE);
		trampoline = 0;
	}
	return trampoline;
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