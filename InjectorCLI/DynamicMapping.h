#include <windows.h>

LPVOID MapModuleToProcess(HANDLE hProcess, BYTE * dllMemory);
void DoBaseRelocation(PIMAGE_BASE_RELOCATION relocation, DWORD_PTR memory, DWORD_PTR dwDelta);
DWORD GetDllFunctionAddressRVA(BYTE * dllMemory, LPCSTR apiName);
DWORD RVAToOffset(PIMAGE_NT_HEADERS pNtHdr, DWORD dwRVA);
HMODULE GetModuleBaseRemote(HANDLE hProcess, const wchar_t* szDLLName);
DWORD StartDllInitFunction(HANDLE hProcess, DWORD_PTR functionAddress, LPVOID imageBase);
