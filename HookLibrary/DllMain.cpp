#include <ntdll/ntdll.h>

#pragma comment(linker, "/ENTRY:DllMain")

//----------------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    LdrDisableThreadCalloutsForDll(hinstDLL);
    return TRUE;
}
