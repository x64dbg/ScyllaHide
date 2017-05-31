#include <ntdll/ntdll.h>

#ifdef NDEBUG
#pragma comment(linker, "/ENTRY:DllMain")
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    LdrDisableThreadCalloutsForDll(hinstDLL);
    return TRUE;
}