#include <windows.h>

#pragma comment(linker, "/ENTRY:DllMain")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}