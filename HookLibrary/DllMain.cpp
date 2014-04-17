#include "HookMain.h"
#include "Hook.h"
#include "..\ntdll\ntdll.h"
#include "HookedFunctions.h"
#include "PebHider.h"

HOOK_DLL_EXCHANGE DllExchange = { 0 };

#pragma comment(linker, "/ENTRY:DllMain")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
