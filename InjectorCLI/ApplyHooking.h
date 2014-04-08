#pragma once
#include <windows.h>
#include "..\HookLibrary\HookMain.h"


void ApplyHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
