#pragma once
#include <windows.h>
#include "..\HookLibrary\HookMain.h"


bool ApplyHook(HOOK_DLL_EXCHANGE * dllexchange, HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
