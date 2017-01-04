#pragma once

#include "..\HookLibrary\HookMain.h"

bool ReadNtApiInformation(const wchar_t *szFilePath, HOOK_DLL_EXCHANGE *pDllExchangeLoader);
