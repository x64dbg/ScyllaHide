#pragma once

#include <windows.h>

unsigned GetDetourLen(LPCBYTE lpbStart, unsigned uMinSize);
void WriteJumper(LPBYTE lpbFrom, LPCBYTE lpcbTo);
LPBYTE DetourCreate(LPBYTE lpbFuncOrig, LPCBYTE lpcbFuncDetour, BOOL fCreateTramp);
