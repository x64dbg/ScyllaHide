#pragma once

#ifndef _WIN64
#pragma comment(lib, "LDE64")
extern "C" unsigned int __stdcall LDE(const void * lpData, unsigned int size);
#else
#pragma comment(lib, "LDE64x64")
extern "C" unsigned int __fastcall LDE(const void * lpData, unsigned int size);
#endif

int GetDetourLen(const void * lpStart, const int minSize);
void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo);
void * DetourCreate(void * lpFuncOrig, void * lpFuncDetour, bool createTramp);

