#pragma once


#define MAXIMUM_INSTRUCTION_SIZE (16) //maximum instruction size == 16

int GetDetourLen(const void * lpStart, const int minSize);
void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo);
void * DetourCreate(void * lpFuncOrig, void * lpFuncDetour, bool createTramp);
void * DetourCreateRemote(void * hProcess, void * lpFuncOrig, void * lpFuncDetour, bool createTramp);
int LengthDisassemble(void* DisassmAddress);
