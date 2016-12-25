#pragma once

#include <Windows.h>
#pragma pack(push)
#include <ollydbg1/ollyplugindefinitions.h>
#pragma pack(pop)

#define ADDR_TYPE_RVA 2
#define ADDR_TYPE_OFFSET 3

void fixBadPEBugs();
void fixForegroundWindow();
void fixX64Bug();
void fixFPUBug();
void patchEPOutsideCode();
void hookOllyBreakpoints();
void fixSprintfBug();
DWORD _stdcall removeEPBreak(LPVOID lpParam);
void ReadTlsAndSetBreakpoints(DWORD dwProcessId, LPVOID baseofImage);
void advcancedCtrlG();
bool advancedCtrlG_handleGotoExpression(int addrType);
void fixBadPEImage();
void skipCompressedCode();
void skipLoadDll();
void fixNTSymbols();
void fixFaultyHandleOnExit();
void hookOllyWindowProcs();

//hooks
void handleBreakpoints();
void handleSprintf();
void advancedCtrlG_WMINIT();
void advancedCtrlG_WMCOMMAND();
void advancedCtrlG_Save();
void hookedOllyWindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
