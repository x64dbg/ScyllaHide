#pragma once
#include <Windows.h>
#include "ollyplugindefinitions.h"

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

//hooks
void handleBreakpoints();
void handleSprintf();
