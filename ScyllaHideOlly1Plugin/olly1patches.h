#pragma once
#include <Windows.h>
#include "ollyplugindefinitions.h"

void fixBadPEBugs();
void fixForegroundWindow();
void fixX64Bug();
void fixFPUBug();
void hookOllyBreakpoints();
void ReadTlsAndSetBreakpoints(DWORD dwProcessId, LPVOID baseofImage);
