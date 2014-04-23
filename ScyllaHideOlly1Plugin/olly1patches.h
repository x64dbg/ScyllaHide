#pragma once

void fixBadPEBugs();
void fixForegroundWindow();
void fixX64Bug();
void fixFPUBug();
void hookOllyBreakpoints();
extern "C" void __declspec(dllexport) setTLSBreakpoints();

//olly definitions
extern "C" void _Addtolist(long addr,int highlight,char *format,...);