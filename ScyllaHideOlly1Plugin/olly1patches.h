#pragma once

void fixBadPEBugs();
void fixForegroundWindow();
void fixX64Bug();
void fixFPUBug();

//olly definitions
extern "C" void _Addtolist(long addr,int highlight,char *format,...);