#pragma once

void fixBadPEBugs();
void fixForegroundWindow();

//olly definitions
extern "C" void _Addtolist(long addr,int highlight,char *format,...);