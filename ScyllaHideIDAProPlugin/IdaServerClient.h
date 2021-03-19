#pragma once

#include <pro.h>

bool StartWinsock();
bool ConnectToServer(const char * host, const char * port);
bool SendEventToServer(unsigned long notif_code, unsigned long ProcessId);
void CloseServerSocket();
bool GetHost(const qstring &input, qstring &output);
bool SendInjectToServer(unsigned long ProcessId);
