#pragma once
#include <Windows.h>

#pragma comment(lib, "WinInet.lib")

#define UPDATE_CHECK_URL L"http://bitbucket.org/NtQuery/scyllahide/downloads/version.txt"

bool isNewVersionAvailable();