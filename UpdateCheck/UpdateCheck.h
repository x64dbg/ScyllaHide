#pragma once
#include <Windows.h>

#pragma comment(lib, "WinInet.lib")

#define UPDATE_CHECK_URL L"http://bitbucket.org/cypherpunk/scylla_wrapper_dll/downloads/version.txt"

bool isNewVersionAvailable(char* curVersion);