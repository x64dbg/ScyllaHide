#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define IDA_SERVER_DEFAULT_PORT_TEXT "1337"
#define IDA_SERVER_DEFAULT_PORT 1337

BOOL startWinsock();
void startListen();
void handleClient( SOCKET ClientSocket );


