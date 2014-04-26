#include "idaserver.h"


WSADATA wsaData;
BOOL isWinsockUp;


char * ListenPortString = IDA_SERVER_DEFAULT_PORT_TEXT;
unsigned short ListenPort = IDA_SERVER_DEFAULT_PORT;

IDA_SERVER_EXCHANGE idaExchange = {0};

int main(int argc, char *argv[])
{
	printf("size of IDA_SERVER_EXCHANGE %d\n\n", sizeof(IDA_SERVER_EXCHANGE));


	printf("Starting IDA Server...\n");

	if (argc > 1)
	{
		ListenPortString = argv[1];
		ListenPort = (unsigned short)strtoul(ListenPortString, 0, 10);
	}
	printf("Listen Port: %d\n", ListenPort);


	if (startWinsock())
	{
		printf("Starting Winsock: DONE\n");
		startListen();
	}
	

	getchar();
	return 0;
}



void startListen()
{
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, ListenPortString, &hints, &result);
	if ( iResult != 0 )
	{
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET)
	{
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return;
	}

	// Setup the TCP listening socket
	iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR)
	{
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR)
	{
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return;
	}

	printf("Listening on port %s...\n",ListenPortString);

	while(1)
	{
		ClientSocket = accept(ListenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET)
		{
			printf("accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return;
		}
		else
		{
			printf("Accepted a client\n");
			handleClient(ClientSocket);
			closesocket(ClientSocket);
		}
	}


}

static DWORD ProcessId = 0;
static bool bHooked = false;

void handleClient( SOCKET ClientSocket )
{
	int iResult;
	do
	{
		iResult = recv(ClientSocket, (char*)&idaExchange, sizeof(IDA_SERVER_EXCHANGE), 0);
		if (iResult == sizeof(IDA_SERVER_EXCHANGE))
		{
			switch (idaExchange.notif_code)
			{
			case dbg_process_attach:
				{

					break;
				}
			case dbg_process_start:
				{

					//ProcessId = idaExchange.ProcessId;
					//bHooked = false;
					//ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

					//if (!bHooked)
					//{
					//	bHooked = true;
					//	startInjection(ProcessId, ScyllaHideDllPath, true);
					//}

					break;
				}
			case dbg_process_exit:
				{

					break;
				}
			case dbg_library_load:
				{

					break;
				}
			}
		}
		else if (iResult == 0)
		{
			printf("Connection closing...\n");
		}
		else if (iResult < 0)
		{
			printf("recv failed with error: %d\n", WSAGetLastError());
		}
		else
		{
			printf("Something is wrong, unknown struct size %d\n",sizeof(IDA_SERVER_EXCHANGE));
		}
	} while (iResult > 0);
}


BOOL startWinsock()
{
	isWinsockUp = TRUE;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("WSAStartup failed: %d\n", iResult);
		isWinsockUp = FALSE;
	}

	return isWinsockUp;
}

void closeWinsock()
{
	WSACleanup();
	isWinsockUp = FALSE;
}