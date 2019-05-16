#include "IdaServerClient.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Scylla/Settings.h>

#include "..\ScyllaHideIDAServer\IdaServerExchange.h"
#include "..\PluginGeneric\Injector.h"

#pragma comment (lib, "Ws2_32.lib")

extern scl::Settings g_settings;


SOCKET serverSock = INVALID_SOCKET;
WSADATA wsaData;

IDA_SERVER_EXCHANGE idaExchange = {0};
extern wchar_t DllPathForInjection[MAX_PATH];

bool StartWinsock()
{
	bool isWinsockUp = true;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		isWinsockUp = false;
	}

	return isWinsockUp;
}

bool SendInjectToServer(unsigned long ProcessId)
{
	return SendEventToServer(inject_dll, ProcessId);
}

bool SendEventToServer(unsigned long notif_code, unsigned long ProcessId)
{
	idaExchange.notif_code = notif_code;
	idaExchange.ProcessId = ProcessId;

    idaExchange.EnablePebBeingDebugged = g_settings.opts().fixPebBeingDebugged;
    idaExchange.EnablePebHeapFlags = g_settings.opts().fixPebHeapFlags;
    idaExchange.EnablePebNtGlobalFlag = g_settings.opts().fixPebNtGlobalFlag;
    idaExchange.EnablePebStartupInfo = g_settings.opts().fixPebStartupInfo;
    idaExchange.EnableOutputDebugStringHook = g_settings.opts().hookOutputDebugStringA;
    idaExchange.EnableNtSetInformationThreadHook = g_settings.opts().hookNtSetInformationThread;
    idaExchange.EnableNtQueryInformationProcessHook = g_settings.opts().hookNtQueryInformationProcess;
    idaExchange.EnableNtQuerySystemInformationHook = g_settings.opts().hookNtQuerySystemInformation;
    idaExchange.EnableNtQueryObjectHook = g_settings.opts().hookNtQueryObject;
    idaExchange.EnableNtYieldExecutionHook = g_settings.opts().hookNtYieldExecution;
    idaExchange.EnableNtCloseHook = g_settings.opts().hookNtClose;
    idaExchange.EnableNtCreateThreadExHook = g_settings.opts().hookNtCreateThreadEx;
    idaExchange.EnablePreventThreadCreation = g_settings.opts().preventThreadCreation;

    idaExchange.EnableNtGetContextThreadHook = g_settings.opts().hookNtGetContextThread;
    idaExchange.EnableNtSetContextThreadHook = g_settings.opts().hookNtSetContextThread;
    idaExchange.EnableNtContinueHook = g_settings.opts().hookNtContinue;
    idaExchange.EnableKiUserExceptionDispatcherHook = g_settings.opts().hookKiUserExceptionDispatcher;
    idaExchange.EnableNtSetInformationProcessHook = g_settings.opts().hookNtSetInformationProcess;
    idaExchange.EnableMalwareRunPeUnpacker = g_settings.opts().malwareRunpeUnpacker;

    idaExchange.EnableGetTickCountHook = g_settings.opts().hookGetTickCount;
    idaExchange.EnableGetTickCount64Hook = g_settings.opts().hookGetTickCount64;
    idaExchange.EnableGetLocalTimeHook = g_settings.opts().hookGetLocalTime;
    idaExchange.EnableGetSystemTimeHook = g_settings.opts().hookGetSystemTime;
    idaExchange.EnableNtQuerySystemTimeHook = g_settings.opts().hookNtQuerySystemTime;
    idaExchange.EnableNtQueryPerformanceCounterHook = g_settings.opts().hookNtQueryPerformanceCounter;

    idaExchange.EnableNtUserBlockInputHook = g_settings.opts().hookNtUserBlockInput;
    idaExchange.EnableNtUserFindWindowExHook = g_settings.opts().hookNtUserFindWindowEx;
    idaExchange.EnableNtUserBuildHwndListHook = g_settings.opts().hookNtUserBuildHwndList;
    idaExchange.EnableNtUserQueryWindowHook = g_settings.opts().hookNtUserQueryWindow;
    idaExchange.EnableNtSetDebugFilterStateHook = g_settings.opts().hookNtSetDebugFilterState;
    idaExchange.DllInjectNormal = g_settings.opts().dllNormal;
    idaExchange.DllInjectStealth = g_settings.opts().dllStealth;
    idaExchange.UnloadDllAfterInjection = g_settings.opts().dllUnload;

	wcscpy_s(idaExchange.DllPathForInjection, DllPathForInjection);


	int iResult = send(serverSock, (char*)&idaExchange, (int)sizeof(IDA_SERVER_EXCHANGE), 0);
	if (iResult == SOCKET_ERROR)
	{
		//printf("send failed with error: %d\n", WSAGetLastError());
		return false;
	}

	idaExchange.result = RESULT_FAILED;

	iResult = recv(serverSock, (char*)&idaExchange, (int)sizeof(IDA_SERVER_EXCHANGE), 0);

	if (iResult == sizeof(IDA_SERVER_EXCHANGE))
	{
		if (idaExchange.result == RESULT_SUCCESS)
		{
			return true;
		}
	}

	return false;
}

void CloseServerSocket()
{
	closesocket(serverSock);
	serverSock = INVALID_SOCKET;
}

bool ConnectToServer(const char * host, const char * port)
{
	int iResult;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(host, port, &hints, &result);
	if ( iResult != 0 )
	{
		//printf("getaddrinfo failed with error: %d\n", iResult);
		return false;
	}

	// Attempt to connect to an address until one succeeds
	for(ptr=result; ptr != NULL ;ptr=ptr->ai_next)
	{

		// Create a SOCKET for connecting to server
		serverSock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (serverSock == INVALID_SOCKET)
		{
			//printf("socket failed with error: %ld\n", WSAGetLastError());
			return false;
		}

		// Connect to server.
		iResult = connect( serverSock, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR)
		{
			closesocket(serverSock);
			serverSock = INVALID_SOCKET;
			continue;
		}
		else
		{
			break;
		}
	}

	freeaddrinfo(result);

	if (serverSock == INVALID_SOCKET)
	{
		//printf("Unable to connect to server!\n");
		return false;
	}
	else
	{
		return true;
	}
}

//input: tcp:port=5000,server=localhost
//OR
//input: IP
//IDA v6 BUG!!!!!!!
bool GetHost(char * input, char * output)
{
	char * t = strstr(input, "server=");
	if (t)
	{
		t += 7;
		strcpy(output, t);
	}
	else
	{
		strcpy(output, input);
	}

	return true;
}
