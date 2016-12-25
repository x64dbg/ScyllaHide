#include "IdaServerClient.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Scylla/Settings.h>

#include "..\ScyllaHideIDAServer\IdaServerExchange.h"
#include "..\PluginGeneric\Injector.h"

#pragma comment (lib, "Ws2_32.lib")

extern Scylla::HideSettings g_hideSettings;


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

    idaExchange.EnablePebBeingDebugged = g_hideSettings.PEBBeingDebugged;
    idaExchange.EnablePebHeapFlags = g_hideSettings.PEBHeapFlags;
    idaExchange.EnablePebNtGlobalFlag = g_hideSettings.PEBNtGlobalFlag;
    idaExchange.EnablePebStartupInfo = g_hideSettings.PEBStartupInfo;
    idaExchange.EnableBlockInputHook = g_hideSettings.BlockInput;
    idaExchange.EnableOutputDebugStringHook = g_hideSettings.OutputDebugStringA;
    idaExchange.EnableNtSetInformationThreadHook = g_hideSettings.NtSetInformationThread;
    idaExchange.EnableNtQueryInformationProcessHook = g_hideSettings.NtQueryInformationProcess;
    idaExchange.EnableNtQuerySystemInformationHook = g_hideSettings.NtQuerySystemInformation;
    idaExchange.EnableNtQueryObjectHook = g_hideSettings.NtQueryObject;
    idaExchange.EnableNtYieldExecutionHook = g_hideSettings.NtYieldExecution;
    idaExchange.EnableNtCloseHook = g_hideSettings.NtClose;
    idaExchange.EnableNtCreateThreadExHook = g_hideSettings.NtCreateThreadEx;
    idaExchange.EnablePreventThreadCreation = g_hideSettings.preventThreadCreation;

    idaExchange.EnableNtGetContextThreadHook = g_hideSettings.NtGetContextThread;
    idaExchange.EnableNtSetContextThreadHook = g_hideSettings.NtSetContextThread;
    idaExchange.EnableNtContinueHook = g_hideSettings.NtContinue;
    idaExchange.EnableKiUserExceptionDispatcherHook = g_hideSettings.KiUserExceptionDispatcher;
    idaExchange.EnableNtSetInformationProcessHook = g_hideSettings.NtSetInformationProcess;
    idaExchange.EnableMalwareRunPeUnpacker = g_hideSettings.malwareRunpeUnpacker;

    idaExchange.EnableGetTickCountHook = g_hideSettings.GetTickCount;
    idaExchange.EnableGetTickCount64Hook = g_hideSettings.GetTickCount64;
    idaExchange.EnableGetLocalTimeHook = g_hideSettings.GetLocalTime;
    idaExchange.EnableGetSystemTimeHook = g_hideSettings.GetSystemTime;
    idaExchange.EnableNtQuerySystemTimeHook = g_hideSettings.NtQuerySystemTime;
    idaExchange.EnableNtQueryPerformanceCounterHook = g_hideSettings.NtQueryPerformanceCounter;

    idaExchange.EnableNtUserFindWindowExHook = g_hideSettings.NtUserFindWindowEx;
    idaExchange.EnableNtUserBuildHwndListHook = g_hideSettings.NtUserBuildHwndList;
    idaExchange.EnableNtUserQueryWindowHook = g_hideSettings.NtUserQueryWindow;
    idaExchange.EnableNtSetDebugFilterStateHook = g_hideSettings.NtSetDebugFilterState;
    idaExchange.DllInjectNormal = g_hideSettings.DLLNormal;
    idaExchange.DllInjectStealth = g_hideSettings.DLLStealth;
    idaExchange.UnloadDllAfterInjection = g_hideSettings.DLLUnload;

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