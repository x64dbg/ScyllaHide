#define _CRT_SECURE_NO_WARNINGS
#include "IdaServerClient.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "..\ScyllaHideIDAServer\IdaServerExchange.h"
#include "..\PluginGeneric\Injector.h"

#pragma comment (lib, "Ws2_32.lib")

extern struct HideOptions pHideOptions;


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

	idaExchange.EnablePebBeingDebugged = pHideOptions.PEBBeingDebugged;
	idaExchange.EnablePebHeapFlags = pHideOptions.PEBHeapFlags;
	idaExchange.EnablePebNtGlobalFlag = pHideOptions.PEBNtGlobalFlag;
	idaExchange.EnablePebStartupInfo = pHideOptions.PEBStartupInfo;
	idaExchange.EnableBlockInputHook = pHideOptions.BlockInput;
	idaExchange.EnableOutputDebugStringHook = pHideOptions.OutputDebugStringA;
	idaExchange.EnableNtSetInformationThreadHook = pHideOptions.NtSetInformationThread;
	idaExchange.EnableNtQueryInformationProcessHook = pHideOptions.NtQueryInformationProcess;
	idaExchange.EnableNtQuerySystemInformationHook = pHideOptions.NtQuerySystemInformation;
	idaExchange.EnableNtQueryObjectHook = pHideOptions.NtQueryObject;
	idaExchange.EnableNtYieldExecutionHook = pHideOptions.NtYieldExecution;
	idaExchange.EnableNtCloseHook = pHideOptions.NtClose;
	idaExchange.EnableNtCreateThreadExHook = pHideOptions.NtCreateThreadEx;
	idaExchange.EnablePreventThreadCreation = pHideOptions.preventThreadCreation;

	idaExchange.EnableNtGetContextThreadHook = pHideOptions.NtGetContextThread;
	idaExchange.EnableNtSetContextThreadHook = pHideOptions.NtSetContextThread;
	idaExchange.EnableNtContinueHook = pHideOptions.NtContinue;
	idaExchange.EnableKiUserExceptionDispatcherHook = pHideOptions.KiUserExceptionDispatcher;
	idaExchange.EnableNtSetInformationProcessHook = pHideOptions.NtSetInformationProcess;
	idaExchange.EnableMalwareRunPeUnpacker = pHideOptions.malwareRunpeUnpacker;

	idaExchange.EnableGetTickCountHook = pHideOptions.GetTickCount;
	idaExchange.EnableGetTickCount64Hook = pHideOptions.GetTickCount64;
	idaExchange.EnableGetLocalTimeHook = pHideOptions.GetLocalTime;
	idaExchange.EnableGetSystemTimeHook = pHideOptions.GetSystemTime;
	idaExchange.EnableNtQuerySystemTimeHook = pHideOptions.NtQuerySystemTime;
	idaExchange.EnableNtQueryPerformanceCounterHook = pHideOptions.NtQueryPerformanceCounter;

	idaExchange.EnableNtUserFindWindowExHook = pHideOptions.NtUserFindWindowEx;
	idaExchange.EnableNtUserBuildHwndListHook = pHideOptions.NtUserBuildHwndList;
	idaExchange.EnableNtUserQueryWindowHook = pHideOptions.NtUserQueryWindow;
	idaExchange.EnableNtSetDebugFilterStateHook = pHideOptions.NtSetDebugFilterState;
	idaExchange.DllInjectNormal = pHideOptions.DLLNormal;
	idaExchange.DllInjectStealth = pHideOptions.DLLStealth;
	idaExchange.UnloadDllAfterInjection = pHideOptions.DLLUnload;

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