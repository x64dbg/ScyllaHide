#include <WinSock2.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>
#include <Scylla/Version.h>

#include "idaserver.h"
#include "IdaServerExchange.h"
#include "..\PluginGeneric\Injector.h"

WSADATA wsaData;

char * ListenPortString = IDA_SERVER_DEFAULT_PORT_TEXT;
unsigned short ListenPort = IDA_SERVER_DEFAULT_PORT;

IDA_SERVER_EXCHANGE idaExchange = {0};

Scylla::HideSettings g_hideSettings;

#ifdef _WIN64
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};

bool SetDebugPrivileges();
void checkPaths();


extern HOOK_DLL_EXCHANGE DllExchangeLoader;

typedef void (__cdecl * t_LogWrapper)(const WCHAR * format, ...);

void LogWrapper(const WCHAR * format, ...);
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;

int main(int argc, char *argv[])
{
	LogWrap = LogWrapper;
	LogErrorWrap = LogWrapper;

	SetDebugPrivileges();

	printf("%s IDA Server v%s\n", SCYLLA_HIDE_NAME_A, SCYLLA_HIDE_VERSION_STRING_A);

	checkPaths();

	if (argc > 1)
	{
		ListenPortString = argv[1];
		ListenPort = (unsigned short)strtoul(ListenPortString, 0, 10);
	}

	printf("Listen Port: %d (0x%X)\n", ListenPort, ListenPort);

	if (startWinsock())
	{
		//printf("Starting Winsock: DONE\n");
		startListen();
	}


	getchar();
	return 0;
}

void checkPaths()
{
	GetModuleFileNameW(0, NtApiIniPath, _countof(NtApiIniPath));
	WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
	if (temp)
	{
		temp++;
		*temp = 0;
		wcscpy(ScyllaHideDllPath, NtApiIniPath);
		wcscat(ScyllaHideDllPath, ScyllaHideDllFilename);
		wcscat(NtApiIniPath, NtApiIniFilename);
	}

	bool missing = false;

	if (!Scylla::FileExistsW(ScyllaHideDllPath))
	{
		wprintf(L"File is missing: %s\n", ScyllaHideDllPath);
		missing = true;
	}
	if (!Scylla::FileExistsW(NtApiIniPath))
	{
		wprintf(L"File is missing: %s\n", NtApiIniPath);
		missing = true;
	}
	if (missing)
	{
		getchar();
		ExitProcess(0);
	}
}

void startListen()
{
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

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

	int count = 0;

	while(1)
	{
		ClientSocket = accept(ListenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET)
		{
			printf("accept failed with error: %d\n", WSAGetLastError());
			break;
		}
		else
		{
			count++;

			printf("Accepted Client %d\n", count);
			handleClient(ClientSocket);
			closesocket(ClientSocket);
		}
	}

	closesocket(ListenSocket);

	WSACleanup();
}

static DWORD ProcessId = 0;
static bool bHooked = false;

void MapSettings()
{
    g_hideSettings.DLLUnload = idaExchange.UnloadDllAfterInjection;
    g_hideSettings.DLLNormal = idaExchange.DllInjectNormal;
    g_hideSettings.DLLStealth = idaExchange.DllInjectStealth;
    g_hideSettings.KiUserExceptionDispatcher = idaExchange.EnableKiUserExceptionDispatcherHook;
    g_hideSettings.NtClose = idaExchange.EnableNtCloseHook;
    g_hideSettings.NtContinue = idaExchange.EnableNtCloseHook;
    g_hideSettings.NtCreateThreadEx = idaExchange.EnableNtCreateThreadExHook;
    g_hideSettings.NtGetContextThread = idaExchange.EnableNtGetContextThreadHook;
    g_hideSettings.NtQueryInformationProcess = idaExchange.EnableNtQueryInformationProcessHook;
    g_hideSettings.NtQueryObject = idaExchange.EnableNtQueryObjectHook;
    g_hideSettings.NtQuerySystemInformation = idaExchange.EnableNtQuerySystemInformationHook;
    g_hideSettings.NtSetContextThread = idaExchange.EnableNtSetContextThreadHook;
    g_hideSettings.NtSetDebugFilterState = idaExchange.EnableNtSetDebugFilterStateHook;
    g_hideSettings.NtSetInformationThread = idaExchange.EnableNtSetInformationThreadHook;
    g_hideSettings.NtUserBuildHwndList = idaExchange.EnableNtUserBuildHwndListHook;
    g_hideSettings.NtUserFindWindowEx = idaExchange.EnableNtUserFindWindowExHook;
    g_hideSettings.NtUserQueryWindow = idaExchange.EnableNtUserQueryWindowHook;
    g_hideSettings.NtYieldExecution = idaExchange.EnableNtYieldExecutionHook;
    g_hideSettings.preventThreadCreation = idaExchange.EnablePreventThreadCreation;
    g_hideSettings.OutputDebugStringA = idaExchange.EnableOutputDebugStringHook;
    g_hideSettings.BlockInput = idaExchange.EnableBlockInputHook;
    g_hideSettings.NtSetInformationProcess = idaExchange.EnableNtSetInformationProcessHook;

    g_hideSettings.GetTickCount = idaExchange.EnableGetTickCountHook;
    g_hideSettings.GetTickCount64 = idaExchange.EnableGetTickCount64Hook;
    g_hideSettings.GetLocalTime = idaExchange.EnableGetLocalTimeHook;
    g_hideSettings.GetSystemTime = idaExchange.EnableGetSystemTimeHook;
    g_hideSettings.NtQuerySystemTime = idaExchange.EnableNtQuerySystemTimeHook;
    g_hideSettings.NtQueryPerformanceCounter = idaExchange.EnableNtQueryPerformanceCounterHook;

    g_hideSettings.PEBBeingDebugged = idaExchange.EnablePebBeingDebugged;
    g_hideSettings.PEBHeapFlags = idaExchange.EnablePebHeapFlags;
    g_hideSettings.PEBNtGlobalFlag = idaExchange.EnablePebNtGlobalFlag;
    g_hideSettings.PEBStartupInfo = idaExchange.EnablePebStartupInfo;

    g_hideSettings.malwareRunpeUnpacker = idaExchange.EnableMalwareRunPeUnpacker;
}

void DoSomeBitCheck()
{
	if (Scylla::IsWindows64())
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, ProcessId);
		if (hProcess)
		{

#ifdef _WIN64
            if (Scylla::IsWow64Process(hProcess))
			{
				printf("WARNING: This is a 32bit process and I am 64bit!");
				getchar();
				ExitProcess(0);
			}
#else
            if (!Scylla::IsWow64Process(hProcess))
			{
				printf("WARNING: This is a 64bit process and I am 32bit!");
				getchar();
				ExitProcess(0);
			}
#endif
			CloseHandle(hProcess);
		}
	}
}

void handleClient( SOCKET ClientSocket )
{
	int iResult;
	bool once = false;

	do
	{
		iResult = recv(ClientSocket, (char*)&idaExchange, sizeof(IDA_SERVER_EXCHANGE), 0);

		if (iResult == sizeof(IDA_SERVER_EXCHANGE))
		{
			MapSettings();

			switch (idaExchange.notif_code)
			{
			case dbg_process_attach:
				{

					break;
				}
			case dbg_process_start:
				{

					ProcessId = idaExchange.ProcessId;
					bHooked = false;
					ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

					if (!once)
					{
						DoSomeBitCheck();
						once = true;
					}

					if (!bHooked)
					{
						bHooked = true;
						startInjection(ProcessId, ScyllaHideDllPath, true);
					}

					break;
				}
			case dbg_process_exit:
				{

					iResult = -1; //terminate loop
					break;
				}
			case dbg_library_load:
				{

					if (bHooked)
					{
						startInjection(ProcessId, ScyllaHideDllPath, false);
					}
					break;
				}

			case inject_dll:
				{
					if (!once)
					{
						DoSomeBitCheck();
						once = true;
					}

					injectDll(ProcessId, idaExchange.DllPathForInjection);
					break;
				}
			}

			idaExchange.result = RESULT_SUCCESS;
			send(ClientSocket, (char*)&idaExchange, sizeof(IDA_SERVER_EXCHANGE), 0);
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
	BOOL isWinsockUp = TRUE;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("WSAStartup failed: %d\n", iResult);
		isWinsockUp = FALSE;
	}

	return isWinsockUp;
}

bool SetDebugPrivileges()
{
	TOKEN_PRIVILEGES Debug_Privileges;
	bool retVal = false;

	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
	{
		HANDLE hToken = 0;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			Debug_Privileges.PrivilegeCount = 1;

			retVal = AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL) != FALSE;

			CloseHandle(hToken);
		}
	}

	return retVal;
}

void LogWrapper(const WCHAR * format, ...)
{
	WCHAR text[2000];
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfW(text, format, va_alist);

	wprintf(L"%s",text);
	wprintf(L"\n");
}
