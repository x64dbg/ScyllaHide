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

scl::Settings g_settings;

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

    if (!scl::FileExistsW(ScyllaHideDllPath))
	{
		wprintf(L"File is missing: %s\n", ScyllaHideDllPath);
		missing = true;
	}
    if (!scl::FileExistsW(NtApiIniPath))
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
    g_settings.opts().dllUnload = idaExchange.UnloadDllAfterInjection;
    g_settings.opts().dllNormal = idaExchange.DllInjectNormal;
    g_settings.opts().dllStealth = idaExchange.DllInjectStealth;
    g_settings.opts().hookKiUserExceptionDispatcher = idaExchange.EnableKiUserExceptionDispatcherHook;
    g_settings.opts().hookNtClose = idaExchange.EnableNtCloseHook;
    g_settings.opts().hookNtContinue = idaExchange.EnableNtCloseHook;
    g_settings.opts().hookNtCreateThreadEx = idaExchange.EnableNtCreateThreadExHook;
    g_settings.opts().hookNtGetContextThread = idaExchange.EnableNtGetContextThreadHook;
    g_settings.opts().hookNtQueryInformationProcess = idaExchange.EnableNtQueryInformationProcessHook;
    g_settings.opts().hookNtQueryObject = idaExchange.EnableNtQueryObjectHook;
    g_settings.opts().hookNtQuerySystemInformation = idaExchange.EnableNtQuerySystemInformationHook;
    g_settings.opts().hookNtSetContextThread = idaExchange.EnableNtSetContextThreadHook;
    g_settings.opts().hookNtSetDebugFilterState = idaExchange.EnableNtSetDebugFilterStateHook;
    g_settings.opts().hookNtSetInformationThread = idaExchange.EnableNtSetInformationThreadHook;
    g_settings.opts().hookNtUserBuildHwndList = idaExchange.EnableNtUserBuildHwndListHook;
    g_settings.opts().hookNtUserFindWindowEx = idaExchange.EnableNtUserFindWindowExHook;
    g_settings.opts().hookNtUserQueryWindow = idaExchange.EnableNtUserQueryWindowHook;
    g_settings.opts().hookNtYieldExecution = idaExchange.EnableNtYieldExecutionHook;
    g_settings.opts().preventThreadCreation = idaExchange.EnablePreventThreadCreation;
    g_settings.opts().hookOutputDebugStringA = idaExchange.EnableOutputDebugStringHook;
    g_settings.opts().hookBlockInput = idaExchange.EnableBlockInputHook;
    g_settings.opts().hookNtSetInformationProcess = idaExchange.EnableNtSetInformationProcessHook;

    g_settings.opts().hookGetTickCount = idaExchange.EnableGetTickCountHook;
    g_settings.opts().hookGetTickCount64 = idaExchange.EnableGetTickCount64Hook;
    g_settings.opts().hookGetLocalTime = idaExchange.EnableGetLocalTimeHook;
    g_settings.opts().hookGetSystemTime = idaExchange.EnableGetSystemTimeHook;
    g_settings.opts().hookNtQuerySystemTime = idaExchange.EnableNtQuerySystemTimeHook;
    g_settings.opts().hookNtQueryPerformanceCounter = idaExchange.EnableNtQueryPerformanceCounterHook;

    g_settings.opts().fixPebBeingDebugged = idaExchange.EnablePebBeingDebugged;
    g_settings.opts().fixPebHeapFlags = idaExchange.EnablePebHeapFlags;
    g_settings.opts().fixPebNtGlobalFlag = idaExchange.EnablePebNtGlobalFlag;
    g_settings.opts().fixPebStartupInfo = idaExchange.EnablePebStartupInfo;

    g_settings.opts().malwareRunpeUnpacker = idaExchange.EnableMalwareRunPeUnpacker;
}

void DoSomeBitCheck()
{
    if (scl::IsWindows64())
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, ProcessId);
		if (hProcess)
		{

#ifdef _WIN64
            if (scl::IsWow64Process(hProcess))
			{
				printf("WARNING: This is a 32bit process and I am 64bit!");
				getchar();
				ExitProcess(0);
			}
#else
            if (!scl::IsWow64Process(hProcess))
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
