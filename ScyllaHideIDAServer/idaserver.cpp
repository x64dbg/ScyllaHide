#define _CRT_SECURE_NO_WARNINGS
#include "idaserver.h"
#include "IdaServerExchange.h"

#include "..\PluginGeneric\ScyllaHideVersion.h"

#include "..\PluginGeneric\Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"

WSADATA wsaData;


char * ListenPortString = IDA_SERVER_DEFAULT_PORT_TEXT;
unsigned short ListenPort = IDA_SERVER_DEFAULT_PORT;

IDA_SERVER_EXCHANGE idaExchange = {0};

struct HideOptions pHideOptions = {0};

#ifdef _WIN64
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif

const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};

bool SetDebugPrivileges();
BOOL FileExists(LPCWSTR szPath);
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

	if (sizeof(IDA_SERVER_EXCHANGE) != IDA_SERVER_EXCHANGE_STRUCT_SIZE)
	{
		printf("WRONG!!! Size of IDA_SERVER_EXCHANGE %d == %d?\n\n", sizeof(IDA_SERVER_EXCHANGE), IDA_SERVER_EXCHANGE_STRUCT_SIZE);
		getchar();
		return 0;
	}

	SetDebugPrivileges();

	printf("Starting IDA Server v" SCYLLA_HIDE_VERSION_STRING_A "...\n");

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

BOOL FileExists(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
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

	if (!FileExists(ScyllaHideDllPath))
	{
		wprintf(L"File missing %s\n", ScyllaHideDllPath);
		missing = true;
	}
	if (!FileExists(NtApiIniPath))
	{
		wprintf(L"File missing %s\n", NtApiIniPath);
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
	pHideOptions.DLLUnload = idaExchange.UnloadDllAfterInjection;
	pHideOptions.DLLNormal = idaExchange.DllInjectNormal;
	pHideOptions.DLLStealth = idaExchange.DllInjectStealth;
	pHideOptions.KiUserExceptionDispatcher = idaExchange.EnableKiUserExceptionDispatcherHook;
	pHideOptions.NtClose = idaExchange.EnableNtCloseHook;
	pHideOptions.NtContinue = idaExchange.EnableNtCloseHook;
	pHideOptions.NtCreateThreadEx = idaExchange.EnableNtCreateThreadExHook;
	pHideOptions.NtGetContextThread = idaExchange.EnableNtGetContextThreadHook;
	pHideOptions.NtQueryInformationProcess = idaExchange.EnableNtQueryInformationProcessHook;
	pHideOptions.NtQueryObject = idaExchange.EnableNtQueryObjectHook;
	pHideOptions.NtQuerySystemInformation = idaExchange.EnableNtQuerySystemInformationHook;
	pHideOptions.NtSetContextThread = idaExchange.EnableNtSetContextThreadHook;
	pHideOptions.NtSetDebugFilterState = idaExchange.EnableNtSetDebugFilterStateHook;
	pHideOptions.NtSetInformationThread = idaExchange.EnableNtSetInformationThreadHook;
	pHideOptions.NtUserBuildHwndList = idaExchange.EnableNtUserBuildHwndListHook;
	pHideOptions.NtUserFindWindowEx = idaExchange.EnableNtUserFindWindowExHook;
	pHideOptions.NtUserQueryWindow = idaExchange.EnableNtUserQueryWindowHook;
	pHideOptions.NtYieldExecution = idaExchange.EnableNtYieldExecutionHook;
	pHideOptions.preventThreadCreation = idaExchange.EnablePreventThreadCreation;
	pHideOptions.OutputDebugStringA = idaExchange.EnableOutputDebugStringHook;
	pHideOptions.BlockInput = idaExchange.EnableBlockInputHook;

	pHideOptions.GetTickCount = idaExchange.EnableGetTickCountHook;
	pHideOptions.GetTickCount64 = idaExchange.EnableGetTickCount64Hook;
	pHideOptions.GetLocalTime = idaExchange.EnableGetLocalTimeHook;
	pHideOptions.GetSystemTime = idaExchange.EnableGetSystemTimeHook;
	pHideOptions.NtQuerySystemTime = idaExchange.EnableNtQuerySystemTimeHook;
	pHideOptions.NtQueryPerformanceCounter = idaExchange.EnableNtQueryPerformanceCounterHook;

	pHideOptions.PEBBeingDebugged = idaExchange.EnablePebBeingDebugged;
	pHideOptions.PEBHeapFlags = idaExchange.EnablePebHeapFlags;
	pHideOptions.PEBNtGlobalFlag = idaExchange.EnablePebNtGlobalFlag;
	pHideOptions.PEBStartupInfo = idaExchange.EnablePebStartupInfo;
}

void DoSomeBitCheck()
{
	if (isWindows64())
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, ProcessId);
		if (hProcess)
		{
			bool wow64 = IsProcessWOW64(hProcess);

#ifdef _WIN64
			if (wow64)
			{
				printf("WARNING: This is a 32bit process and I am 64bit!");
				getchar();
				ExitProcess(0);
			}
#else
			if (!wow64)
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