#define _CRT_SECURE_NO_WARNINGS
#include "idaserver.h"
#include "IdaServerExchange.h"

#include "..\ScyllaHideOlly2Plugin\ScyllaHideVersion.h"

#include "..\ScyllaHideOlly2Plugin\Injector.h"
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

DWORD SetDebugPrivileges();
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

	if (sizeof(IDA_SERVER_EXCHANGE) != 638)
	{
		printf("WRONG!!! Size of IDA_SERVER_EXCHANGE %d == 638?\n\n", sizeof(IDA_SERVER_EXCHANGE));
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

	if (!FileExists(ScyllaHideDllPath))
	{
		wprintf(L"File missing %s\n", ScyllaHideDllPath);
	}
	if (!FileExists(NtApiIniPath))
	{
		wprintf(L"File missing %s\n", NtApiIniPath);
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
	pHideOptions.GetTickCount = idaExchange.EnableGetTickCountHook;
	pHideOptions.BlockInput = idaExchange.EnableBlockInputHook;

	pHideOptions.PEBBeingDebugged = idaExchange.EnablePebBeingDebugged;
	pHideOptions.PEBHeapFlags = idaExchange.EnablePebHeapFlags;
	pHideOptions.PEBNtGlobalFlag = idaExchange.EnablePebNtGlobalFlag;
	pHideOptions.PEBStartupInfo = idaExchange.EnablePebStartupInfo;
}

void handleClient( SOCKET ClientSocket )
{
	int iResult;
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

					if (!bHooked)
					{
						bHooked = true;
						startInjection(ProcessId, ScyllaHideDllPath, true);
					}

					break;
				}
			case dbg_process_exit:
				{

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
						injectDll(ProcessId, idaExchange.DllPathForInjection);
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
	BOOL isWinsockUp = TRUE;

	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		printf("WSAStartup failed: %d\n", iResult);
		isWinsockUp = FALSE;
	}

	return isWinsockUp;
}

DWORD SetDebugPrivileges()
{
	DWORD err = 0;
	TOKEN_PRIVILEGES Debug_Privileges;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid)) return GetLastError();

	HANDLE hToken = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		err = GetLastError();
		if (hToken) CloseHandle(hToken);
		return err;
	}

	Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	Debug_Privileges.PrivilegeCount = 1;

	if (!AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, NULL, NULL))
	{
		err = GetLastError();
		if (hToken) CloseHandle(hToken);
	}

	return err;
}

void LogWrapper(const WCHAR * format, ...)
{
	WCHAR text[2000];
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfW(text, format, va_alist);

	wprintf(text);
}