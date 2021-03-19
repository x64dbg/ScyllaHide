#pragma once

#pragma warning(push)
#pragma warning(disable: 4244 4267)
#include <dbg.hpp>
#pragma warning(pop)

#define IDA_SERVER_DEFAULT_PORT_TEXT "1337"
#define IDA_SERVER_DEFAULT_PORT 1337

enum server_dbg_notification_t
{
	inject_dll = dbg_last
};

#define RESULT_SUCCESS 1
#define RESULT_FAILED 0

typedef struct _IDA_SERVER_EXCHANGE
{
	unsigned long result;
	unsigned long notif_code; // IDA dbg_notification_t
	unsigned long ProcessId;

	unsigned char EnablePebBeingDebugged;
	unsigned char EnablePebHeapFlags;
	unsigned char EnablePebNtGlobalFlag;
	unsigned char EnablePebStartupInfo;
	unsigned char EnablePebOsBuildNumber;

	unsigned char EnableOutputDebugStringHook;

	unsigned char EnableNtSetInformationThreadHook;
	unsigned char EnableNtQuerySystemInformationHook;
	unsigned char EnableNtQueryInformationProcessHook;
	unsigned char EnableNtSetInformationProcessHook;
	unsigned char EnableNtQueryObjectHook;
	unsigned char EnableNtYieldExecutionHook;
	unsigned char EnableNtCloseHook;
	unsigned char EnableMalwareRunPeUnpacker;

	unsigned char EnablePreventThreadCreation;
	unsigned char EnableNtCreateThreadExHook;

	// Protect and Hide hardware breakpoints
	unsigned char EnableNtGetContextThreadHook;
	unsigned char EnableNtSetContextThreadHook;
	unsigned char EnableNtContinueHook;
	unsigned char EnableKiUserExceptionDispatcherHook;

	unsigned char EnableNtUserBlockInputHook;
	unsigned char EnableNtUserQueryWindowHook;
	unsigned char EnableNtUserGetForegroundWindowHook;
	unsigned char EnableNtUserBuildHwndListHook;
	unsigned char EnableNtUserFindWindowExHook;
	unsigned char EnableNtSetDebugFilterStateHook;

	unsigned char EnableGetTickCountHook;
	unsigned char EnableGetTickCount64Hook;
	unsigned char EnableGetLocalTimeHook;
	unsigned char EnableGetSystemTimeHook;
	unsigned char EnableNtQuerySystemTimeHook;
	unsigned char EnableNtQueryPerformanceCounterHook;

    unsigned char KillAntiAttach;

	unsigned char DllInjectStealth;
	unsigned char DllInjectNormal;
	unsigned char UnloadDllAfterInjection;
	wchar_t DllPathForInjection[300];
} IDA_SERVER_EXCHANGE;
