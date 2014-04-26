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
void closeWinsock();
void startListen();
void handleClient( SOCKET ClientSocket );

#define PROCESS_START 1
#define PROCESS_ATTACH 2
#define PROCESS_EXIT 3
#define PROCESS_NEWMODULE 4

enum server_dbg_notification_t
{
	dbg_null = 0,

	// debugger low-level event notifications (see IDD.HPP for details).

	dbg_process_start,   // Parameter:  const debug_event_t *event
	//   This event notification is also an asynchronous
	//   function result notification for start_process() !

	dbg_process_exit,    // Parameter:  const debug_event_t *event
	//   This event notification is also an asynchronous
	//   function result notification for exit_process() !

	dbg_process_attach,  // Parameter:  const debug_event_t *event
	//   This event notification is also an asynchronous
	//   function result notification for attach_process() !

	dbg_process_detach,  // Parameter:  const debug_event_t *event
	//   This event notification is also an asynchronous
	//   function result notification for detach_process() !

	dbg_thread_start,    // Parameter:  const debug_event_t *event

	dbg_thread_exit,     // Parameter:  const debug_event_t *event

	dbg_library_load,    // Parameter:  const debug_event_t *event

	dbg_library_unload,  // Parameter:  const debug_event_t *event

	dbg_information,     // Parameter:  const debug_event_t *event

	dbg_exception,       // Parameters: const debug_event_t *event
	//             int                 *warn = -1
	//             Return (in *warn):
	//              -1 - to display an exception warning dialog
	//                   if the process is suspended.
	//               0 - to never display an exception warning dialog.
	//               1 - to always display an exception warning dialog.

	// debugger high-level event notifications

	dbg_suspend_process, // The process is now suspended.
	// Parameter: const debug_event_t *event
	//   This event notification is also an asynchronous
	//   function result notification for suspend_process() !

	dbg_bpt,             // A user defined breakpoint was reached.
	// Parameters: thid_t tid
	//             ea_t        bptea
	//             int        *warn = -1
	//             Return (in *warn):
	//              -1 - to display a breakpoint warning dialog
	//                   if the process is suspended.
	//               0 - to never display a breakpoint warning dialog.
	//               1 - to always display a breakpoint warning dialog.

	dbg_trace,           // A step occured (one instruction was executed). This event
	// notification is only generated if step tracing is enabled.
	// Parameters: thid_t tid
	//             ea_t        ip
	// Returns: 1-do not log this trace event; 0-log it

	dbg_request_error,   // An error occured during the processing of a request.
	// Parameters: ui_notification_t  failed_command
	//             dbg_notification_t failed_dbg_notification

	// debugger asynchronous function result notifications
	//   Please note some low-level event notifications also act as asynchronous
	//   function result notifications.

	dbg_step_into,       // Parameter: const debug_event_t *event

	dbg_step_over,       // Parameter: const debug_event_t *event

	dbg_run_to,          // Parameter: const debug_event_t *event

	dbg_step_until_ret,  // Parameter: const debug_event_t *event

	dbg_bpt_changed,     // Breakpoint has been changed

	dbg_last,            // The last debugger notification code
};

#define RESULT_SUCCESS 1
#define RESULT_FAILED 0

typedef struct _IDA_SERVER_EXCHANGE
{
	DWORD result;
	DWORD notif_code; //server_dbg_notification_t
	DWORD ProcessId;

	BOOLEAN EnablePebBeingDebugged;
	BOOLEAN EnablePebHeapFlags;
	BOOLEAN EnablePebNtGlobalFlag;
	BOOLEAN EnablePebStartupInfo;

	BOOLEAN EnableBlockInputHook;
	BOOLEAN EnableGetTickCountHook;
	BOOLEAN EnableOutputDebugStringHook;

	BOOLEAN EnableNtSetInformationThreadHook;
	BOOLEAN EnableNtQuerySystemInformationHook;
	BOOLEAN EnableNtQueryInformationProcessHook;
	BOOLEAN EnableNtQueryObjectHook;
	BOOLEAN EnableNtYieldExecutionHook;
	BOOLEAN EnableNtCloseHook;

	BOOLEAN EnablePreventThreadCreation;
	BOOLEAN EnableNtCreateThreadExHook;

	//Protect and Hide Hardware Breakpoints
	BOOLEAN EnableNtGetContextThreadHook;
	BOOLEAN EnableNtSetContextThreadHook;
	BOOLEAN EnableNtContinueHook;
	BOOLEAN EnableKiUserExceptionDispatcherHook;

	BOOLEAN EnableNtUserQueryWindowHook;
	BOOLEAN EnableNtUserBuildHwndListHook;
	BOOLEAN EnableNtUserFindWindowExHook;
	BOOLEAN EnableNtSetDebugFilterStateHook;

} IDA_SERVER_EXCHANGE;
