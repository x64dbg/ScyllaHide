#pragma once

#define IDA_SERVER_DEFAULT_PORT_TEXT "1337"
#define IDA_SERVER_DEFAULT_PORT 1337

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

	dbg_step_into,       // Parameter: const debug_event_t *event

	dbg_step_over,       // Parameter: const debug_event_t *event

	dbg_run_to,          // Parameter: const debug_event_t *event

	dbg_step_until_ret,  // Parameter: const debug_event_t *event

	dbg_bpt_changed,     // Breakpoint has been changed

	inject_dll
};

#define RESULT_SUCCESS 1
#define RESULT_FAILED 0

typedef struct _IDA_SERVER_EXCHANGE
{
	unsigned long result;
	unsigned long notif_code; //server_dbg_notification_t
	unsigned long ProcessId;

	unsigned char EnablePebBeingDebugged;
	unsigned char EnablePebHeapFlags;
	unsigned char EnablePebNtGlobalFlag;
	unsigned char EnablePebStartupInfo;

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

	//Protect and Hide Hardware Breakpoints
	unsigned char EnableNtGetContextThreadHook;
	unsigned char EnableNtSetContextThreadHook;
	unsigned char EnableNtContinueHook;
	unsigned char EnableKiUserExceptionDispatcherHook;

	unsigned char EnableNtUserBlockInputHook;
	unsigned char EnableNtUserQueryWindowHook;
	unsigned char EnableNtUserBuildHwndListHook;
	unsigned char EnableNtUserFindWindowExHook;
	unsigned char EnableNtSetDebugFilterStateHook;

	unsigned char EnableGetTickCountHook;
	unsigned char EnableGetTickCount64Hook;
	unsigned char EnableGetLocalTimeHook;
	unsigned char EnableGetSystemTimeHook;
	unsigned char EnableNtQuerySystemTimeHook;
	unsigned char EnableNtQueryPerformanceCounterHook;

	unsigned char DllInjectStealth;
	unsigned char DllInjectNormal;
	unsigned char UnloadDllAfterInjection;
	wchar_t DllPathForInjection[300];
} IDA_SERVER_EXCHANGE;