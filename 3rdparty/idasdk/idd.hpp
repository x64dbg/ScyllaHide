/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _IDD_HPP
#define _IDD_HPP
#include <area.hpp>
#include <ua.hpp>
#pragma pack(push, 4)

//
//      This file contains definition of the interface to IDD modules
//      The interface consists of structures describing the target
//      debugged processor and a debugging API.

#define         IDD_INTERFACE_VERSION   15


typedef uchar type_t;
typedef uchar p_list;
class idc_value_t;
typedef uint32 argloc_t;

//====================================================================
//
//                       Process and Threads
//

typedef int pid_t;                   // process id
typedef int thid_t;                  // thread id

#define NO_PROCESS pid_t(0xFFFFFFFF) // No process
#define NO_THREAD  0                 // No thread
                                     // in PROCESS_START this value
                                     // can be used to specify that
                                     // the main thread has not been created
                                     // It will be initializated later
                                     // by a THREAD_START event.

struct process_info_t
{
  pid_t pid;
  char name[MAXSTR];
};
DECLARE_TYPE_AS_MOVABLE(process_info_t);

//====================================================================
//
//                          Registers
//

typedef unsigned char register_class_t; // Each register is associated to
                                        // a register class.
                                        // example: "segment", "mmx", ...

struct register_info_t
{
  const char *name;                   // Register name.
  uint32 flags;                       // Register special features
#define REGISTER_READONLY 0x0001      //   the user can't modify the current value of this register
#define REGISTER_IP       0x0002      //   instruction pointer
#define REGISTER_SP       0x0004      //   stack pointer
#define REGISTER_FP       0x0008      //   frame pointer
#define REGISTER_ADDRESS  0x0010      //   may contain an address
#define REGISTER_CS       0x0020      //   code segment
#define REGISTER_SS       0x0040      //   stack segment
#define REGISTER_NOLF     0x0080      //   displays this register without returning to the next line
                                      //   allowing the next register to be displayed to its right (on the same line)
#define REGISTER_CUSTFMT  0x0100      //   register should be displayed using a custom data format
                                      //   the format name is in bit_strings[0]
                                      //   the corresponding regval_t will use bytevec_t
  register_class_t register_class;
  char dtyp;                          // Register size (dt_... constants)
  const char *const *bit_strings;     // Strings corresponding to each bit of the register
                                      // (NULL = no bit, same name = multi-bits mask)
  int bit_strings_default;            // Mask of default bits
};
DECLARE_TYPE_AS_MOVABLE(register_info_t);

//====================================================================
//
//                           Memory
//

// The following structure is used by debugger modules to report memory are
// information to IDA kernel. It is ok to return empty fields if information
// is not available.

struct memory_info_t : public area_t
{
  memory_info_t(void)
    : sbase(0),bitness(0),perm(0) {}
  qstring name;                // Memory area name
  qstring sclass;              // Memory area class name
  ea_t sbase;                  // Segment base (meaningful only for segmented architectures, e.g. 16-bit x86)
                               // The base is specified in paragraphs (i.e. shifted to the right by 4)
  uchar bitness;               // Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
  uchar perm;                  // Memory area permissions (0-no information): see segment.hpp
  bool operator ==(const memory_info_t &r) const
  {
    return startEA == r.startEA
        && endEA   == r.endEA
        && name    == r.name
        && sclass  == r.sclass
        && sbase   == r.sbase
        && bitness == r.bitness
        && perm    == r.perm;
  }
  bool operator !=(const memory_info_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(memory_info_t);
typedef qvector<memory_info_t> meminfo_vec_t;

//====================================================================
//
//                         Debug events
//

enum event_id_t
{
  NO_EVENT       = 0x00000000, // Not an interesting event. This event can be
                               // used if the debugger module needs to return
                               // an event but there are no valid events.
  PROCESS_START  = 0x00000001, // New process has been started.
  PROCESS_EXIT   = 0x00000002, // Process has been stopped.
  THREAD_START   = 0x00000004, // New thread has been started.
  THREAD_EXIT    = 0x00000008, // Thread has been stopped.
  BREAKPOINT     = 0x00000010, // Breakpoint has been reached. IDA will complain
                               // about unknown breakpoints, they should be reported
                               // as exceptions.
  STEP           = 0x00000020, // One instruction has been executed. Spurious
                               // events of this kind are silently ignored by IDA.
  EXCEPTION      = 0x00000040, // Exception.
  LIBRARY_LOAD   = 0x00000080, // New library has been loaded.
  LIBRARY_UNLOAD = 0x00000100, // Library has been unloaded.
  INFORMATION    = 0x00000200, // User-defined information.
                               // This event can be used to return empty information
                               // This will cause IDA to call get_debug_event()
                               // immediately once more.
  SYSCALL        = 0x00000400, // Syscall (not used yet).
  WINMESSAGE     = 0x00000800, // Window message (not used yet).
  PROCESS_ATTACH = 0x00001000, // Successfully attached to running process.
  PROCESS_DETACH = 0x00002000, // Successfully detached from process.
  PROCESS_SUSPEND= 0x00004000, // Process has been suspended..
                               // This event can be used by the debugger module
                               // to signal if the process spontaneously gets
                               // suspended (not because of an exception,
                               // breakpoint, or single step). IDA will silently
                               // switch to the 'suspended process' mode without
                               // displaying any messages.
};


// Those structures describe particular debug events

struct module_info_t
{
  char name[MAXSTR];    // full name of the module.
  ea_t base;            // module base address. if unknown pass BADADDR
  asize_t size;         // module size. if unknown pass 0
  ea_t rebase_to;       // if not BADADDR, then rebase the program to the specified address
};

struct e_breakpoint_t
{
  ea_t hea;             // Possible address referenced by hardware breakpoints
  ea_t kea;             // Address of the triggered bpt from the kernel's point
                        // of view (for some systems with special memory mappings,
                        // the triggered ea might be different from event ea).
                        // Use to BADADDR for flat memory model.
};

struct e_exception_t
{
  uint32 code;          // Exception code
  bool can_cont;        // Execution of the process can continue after this exception?
  ea_t ea;              // Possible address referenced by the exception
  char info[MAXSTR];    // Exception message
};

// This structure is used only when detailed information
//   on a debug event is needed.
struct debug_event_t
{
  debug_event_t(void) : eid(NO_EVENT) {}
                           // The following fields must be filled for all events:
  event_id_t eid;          // Event code (used to decipher 'info' union)
  pid_t pid;               // Process where the event occured
  thid_t tid;              // Thread where the event occured
  ea_t ea;                 // Address where the event occured
  bool handled;            // Is event handled by the debugger?
                           // (from the system's point of view)
                           // Meaningful for EXCEPTION events
#ifndef SWIG
  union
  {
#endif //SWIG
    module_info_t modinfo; // PROCESS_START, PROCESS_ATTACH, LIBRARY_LOAD
    int exit_code;         // PROCESS_EXIT, THREAD_EXIT
    char info[MAXSTR];     // LIBRARY_UNLOAD (unloaded library name)
                           // INFORMATION (will be displayed in the
                           //              messages window if not empty)
    e_breakpoint_t bpt;    // BREAKPOINT
    e_exception_t exc;     // EXCEPTION
#ifndef SWIG
  };
#endif //SWIG
  // On some systems with special memory mappings the triggered ea might be
  // different from the actual ea. Calculate the address to use.
  ea_t bpt_ea(void) const
  {
    return eid == BREAKPOINT && bpt.kea != BADADDR ? bpt.kea : ea;
  }
};

// Hardware breakpoint types. Fire the breakpoint upon:
typedef int bpttype_t;
const bpttype_t
  BPT_OLD_EXEC = 0,             // (obsolute: execute instruction)
  BPT_WRITE    = 1,             // Write access
  BPT_READ     = 2,             // Read access
  BPT_RDWR     = 3,             // Read/write access
  BPT_SOFT     = 4,             // Software breakpoint
  BPT_EXEC     = 8;             // Execute instruction


// Exception information
struct exception_info_t
{
  uint code;
  uint32 flags;
#define EXC_BREAK  0x0001 // break on the exception
#define EXC_HANDLE 0x0002 // should be handled by the debugger?
#define EXC_MSG    0x0004 // instead of a warning, log the exception to the output window
#define EXC_SILENT 0x0008 // do not warn or log to the output window
  bool break_on(void) const { return (flags & EXC_BREAK) != 0; }
  bool handle(void) const { return (flags & EXC_HANDLE) != 0; }
  qstring name;         // Exception standard name
  qstring desc;         // Long message used to display info about the exception
  exception_info_t(void) {}
  exception_info_t(uint _code, uint32 _flags, const char *_name, const char *_desc)
    : code(_code), flags(_flags), name(_name), desc(_desc) {}
};
DECLARE_TYPE_AS_MOVABLE(exception_info_t);
typedef qvector<exception_info_t> excvec_t;

// Structure to hold a register value.
// Small values (up to 64-bit integers and floating point values) use
// RVT_INT and RVT_FLOAT types. For bigger values the bytes() vector is used.
struct regval_t
{
  int32 rvtype;         // value type
#define RVT_INT    (-1) // integer
#define RVT_FLOAT  (-2) // floating point
                        // other values mean custom data type
#ifndef SWIG
  union
  {
#endif //SWIG
    uint64 ival;        // 8:  integer value
    uint16 fval[6];     // 12: floating point value in the internal representation (see ieee.h)
#ifndef SWIG
    uchar reserve[sizeof(bytevec_t)]; // bytevec_t: custom data type (use bytes() to access it)
  };
#endif //SWIG
  regval_t(void) : rvtype(RVT_INT), ival(~uint64(0)) {}
  ~regval_t(void) { clear(); }
  regval_t(const regval_t &r) : rvtype(RVT_INT) { *this = r; }
  regval_t &operator = (const regval_t &r)
  {
    if ( r.rvtype >= 0 )
    {
      if ( rvtype >= 0 )
        bytes() = r.bytes();
      else
        new (&bytes()) bytevec_t(r.bytes());
    }
    else // r.rvtype < 0
    {
      if ( rvtype >= 0 )
        bytes().~bytevec_t();
      memcpy(fval, r.fval, sizeof(fval));
    }
    rvtype = r.rvtype;
    return *this;
  }
  void clear(void)
  {
    if ( rvtype >= 0 )
    {
      bytes().~bytevec_t();
      rvtype = RVT_INT;
    }
  }
  bool operator == (const regval_t &r) const
  {
    if ( rvtype == r.rvtype )
    {
      if ( rvtype == RVT_INT )
        return ival == r.ival;
      return memcmp(get_data(), r.get_data(), get_data_size()) == 0;
    }
    return false;
  }
  bool operator != (const regval_t &r) const { return !(*this == r); }
  void _set_int(uint64 x) { ival = x; }
  void _set_float(const ushort *x) { memcpy(fval, x, sizeof(fval)); rvtype = RVT_FLOAT; }
  void set_int(uint64 x) { clear(); _set_int(x); }
  void set_float(const ushort *x) { clear(); _set_float(x); }
  void swap(regval_t &r) { qswap(*this, r); }
        bytevec_t &bytes(void)       { return *(bytevec_t *)reserve; }
  const bytevec_t &bytes(void) const { return *(bytevec_t *)reserve; }
  void _set_bytes(const uchar *data, size_t size) { new (&bytes()) bytevec_t(data, size); rvtype = 0; }
  void _set_bytes(const bytevec_t &v) { new (&bytes()) bytevec_t(v); rvtype = 0; }
  void set_bytes(const uchar *data, size_t size) { clear(); _set_bytes(data, size); }
  void set_bytes(const bytevec_t &v) { clear(); _set_bytes(v); }
  bytevec_t &_set_bytes(void) { new (&bytes()) bytevec_t; rvtype = 0; return bytes(); }
  bytevec_t &set_bytes(void) { clear(); _set_bytes(); return bytes(); }
        void *get_data(void)       { return rvtype >= 0 ? (void *)bytes().begin() : (void *)&fval; }
  const void *get_data(void) const { return rvtype >= 0 ? (void *)bytes().begin() : (void *)&fval; }
  size_t get_data_size(void) const { return rvtype >= 0 ? bytes().size() : rvtype == RVT_INT ? sizeof(ival) : sizeof(fval); }
};
DECLARE_TYPE_AS_MOVABLE(regval_t);
typedef qvector<regval_t> regvals_t;

// Instruction operand information
#ifdef NO_OBSOLETE_FUNCS
struct idd_opinfo_t
{
  bool modified;        // the operand is modified (written) by the instruction
  ea_t ea;              // operand address (BADADDR - no address)
  regval_t value;       // operand value. custom data is represented by 'bytes'.
  int debregidx;        // for custom data: index of the corresponding register in dbg->registers
  int value_size;       // size of the value in bytes

  idd_opinfo_t(void) : modified(false), ea(BADADDR), debregidx(-1), value_size(0) {}
};
#endif

// Call stack trace information
struct call_stack_info_t
{
  ea_t callea;          // the address of the call instruction
  ea_t funcea;          // the address of the called function
  ea_t fp;              // the value of the frame pointer of the called function
  bool funcok;          // is the function present?
  bool operator==(const call_stack_info_t &r) const
  {
    return callea == r.callea
        && funcea == r.funcea
        && funcok == r.funcok
        && fp     == r.fp;
  }
  bool operator!=(const call_stack_info_t &r) const { return !(*this == r); }
};

DECLARE_TYPE_AS_MOVABLE(call_stack_info_t);
struct call_stack_t : public qvector<call_stack_info_t>
{
  bool dirty;           // is the stack trace obsolete?
};


// Call a function from the debugged application
//      func_ea - address to call
//      tid     - thread to use. NO_THREAD means to use the current thread
//      type    - type of the function to call
//                if NULL, the type information will be retrieved from the idb
//      fields  - argument names (currently not used)
//      argnum  - number of actual arguments
//      argv    - array of arguments
//      r       - out: function return value
//                for APPCALL_MANUAL, r will hold the new stack point value
//                for APPCALL_DEBEV, r will hold the exception information upon failure
//                                   and the return code will be eExecThrow
// Returns: eOk if successful, otherwise an error code

idaman error_t ida_export appcall(
        ea_t func_ea,
        thid_t tid,
        const type_t *type,
        const p_list *fields,
        int argnum,
        idc_value_t *argv,
        idc_value_t *r);


// Cleanup after manual appcall
//      tid     - thread to use. NO_THREAD means to use the current thread
// The application state is restored as it was before calling the last appcall()
// Nested appcalls are supported.
// Returns: eOk if successful, otherwise an error code

idaman error_t ida_export cleanup_appcall(thid_t tid);


// Return values for get_debug_event()
enum gdecode_t
{
  GDE_ERROR = -1,       // error
  GDE_NO_EVENT,         // no debug events are available
  GDE_ONE_EVENT,        // got one event, no more available yet
  GDE_MANY_EVENTS,      // got one event, more events available
};

// Input argument for update_bpts()
struct update_bpt_info_t
{
  ea_t ea;              // in: bpt address
  bytevec_t orgbytes;   // in(del), out(add): original bytes (only for swbpts)
  bpttype_t type;       // in: bpt type
  int size;             // in: bpt size (only for hwbpts)
  uchar code;           // in: 0. BPT_SKIP entries must be skipped by the debugger module
                        // out: BPT_... code
};
typedef qvector<update_bpt_info_t> update_bpt_vec_t;

// Input argument for update_lowcnds()
// Server-side low-level breakpoint conditions
struct lowcnd_t
{
  ea_t ea;              // address of the condition
  qstring cndbody;      // new condition. empty means 'remove condition'
                        // the following fields are valid only if condition is not empty:
  bpttype_t type;       // existing breakpoint type
  bytevec_t orgbytes;   // original bytes (if type==BPT_SOFT)
  insn_t cmd;           // decoded instruction at 'ea'
                        // (used for processors without single step feature, e.g. arm)
  bool compiled;        // has 'cndbody' already been compiled?
  int size;             // breakpoint size (if type!=BPT_SOFT)
};
typedef qvector<lowcnd_t> lowcnd_vec_t;

//====================================================================
// internal kernel function, should not be used by plugins yet
// 1-resumed,0-suspended,-1-error
int idaapi handle_debug_event(const debug_event_t *ev, int rqflags);

#define RQ_MASKING  0x0001  // masking step handler: unless errors, tmpbpt handlers won't be called
                            // should be used only with request_internal_step()
#define RQ_SUSPEND  0x0002  // suspending step handler: suspends the app
                            // handle_debug_event: suspends the app
#define RQ_NOSUSP   0x0000  // running step handler: continues the app
#define RQ_IGNWERR  0x0004  // ignore breakpoint write failures
#define RQ_SILENT   0x0008  // all: no dialog boxes
#define RQ_VERBOSE  0x0000  // all: display dialog boxes
#define RQ_SWSCREEN 0x0010  // handle_debug_event: switch screens
#define RQ__NOTHRRF 0x0020  // handle_debug_event: do not refresh threads. temporary flag
                            // must go away as soon as we straighten dstate.
#define RQ_PROCEXIT 0x0040  // snapshots: the process is exiting
#define RQ_IDAIDLE  0x0080  // handle_debug_event: ida is idle
#define RQ_SUSPRUN  0x0100  // handle_debug_event: suspend at PROCESS_START
#define RQ_RESUME   0x0200  // handle_debug_event: resume application


//====================================================================
//
//     This structure describes a debugger API module.
//     (functions needed to debug a process on a specific
//      operating system)
//
//     The address of this structure must be put into the 'dbg' variable by
//     the init() function of the debugger plugin

struct debugger_t
{
  int version;                        // Expected kernel version,
                                      //   should be IDD_INTERFACE_VERSION
  const char *name;                   // Short debugger name like win32 or linux
  int id;                             // Debugger API module id
#define DEBUGGER_ID_X86_IA32_WIN32_USER              0 // Userland win32 processes (win32 debugging APIs)
#define DEBUGGER_ID_X86_IA32_LINUX_USER              1 // Userland linux processes (ptrace())
#define DEBUGGER_ID_ARM_WINCE_ASYNC                  2 // Windows CE ARM (ActiveSync transport)
#define DEBUGGER_ID_X86_IA32_MACOSX_USER             3 // Userland MAC OS X processes
#define DEBUGGER_ID_ARM_EPOC_USER                    4 // Symbian OS
#define DEBUGGER_ID_ARM_IPHONE_USER                  5 // iPhone 1.x
#define DEBUGGER_ID_X86_IA32_BOCHS                   6 // BochsDbg.exe 32
#define DEBUGGER_ID_6811_EMULATOR                    7 // MC6812 emulator (beta)
#define DEBUGGER_ID_GDB_USER                         8 // GDB remote
#define DEBUGGER_ID_WINDBG                           9 // WinDBG using Microsoft Debug engine
#define DEBUGGER_ID_X86_DOSBOX_EMULATOR             10 // Dosbox MS-DOS emulator
#define DEBUGGER_ID_ARM_LINUX_USER                  11 // Userland arm linux
#define DEBUGGER_ID_TRACE_REPLAYER                  12 // Fake debugger to replay recorded traces
#define DEBUGGER_ID_ARM_WINCE_TCPIP                 13 // Windows CE ARM (TPC/IP transport)

// ...
  const char *processor;              // Required processor name
                                      // Used for instant debugging to load the correct
                                      // processor module

  uint32 flags;                             // Debugger module special features
#define DBG_FLAG_REMOTE       0x00000001    // Remote debugger (requires remote host name unless DBG_FLAG_NOHOST)
#define DBG_FLAG_NOHOST       0x00000002    // Remote debugger with does not require network params (host/port/pass)
                                            // (a unique device connected to the machine)
#define DBG_FLAG_FAKE_ATTACH  0x00000004    // PROCESS_ATTACH is a fake event
                                            // and does not suspend the execution
#define DBG_FLAG_HWDATBPT_ONE 0x00000008    // Hardware data breakpoints are
                                            // one byte size by default
#define DBG_FLAG_CAN_CONT_BPT 0x00000010    // Debugger knows to continue from a bpt
                                            // This flag also means that the debugger module
                                            // hides breakpoints from ida upon read_memory
#define DBG_FLAG_NEEDPORT     0x00000020    // Remote debugger requires port number (to be used with DBG_FLAG_NOHOST)
#define DBG_FLAG_DONT_DISTURB 0x00000040    // Debugger can handle only
                                            //   get_debug_event()
                                            //   prepare_to_pause_process()
                                            //   exit_process()
                                            // when the debugged process is running.
                                            // The kernel may also call service functions
                                            // (file I/O, map_address, etc)
#define DBG_FLAG_SAFE         0x00000080    // The debugger is safe (probably because it just emulates the application
                                            // without really running it)
#define DBG_FLAG_CLEAN_EXIT   0x00000100    // IDA must suspend the application and remove
                                            // all breakpoints before terminating the application.
                                            // Usually this is not required because the application memory
                                            // disappears upon termination.
#define DBG_FLAG_USE_SREGS    0x00000200    // Take segment register values into account (non flat memory)
#define DBG_FLAG_NOSTARTDIR   0x00000400    // Debugger module doesn't use startup directory
#define DBG_FLAG_NOPARAMETERS 0x00000800    // Debugger module doesn't use commandline parameters
#define DBG_FLAG_NOPASSWORD   0x00001000    // Remote debugger doesn't use password
#define DBG_FLAG_CONNSTRING   0x00002000    // Display "Connection string" instead of "Hostname" and hide the "Port" field
#define DBG_FLAG_SMALLBLKS    0x00004000    // If set, IDA uses 256-byte blocks for caching memory contents
                                            // Otherwise, 1024-byte blocks are used
#define DBG_FLAG_MANMEMINFO   0x00008000    // If set, manual memory region manipulation commands
                                            // will be available. Use this bit for debugger modules
                                            // that can not return memory layout information
#define DBG_FLAG_EXITSHOTOK   0x00010000    // IDA may take a memory snapshot at PROCESS_EXIT event
#define DBG_FLAG_VIRTHREADS   0x00020000    // Thread IDs may be shuffled after each debug event
                                            // (to be used for virtual threads that represent cpus for windbg kmode)
#define DBG_FLAG_LOWCNDS      0x00040000    // Low level breakpoint conditions are supported.
#define DBG_FLAG_DEBTHREAD    0x00080000    // Supports creation of a separate thread in ida
                                            // for the debugger (the debthread).
                                            // Most debugger functions will be called from debthread (exceptions are marked below)
                                            // The debugger module may directly call only THREAD_SAFE functions.
                                            // To call other functions please use execute_sync().
                                            // The debthread significantly increases debugging
                                            // speed, especially if debug events occur frequently (to be tested)
#define DBG_FLAG_DEBUG_DLL    0x00100000    // Can debug standalone DLLs
                                            // For example, Bochs debugger can debug any snippet of code
#define DBG_FLAG_FAKE_MEMORY  0x00200000    // get_memory_info/read_memory/write_memory functions work with the idb
                                            // (there is no real process to read from, as for the replayer module)
                                            // the kernel will not call these functions if this flag is set.
                                            // however, third party plugins may call them, they must be implemented.
#define DBG_FLAG_ANYSIZE_HWBPT 0x00400000   // The debugger supports arbitrary size hardware breakpoints.

  bool is_remote(void) const { return (flags & DBG_FLAG_REMOTE) != 0; }
  bool must_have_hostname(void) const
    { return (flags & (DBG_FLAG_REMOTE|DBG_FLAG_NOHOST)) == DBG_FLAG_REMOTE; }
  bool can_continue_from_bpt(void) const
    { return (flags & DBG_FLAG_CAN_CONT_BPT) != 0; }
  bool may_disturb(void) const
    { return (flags & DBG_FLAG_DONT_DISTURB) == 0; }
  bool is_safe(void) const
    { return (flags & DBG_FLAG_SAFE) != 0; }
  bool use_sregs(void) const
    { return (flags & DBG_FLAG_USE_SREGS) != 0; }
  size_t cache_block_size(void) const
    { return (flags & DBG_FLAG_SMALLBLKS) != 0 ? 256 : 1024; }
  bool use_memregs(void) const
    { return (flags & DBG_FLAG_MANMEMINFO) != 0; }
  bool may_take_exit_snapshot(void) const
    { return (flags & DBG_FLAG_EXITSHOTOK) != 0; }
  bool virtual_threads(void) const
    { return (flags & DBG_FLAG_VIRTHREADS) != 0; }
  bool supports_lowcnds(void) const
    { return (flags & DBG_FLAG_LOWCNDS) != 0; }
  bool supports_debthread(void) const
    { return (flags & DBG_FLAG_DEBTHREAD) != 0; }
  bool can_debug_standalone_dlls(void) const
    { return (flags & DBG_FLAG_DEBUG_DLL) != 0; }
  bool fake_memory(void) const
    { return (flags & DBG_FLAG_FAKE_MEMORY) != 0; }

  const char    **register_classes;         // Array of register class names
  int             register_classes_default; // Mask of default printed register classes
  register_info_t *registers;               // Array of registers
  int             registers_size;           // Number of registers

  int             memory_page_size;         // Size of a memory page

  const uchar     *bpt_bytes;               // Array of bytes for a breakpoint instruction
  uchar            bpt_size;                // Size of this array
  uchar            filetype;                // for miniidbs: use this value
                                            // for the file type after attaching
                                            // to a new process
  ushort           reserved;

#if !defined(_MSC_VER)  // this compiler complains :(
  static const int default_port_number = 23946;
#define DEBUGGER_PORT_NUMBER debugger_t::default_port_number
#else
#define DEBUGGER_PORT_NUMBER 23946
#endif

  // Initialize debugger
  // Returns true-success
  // This function is called from the main thread
  bool (idaapi *init_debugger)(const char *hostname, int portnum, const char *password);

  // Terminate debugger
  // Returns true-success
  // This function is called from the main thread
  bool (idaapi *term_debugger)(void);

  // Return information about the n-th "compatible" running process.
  // If n is 0, the processes list is reinitialized.
  // 1-ok, 0-failed, -1-network error
  // This function is called from the main thread
  int (idaapi *process_get_info)(int n, process_info_t *info);

  // Start an executable to debug
  // 1 - ok, 0 - failed, -2 - file not found (ask for process options)
  // 1|CRC32_MISMATCH - ok, but the input file crc does not match
  // -1 - network error
  // This function is called from debthread
  int (idaapi *start_process)(const char *path,
                              const char *args,
                              const char *startdir,
                              int dbg_proc_flags,
                              const char *input_path,
                              uint32 input_file_crc32);
#define DBG_PROC_IS_DLL 0x01            // database contains a dll (not exe)
#define DBG_PROC_IS_GUI 0x02            // using gui version of ida
#define DBG_PROC_32BIT  0x04            // application is 32-bit
#define DBG_PROC_64BIT  0x08            // application is 64-bit
#define CRC32_MISMATCH  0x40000000      // crc32 mismatch bit

  // Attach to an existing running process
  // 1-ok, 0-failed, -1-network error
  // event_id should be equal to -1 if not attaching to a crashed process
  // This function is called from debthread
  int (idaapi *attach_process)(pid_t pid, int event_id);

  // Detach from the debugged process
  // May be called while the process is running or suspended.
  // Must detach from the process in any case.
  // The kernel will repeatedly call get_debug_event() and until PROCESS_DETACH.
  // In this mode, all other events will be automatically handled and process will be resumed.
  // 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *detach_process)(void);

  // rebase database if the debugged program has been rebased by the system
  // This function is called from the main thread
  void (idaapi *rebase_if_required_to)(ea_t new_base);

  // Prepare to pause the process
  // This function will prepare to pause the process
  // Normally the next get_debug_event() will pause the process
  // If the process is sleeping then the pause will not occur
  // until the process wakes up. The interface should take care of
  // this situation.
  // If this function is absent, then it won't be possible to pause the program
  // 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *prepare_to_pause_process)(void);

  // Stop the process.
  // May be called while the process is running or suspended.
  // Must terminate the process in any case.
  // The kernel will repeatedly call get_debug_event() and until PROCESS_EXIT.
  // In this mode, all other events will be automatically handled and process will be resumed.
  // 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *exit_process)(void);

  // Get a pending debug event and suspend the process
  // This function will be called regularly by IDA.
  // This function is called from debthread
  gdecode_t (idaapi *get_debug_event)(debug_event_t *event, int timeout_ms);

  // Continue after handling the event
  // 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *continue_after_event)(const debug_event_t *event);

  // Set exception handling
  // This function is called from debthread or the main thread
  void (idaapi *set_exception_info)(const exception_info_t *info, int qty);

  // The following function will be called by the kernel each time
  // when it has stopped the debugger process for some reason,
  // refreshed the database and the screen.
  // The debugger module may add information to the database if it wants.
  // The reason for introducing this function is that when an event line
  // LOAD_DLL happens, the database does not reflect the memory state yet
  // and therefore we can't add information about the dll into the database
  // in the get_debug_event() function.
  // Only when the kernel has adjusted the database we can do it.
  // Example: for imported PE DLLs we will add the exported function
  // names to the database.
  // This function pointer may be absent, i.e. NULL.
  // This function is called from the main thread
  void (idaapi *stopped_at_debug_event)(bool dlls_added);

  // The following functions manipulate threads.
  // 1-ok, 0-failed, -1-network error
  // These functions are called from debthread
  int (idaapi *thread_suspend) (thid_t tid); // Suspend a running thread
  int (idaapi *thread_continue)(thid_t tid); // Resume a suspended thread
  int (idaapi *thread_set_step)(thid_t tid); // Run one instruction in the thread

  // Read thread registers
  //    tid    - thread id
  //    clsmask- bitmask of register classes to read
  //    regval - pointer to vector of regvals for all registers
  //             regval is assumed to have debugger_t::registers_size elements
  // 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *read_registers)(thid_t tid, int clsmask, regval_t *values);

  // Write one thread register
  //    tid    - thread id
  //    regidx - register index
  //    regval - new value of the register
  // 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *write_register)(thid_t tid, int regidx, const regval_t *value);


  // Get information about the base of a segment register
  // Currently used by the IBM PC module to resolve references like fs:0
  //   tid        - thread id
  //   sreg_value - value of the segment register (returned by get_reg_val())
  //   answer     - pointer to the answer. can't be NULL.
  // 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *thread_get_sreg_base)(thid_t tid, int sreg_value, ea_t *answer);

//
// The following functions manipulate bytes in the memory.
//
  // Get information on the memory areas
  // The debugger module fills 'areas'. The returned vector MUST be sorted.
  // Returns:
  //   -3: use idb segmentation
  //   -2: no changes
  //   -1: the process does not exist anymore
  //    0: failed
  //    1: new memory layout is returned
  // This function is called from debthread
  int (idaapi *get_memory_info)(meminfo_vec_t &areas);

  // Read process memory
  // Returns number of read bytes
  // 0 means read error
  // -1 means that the process does not exist anymore
  // This function is called from debthread
  ssize_t (idaapi *read_memory)(ea_t ea, void *buffer, size_t size);

  // Write process memory
  // Returns number of written bytes, -1-fatal error
  // This function is called from debthread
  ssize_t (idaapi *write_memory)(ea_t ea, const void *buffer, size_t size);

  // Is it possible to set breakpoint?
  // Returns: BPT_...
  // This function is called from debthread or from the main thread if debthread
  // is not running yet.
  // It is called to verify hardware breakpoints.
  int (idaapi *is_ok_bpt)(bpttype_t type, ea_t ea, int len);
#define BPT_OK           0
#define BPT_INTERNAL_ERR 1
#define BPT_BAD_TYPE     2
#define BPT_BAD_ALIGN    3
#define BPT_BAD_ADDR     4
#define BPT_BAD_LEN      5
#define BPT_TOO_MANY     6
#define BPT_READ_ERROR   7
#define BPT_WRITE_ERROR  8
#define BPT_SKIP         9 // update_bpts: do not process bpt
#define BPT_PAGE_OK     10 // update_bpts: ok, added a page bpt

  // Add/del breakpoints.
  // bpts array contains nadd bpts to add, followed by ndel bpts to del.
  // returns number of successfully modified bpts, -1-network error
  // This function is called from debthread
  int (idaapi *update_bpts)(update_bpt_info_t *bpts, int nadd, int ndel);

  // Update low-level (server side) breakpoint conditions
  // Returns nlowcnds. -1-network error
  // This function is called from debthread
  int (idaapi *update_lowcnds)(const lowcnd_t *lowcnds, int nlowcnds);

  // Open/close/read a remote file
  // These functions are called from the main thread
  int  (idaapi *open_file)(const char *file, uint32 *fsize, bool readonly); // -1-error
  void (idaapi *close_file)(int fn);
  ssize_t (idaapi *read_file)(int fn, uint32 off, void *buf, size_t size);

  // Map process address
  // This function may be absent
  //      off    - offset to map
  //      regs   - current register values. if regs == NULL, then perform
  //               global mapping, which is indepedent on used registers
  //               usually such a mapping is a trivial identity mapping
  //      regnum - required mapping. maybe specified as a segment register number
  //               or a regular register number if the required mapping can be deduced
  //               from it. for example, esp implies that ss should be used.
  // Returns: mapped address or BADADDR
  // This function is called from debthread
  ea_t (idaapi *map_address)(ea_t off, const regval_t *regs, int regnum);

  // Set debugger options (parameters that are specific to the debugger module)
  // See the definition of set_options_t in idp.hpp for arguments.
  // See the convenience function in dbg.hpp if you need to call it.
  // This function is optional.
  // This function is called from the main thread
  const char *(idaapi *set_dbg_options)(
        const char *keyword,
        int value_type,
        const void *value);


  // Get pointer to debugger specific functions.
  // This function returns a pointer to a structure that holds pointers to
  // debugger module specific functions. For information on the structure
  // layout, please check the corresponding debugger module. Most debugger
  // modules return NULL because they do not have any extensions. Available
  // extensions may be called from plugins.
  // This function is called from the main thread
  const void *(idaapi *get_debmod_extensions)(void);


  // Calculate the call stack trace
  // This function is called when the process is suspended and should fill
  // the 'trace' object with the information about the current call stack.
  // Returns: true-ok, false-failed.
  // If this function is missing or returns false, IDA will use the standard
  // mechanism (based on the frame pointer chain) to calculate the stack trace
  // This function is called from the main thread
  bool (idaapi *update_call_stack)(thid_t tid, call_stack_t *trace);

  // Call application function.
  // This function calls a function from the debugged application.
  //      func_ea - address to call
  //      tid     - thread to use
  //      fti     - type information for the called function
  //      nargs   - number of actual arguments
  //      regargs - information about register arguments
  //      stkargs - memory blob to pass as stack arguments (usually contains pointed data)
  //                it must be relocated by the callback but not changed otherwise
  //      retregs - function return registers.
  //      errbuf  - out: the error message. if empty on failure, see 'event'
  //                     should not be filled if an appcall exception
  //                     happened but APPCALL_DEBEV is set
  //      event   - out: the last debug event that occured during appcall execution
  //                     filled only if the appcall execution fails and APPCALL_DEBEV is set
  //      options - appcall options, usually taked from inf.appcall_options
  //                possible values: combination of APPCALL_.. constants or 0
  // Returns: ea of stkargs blob, BADADDR-failed, errbuf is filled
  // This function is called from debthread
  ea_t (idaapi *appcall)(
        ea_t func_ea,
        thid_t tid,
        const struct func_type_info_t *fti,
        int nargs,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int options);

#define APPCALL_MANUAL  0x0001  // Only set up the appcall, do not run
                                // cleanup_appcall will not be called by ida!
#define APPCALL_DEBEV   0x0002  // Return debug event information
#define APPCALL_TIMEOUT 0x0004  // Appcall with timeout
                                // The timeout value in milliseconds is specified
                                // in the high 2 bytes of the 'options' argument:
                                // If timed out, errbuf will contain "timeout".
#define SET_APPCALL_TIMEOUT(msecs)   ((uint(msecs) << 16)|APPCALL_TIMEOUT)
#define GET_APPCALL_TIMEOUT(options) (uint(options) >> 16)

  // Cleanup after appcall()
  // The debugger module must keep the stack blob in the memory until this function
  // is called. It will be called by the kernel for each successful appcall().
  // There is an exception: if APPCALL_MANUAL, IDA may not call cleanup_appcall.
  // If the user selects to terminate a manual appcall, then cleanup_appcall will be called.
  // Otherwise, the debugger module should terminate the appcall when the called
  // function returns.
  // 2-ok, there are pending events, 1-ok, 0-failed, -1-network error
  // This function is called from debthread
  int (idaapi *cleanup_appcall)(thid_t tid);

  // Evaluate a low level breakpoint condition at 'ea'
  // Returns: 1-condition is satisfied, 0-not satisfired, -1-network error
  // Other evaluation errors are displayed in a dialog box.
  // This call is rarely used by IDA when the process has already been suspended
  // for some reason and it has to decide whether the process should be resumed
  // or definitely suspended because of a breakpoint with a low level condition.
  // This function is called from debthread
  int (idaapi *eval_lowcnd)(thid_t tid, ea_t ea);

  // This function is called from main thread
  ssize_t (idaapi *write_file)(int fn, uint32 off, const void *buf, size_t size);

  // Perform a debugger-specific function
  // This function is called from debthread
  int (idaapi *send_ioctl)(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize);
};

CASSERT((sizeof(debugger_t) % 4) == 0);

#ifndef NO_OBSOLETE_FUNCS
DEPRECATED typedef thid_t thread_id_t;
DEPRECATED typedef pid_t process_id_t;
#define PROCESS_NO_THREAD 0          // No thread
DEPRECATED struct idd_opinfo_old_t { ea_t addr; uval_t value;  bool modified; };
#endif

#pragma pack(pop)
#endif // _IDD_HPP
