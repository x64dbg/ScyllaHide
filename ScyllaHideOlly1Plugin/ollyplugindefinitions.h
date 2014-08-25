#pragma once
#include <Windows.h>

#pragma pack(1)                      // Force byte alignment of structures


#define TY_STOPAN      0x00000080      // Stop animation if TY_ONESHOT
#define TY_SET         0x00000100      // Code INT3 is in memory
#define TY_ACTIVE      0x00000200      // Permanent breakpoint
#define TY_DISABLED    0x00000400      // Permanent disabled breakpoint
#define TY_ONESHOT     0x00000800      // Temporary stop
#define TY_TEMP        0x00001000      // Temporary breakpoint
#define TY_KEEPCODE    0x00002000      // Set and keep command code
#define TY_KEEPCOND    0x00004000      // Keep condition unchanged (0: remove)
#define TY_NOUPDATE    0x00008000      // Don't redraw breakpoint window
#define TY_RTRACE      0x00010000      // Pseudotype of run trace breakpoint

//olly definitions
extern "C" void _Addtolist(long addr,int highlight,char *format,...);
extern "C" void _Message(unsigned long addr,char *format,...);
extern "C" void _Error(char *format,...);
extern "C" void _Deletebreakpoints(unsigned long addr0,unsigned long addr1,int silent);
extern "C" int _Setbreakpoint(unsigned long addr,unsigned long type,unsigned char cmd);
extern "C" int _Plugingetvalue(int type);
extern "C" void _Tempbreakpoint(unsigned long addr,int mode);
extern "C" int _Gettext(char *title,char *text, char letter,int type,int fontindex);
extern "C" int _Attachtoactiveprocess(int newprocessid);

#define NBAR 17 // Max allowed number of segments in bar
#define PLUGIN_VERSION 110
#define PM_MAIN 0 // Main window        (NULL)
#define PM_THREADS 13 // Threads window     (t_thread*)
#define VAL_HPROCESS 20 // Handle of Debuggee
#define VAL_PROCESSID 21 // Process ID of Debuggee
#define VAL_MAINBASE 24 // Base of main module in the process
#define VAL_THREADS 43 // Table of active threads


typedef unsigned long  ulong;
typedef unsigned char  uchar;

typedef struct t_reg {                 // Excerpt from context
    int            modified;             // Some regs modified, update context
    int            modifiedbyuser;       // Among modified, some modified by user
    int            singlestep;           // Type of single step, SS_xxx
    ulong          r[8];                 // EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
    ulong          ip;                   // Instruction pointer (EIP)
    ulong          flags;                // Flags
    int            top;                  // Index of top-of-stack
    long double    f[8];                 // Float registers, f[top] - top of stack
    char           tag[8];               // Float tags (0x3 - empty register)
    ulong          fst;                  // FPU status word
    ulong          fcw;                  // FPU control word
    ulong          s[6];                 // Segment registers ES,CS,SS,DS,FS,GS
    ulong          base[6];              // Segment bases
    ulong          limit[6];             // Segment limits
    char           big[6];               // Default size (0-16, 1-32 bit)
    ulong          dr6;                  // Debug register DR6
    ulong          threadid;             // ID of thread that owns registers
    ulong          lasterror;            // Last thread error or 0xFFFFFFFF
    int            ssevalid;             // Whether SSE registers valid
    int            ssemodified;          // Whether SSE registers modified
    char           ssereg[8][16];        // SSE registers
    ulong          mxcsr;                // SSE control and status register
    int            selected;             // Reports selected register to plugin
    ulong          drlin[4];             // Debug registers DR0..DR3
    ulong          dr7;                  // Debug register DR7
} t_reg;

typedef struct t_thread {              // Information about active threads
    ulong          threadid;             // Thread identifier
    ulong          dummy;                // Always 1
    ulong          type;                 // Service information, TY_xxx
    HANDLE         thread;               // Thread handle
    ulong          datablock;            // Per-thread data block
    ulong          entry;                // Thread entry point
    ulong          stacktop;             // Working variable of Listmemory()
    ulong          stackbottom;          // Working variable of Listmemory()
    CONTEXT        context;              // Actual context of the thread
    t_reg          reg;                  // Actual contents of registers
    int            regvalid;             // Whether reg is valid
    t_reg          oldreg;               // Previous contents of registers
    int            oldregvalid;          // Whether oldreg is valid
    int            suspendcount;         // Suspension count (may be negative)
    long           usertime;             // Time in user mode, 1/10th ms, or -1
    long           systime;              // Time in system mode, 1/10th ms, or -1
    ulong          reserved[16];         // Reserved for future compatibility
} t_thread;

typedef struct t_bar {
    int            nbar;                 // Number of active columns
    int            font;                 // Font used for bar segments
    int            dx[NBAR];             // Actual widths of columns, pixels
    int            defdx[NBAR];          // Default widths of columns, chars
    char           *name[NBAR];          // Column names (may be NULL)
    uchar          mode[NBAR];           // Combination of BAR_xxx bits
    int            captured;             // One of CAPT_xxx, set to CAPT_FREE
    int            active;               // Info about how mouse is captured
    int            prevx;                // Previous mouse coordinate
} t_bar;

typedef struct t_sortheader {          // Header of sorted data field
    ulong          addr;                 // Base address of the entry
    ulong          size;                 // Size address of the entry
    ulong          type;                 // Entry type, TY_xxx
} t_sortheader;

typedef int  SORTFUNC(const t_sortheader *,const t_sortheader *,const int);
typedef int  DRAWFUNC(char *,char *,int *,t_sortheader *,int);
typedef void DESTFUNC(t_sortheader *);

typedef struct t_sorted {              // Descriptor of sorted table
    char           name[MAX_PATH];       // Name of table, as appears in error
    int            n;                    // Actual number of entries
    int            nmax;                 // Maximal number of entries
    int            selected;             // Index of selected entry or -1
    ulong          seladdr;              // Base address of selected entry
    int            itemsize;             // Size of single entry
    ulong          version;              // Unique version of table
    void           *data;                // Entries, sorted by address
    SORTFUNC       *sortfunc;            // Function which sorts data or NULL
    DESTFUNC       *destfunc;            // Destructor function or NULL
    int            sort;                 // Sorting criterium (column)
    int            sorted;               // Whether indexes are sorted
    int            *index;               // Indexes, sorted by criterium
    int            suppresserr;          // Suppress multiple overflow errors
} t_sorted;

typedef struct t_table {               // Window with sorted data and bar
    HWND           hw;                   // Handle of window or NULL
    t_sorted       data;                 // Sorted data
    t_bar          bar;                  // Description of bar
    int            showbar;              // Bar: 1-displayed, 0-hidden, -1-absent
    short          hscroll;              // Horiz. scroll: 1-displayed, 0-hidden
    short          colsel;               // Column in TABLE_COLSEL window
    int            mode;                 // Combination of bits TABLE_xxx
    int            font;                 // Font used by window
    short          scheme;               // Colour scheme used by window
    short          hilite;               // Syntax highlighting used by window
    int            offset;               // First displayed row
    int            xshift;               // Shift in X direction, pixels
    DRAWFUNC       *drawfunc;            // Function which decodes table fields
} t_table;