#pragma once
#include <Windows.h>

#pragma pack(1)                      // Force byte alignment of structures

#define SHORTLEN       8               // Maximal length of short name
#define TEXTLEN        256             // Maximal length of text string

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
struct t_module;
extern "C" void _Addtolist(long addr,int highlight,char *format,...);
extern "C" void _Message(unsigned long addr,char *format,...);
extern "C" void _Error(char *format,...);
extern "C" void _Deletebreakpoints(unsigned long addr0,unsigned long addr1,int silent);
extern "C" int _Setbreakpoint(unsigned long addr,unsigned long type,unsigned char cmd);
extern "C" int _Plugingetvalue(int type);
extern "C" void _Tempbreakpoint(unsigned long addr,int mode);
extern "C" int _Gettext(char *title,char *text, char letter,int type,int fontindex);
extern "C" int _Attachtoactiveprocess(int newprocessid);
extern "C" void _Infoline(char *format,...);
extern "C" t_module* _Findmodule(unsigned long addr);
extern "C" unsigned long _Writememory(void *buf,unsigned long addr,unsigned long size,int mode);

#define NBAR 17 // Max allowed number of segments in bar
#define PLUGIN_VERSION 110
#define PM_MAIN 0 // Main window        (NULL)
#define PM_THREADS 13 // Threads window     (t_thread*)
#define VAL_HINST              1       // Current program instance
#define VAL_HWMAIN             2       // Handle of the main window
#define VAL_HWCLIENT           3       // Handle of the MDI client window
#define VAL_NCOLORS            4       // Number of common colors
#define VAL_COLORS             5       // RGB values of common colors
#define VAL_BRUSHES            6       // Handles of common color brushes
#define VAL_PENS               7       // Handles of common color pens
#define VAL_NFONTS             8       // Number of common fonts
#define VAL_FONTS              9       // Handles of common fonts
#define VAL_FONTNAMES          10      // Internal font names
#define VAL_FONTWIDTHS         11      // Average widths of common fonts
#define VAL_FONTHEIGHTS        12      // Average heigths of common fonts
#define VAL_NFIXFONTS          13      // Actual number of fixed-pitch fonts
#define VAL_DEFFONT            14      // Index of default font
#define VAL_NSCHEMES           15      // Number of color schemes
#define VAL_SCHEMES            16      // Color schemes
#define VAL_DEFSCHEME          17      // Index of default colour scheme
#define VAL_DEFHSCROLL         18      // Default horizontal scroll
#define VAL_RESTOREWINDOWPOS   19      // Restore window positions from .ini
#define VAL_HPROCESS           20      // Handle of Debuggee
#define VAL_PROCESSID          21      // Process ID of Debuggee
#define VAL_HMAINTHREAD        22      // Handle of main thread
#define VAL_MAINTHREADID       23      // Thread ID of main thread
#define VAL_MAINBASE           24      // Base of main module in the process
#define VAL_PROCESSNAME        25      // Name of the active process
#define VAL_EXEFILENAME        26      // Name of the main debugged file
#define VAL_CURRENTDIR         27      // Current directory for debugged process
#define VAL_SYSTEMDIR          28      // Windows system directory
#define VAL_DECODEANYIP        29      // Decode registers dependless on EIP
#define VAL_PASCALSTRINGS      30      // Decode Pascal-style string constants
#define VAL_ONLYASCII          31      // Only printable ASCII chars in dump
#define VAL_DIACRITICALS       32      // Allow diacritical symbols in strings
#define VAL_GLOBALSEARCH       33      // Search from the beginning of block
#define VAL_ALIGNEDSEARCH      34      // Search aligned to item's size
#define VAL_IGNORECASE         35      // Ignore case in string search
#define VAL_SEARCHMARGIN       36      // Floating search allows error margin
#define VAL_KEEPSELSIZE        37      // Keep size of hex edit selection
#define VAL_MMXDISPLAY         38      // MMX display mode in dialog
#define VAL_WINDOWFONT         39      // Use calling window's font in dialog
#define VAL_TABSTOPS           40      // Distance between tab stops
#define VAL_MODULES            41      // Table of modules (.EXE and .DLL)
#define VAL_MEMORY             42      // Table of allocated memory blocks
#define VAL_THREADS            43      // Table of active threads
#define VAL_BREAKPOINTS        44      // Table of active breakpoints
#define VAL_REFERENCES         45      // Table with found references
#define VAL_SOURCELIST         46      // Table of source files
#define VAL_WATCHES            47      // Table of watches
#define VAL_CPUFEATURES        50      // CPU feature bits
#define VAL_TRACEFILE          51      // Handle of run trace log file
#define VAL_ALIGNDIALOGS       52      // Whether to align dialogs
#define VAL_CPUDASM            53      // Dump descriptor of CPU Disassembler
#define VAL_CPUDDUMP           54      // Dump descriptor of CPU Dump
#define VAL_CPUDSTACK          55      // Dump descriptor of CPU Stack
#define VAL_APIHELP            56      // Name of selected API help file
#define VAL_HARDBP             57      // Whether hardware breakpoints enabled
#define VAL_PATCHES            58      // Table of patches
#define VAL_HINTS              59      // Sorted data with analysis hints

#define NREGSTACK      32              // Length of stack trace buffer
#define NVERS          32              // Max allowed length of file version

#define MM_RESTORE     0x01            // Restore or remove INT3 breakpoints
#define MM_SILENT      0x02            // Don't display error message
#define MM_DELANAL     0x04            // Delete analysis from the memory

typedef unsigned long  ulong;
typedef unsigned char  uchar;
typedef unsigned short ushort;

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

typedef struct t_operand {             // Full decription of command's operand
    char           optype;               // DEC_xxx (mem) or DECR_xxx (reg,const)
    char           opsize;               // Size of operand
    char           regscale[8];          // Scales of registers
    char           seg;                  // Segment register
    ulong          opconst;              // Constant
} t_operand;

typedef struct t_disasm {              // Results of disassembling
    ulong          ip;                   // Instrucion pointer
    char           dump[TEXTLEN];        // Hexadecimal dump of the command
    char           result[TEXTLEN];      // Disassembled command
    char           comment[TEXTLEN];     // Brief comment
    char           opinfo[3][TEXTLEN];   // Comments to command's operands
    int            cmdtype;              // One of C_xxx
    int            memtype;              // Type of addressed variable in memory
    int            nprefix;              // Number of prefixes
    int            indexed;              // Address contains register(s)
    ulong          jmpconst;             // Constant jump address
    ulong          jmptable;             // Possible address of switch table
    ulong          adrconst;             // Constant part of address
    ulong          immconst;             // Immediate constant
    int            zeroconst;            // Whether contains zero constant
    int            fixupoffset;          // Possible offset of 32-bit fixups
    int            fixupsize;            // Possible total size of fixups or 0
    ulong          jmpaddr;              // Destination of jump/call/return
    int            condition;            // 0xFF:unconditional, 0:false, 1:true
    int            error;                // Error while disassembling command
    int            warnings;             // Combination of DAW_xxx
    int            optype[3];            // Type of operand (extended set DEC_xxx)
    int            opsize[3];            // Size of operand, bytes
    int            opgood[3];            // Whether address and data valid
    ulong          opaddr[3];            // Address if memory, index if register
    ulong          opdata[3];            // Actual value (only integer operands)
    t_operand      op[3];                // Full description of operand
    ulong          regdata[8];           // Registers after command is executed
    int            regstatus[8];         // Status of registers, one of RST_xxx
    ulong          addrdata;             // Traced memory address
    int            addrstatus;           // Status of addrdata, one of RST_xxx
    ulong          regstack[NREGSTACK];  // Stack tracing buffer
    int            rststatus[NREGSTACK]; // Status of stack items
    int            nregstack;            // Number of items in stack trace buffer
    ulong          reserved[29];         // Reserved for plugin compatibility
} t_disasm;

typedef ulong SPECFUNC(char *,ulong,ulong,ulong,t_disasm *,int);

typedef struct t_dump {                // Current status of dump window
    t_table        table;                // Treat dump window as custom table
    int            dimmed;               // Draw in lowcolor if nonzero
    ulong          threadid;             // Use decoding and registers if not 0
    int            dumptype;             // Current dump type, DU_xxx+count+size
    SPECFUNC       *specdump;            // Decoder of DU_SPEC dump types
    int            menutype;             // Standard menues, MT_xxx
    int            itemwidth;            // Length of displayed item, characters
    int            showstackframes;      // Show stack frames in address dump
    int            showstacklocals;      // Show names of locals in stack
    int            commentmode;          // 0: comment, 1: source, 2: profile
    char           filename[MAX_PATH];   // Name of displayed or backup file
    ulong          base;                 // Start of memory block or file
    ulong          size;                 // Size of memory block or file
    ulong          addr;                 // Address of first displayed byte
    ulong          lastaddr;             // Address of last displayed byte + 1
    ulong          sel0;                 // Address of first selected byte
    ulong          sel1;                 // Last selected byte (not included!)
    ulong          startsel;             // Start of last selection
    int            captured;             // Mouse is captured by dump
    ulong          reladdr;              // Addresses relative to this
    char           relname[SHORTLEN];    // Symbol for relative zero address base
    uchar          *filecopy;            // Copy of the file or NULL
    uchar          *backup;              // Old backup of memory/file or NULL
    int            runtraceoffset;       // Offset back in run trace
    ulong          reserved[8];          // Reserved for the future extentions
} t_dump;

typedef struct t_stringtable {         // Pointers to string resources
    ulong          name;                 // Name of block of strings
    ulong          language;             // Language identifier
    ulong          addr;                 // Address of block in memory
    ulong          size;                 // Size of block in memory
} t_stringtable;

typedef struct t_fixup {
    ulong          base;                 // Address of fixup
    ulong          size;                 // Size of fixup (usually 2 or 4 bytes)
} t_fixup;

typedef struct t_symvar {              // Symbolic variable from debug data
    int            next;                 // Index of next variable in chain or -1
    ushort         kind;                 // Kind of variable
    union {
        ulong        type;                 // Type of variable
        ulong        regs;
    };              // Registers in optvar
    union {
        ulong        addr;                 // Address or description of registers
        long         offset;
    };            // Offset for EBP-relative data
    ulong          size;                 // Size of variable or optvar data
    int            optvar;               // Index of optvar chain or -1
    ulong          nameaddr;             // NM_DEBUG address of var's name
} t_symvar;

typedef struct t_jdest {               // Element of jump data
    char           type;                 // Type of jump, one of JT_xxx
    ulong          from;                 // Jump source
    ulong          to;                   // Jump destination
} t_jdest;

typedef struct t_module {              // Executable module descriptor
    ulong          base;                 // Base address of module
    ulong          size;                 // Size occupied by module
    ulong          type;                 // Service information, TY_xxx
    ulong          codebase;             // Base address of module code block
    ulong          codesize;             // Size of module code block
    ulong          resbase;              // Base address of resources
    ulong          ressize;              // Size of resources
    t_stringtable  *stringtable;         // Pointers to string resources or NULL
    int            nstringtable;         // Actual number of used stringtable
    int            maxstringtable;       // Actual number of allocated stringtable
    ulong          entry;                // Address of <ModuleEntryPoint> or NULL
    ulong          database;             // Base address of module data block
    ulong          idatatable;           // Base address of import data table
    ulong          idatabase;            // Base address of import data block
    ulong          edatatable;           // Base address of export data table
    ulong          edatasize;            // Size of export data table
    ulong          reloctable;           // Base address of relocation table
    ulong          relocsize;            // Size of relocation table
    char           name[SHORTLEN];       // Short name of the module
    char           path[MAX_PATH];       // Full name of the module
    int            nsect;                // Number of sections in the module
    IMAGE_SECTION_HEADER *sect;          // Copy of section headers from file
    ulong          headersize;           // Total size of headers in executable
    ulong          fixupbase;            // Base of image in executable file
    int            nfixup;               // Number of fixups in executable
    t_fixup        *fixup;               // Extracted fixups or NULL
    char           *codedec;             // Decoded code features or NULL
    ulong          codecrc;              // Code CRC for actual decoding
    char           *hittrace;            // Hit tracing data or NULL
    char           *hittracecopy;        // Copy of INT3-substituted code
    char           *datadec;             // Decoded data features or NULL
    t_table        namelist;             // List of module names
    t_symvar       *symvar;              // Descriptions of symbolic variables
    int            nsymvar;              // Actual number of elements in symvar
    int            maxsymvar;            // Maximal number of elements in symvar
    char           *globaltypes;         // Global types from debug info
    ulong          mainentry;            // Address of WinMain() etc. in dbg data
    ulong          realsfxentry;         // Entry of packed code or NULL
    int            updatenamelist;       // Request to update namelist
    ulong          origcodesize;         // Original size of module code block
    ulong          sfxbase;              // Base of memory block with SFX
    ulong          sfxsize;              // Size of memory block with SFX
    int            issystemdll;          // Whether system DLL
    int            processed;            // 0: not processed, 1: good, -1: bad
    int            dbghelpsym;           // 1: symbols loaded by dbghelp.dll
    char           version[NVERS];       // Version of executable file
    t_jdest        *jddata;              // Recognized jumps within the module
    int            njddata;              // Number of recognized jumps
    ulong          reserved[15];         // Reserved for plugin compatibility
} t_module;

typedef struct t_bpoint {              // Description of INT3 breakpoint
	ulong          addr;                 // Address of breakpoint
	ulong          dummy;                // Always 1
	ulong          type;                 // Type of breakpoint, TY_xxx
	char           cmd;                  // Old value of command
	ulong          passcount;            // Actual pass count
} t_bpoint;

// Dumpbackup() actions.
#define BKUP_CREATE    1               // Create or update backup copy
#define BKUP_VIEWDATA  2               // View original data
#define BKUP_VIEWCOPY  3               // View backup copy
#define BKUP_LOADCOPY  4               // Read backup copy from file
#define BKUP_SAVEDATA  5               // Save original data to file
#define BKUP_SAVECOPY  6               // Save backup copy to file
#define BKUP_DELETE    7               // Delete backup copy

extern "C" void*   cdecl _Getsortedbyselection(t_sorted *sd,int index);
extern "C" void    cdecl _Dumpbackup(t_dump *pd,int action);


// Types of names used in name functions. Note that higher-priority types have
// smaller identifiers!
#define NM_NONAME      0x00            // Undefined name
#define NM_ANYNAME     0xFF            // Name of any type
// Names saved in the data file of module they appear.
#define NM_PLUGCMD     0x30            // Plugin commands to execute at break
#define NM_LABEL       0x31            // User-defined label
#define NM_EXPORT      0x32            // Exported (global) name
#define NM_IMPORT      0x33            // Imported name
#define NM_LIBRARY     0x34            // Name from library or object file
#define NM_CONST       0x35            // User-defined constant
#define NM_COMMENT     0x36            // User-defined comment
#define NM_LIBCOMM     0x37            // Comment from library or object file
#define NM_BREAK       0x38            // Condition related with breakpoint
#define NM_ARG         0x39            // Arguments decoded by analyzer
#define NM_ANALYSE     0x3A            // Comment added by analyzer
#define NM_BREAKEXPR   0x3B            // Expression related with breakpoint
#define NM_BREAKEXPL   0x3C            // Explanation related with breakpoint
#define NM_ASSUME      0x3D            // Assume function with known arguments
#define NM_STRUCT      0x3E            // Code structure decoded by analyzer
#define NM_CASE        0x3F            // Case description decoded by analyzer
// Names saved in the data file of main module.
#define NM_INSPECT     0x40            // Several last inspect expressions
#define NM_WATCH       0x41            // Watch expressions
#define NM_ASM         0x42            // Several last assembled strings
#define NM_FINDASM     0x43            // Several last find assembler strings
#define NM_LASTWATCH   0x48            // Several last watch expressions
#define NM_SOURCE      0x49            // Several last source search strings
#define NM_REFTXT      0x4A            // Several last ref text search strings
#define NM_GOTO        0x4B            // Several last expressions to follow
#define NM_GOTODUMP    0x4C            // Several expressions to follow in Dump
#define NM_TRPAUSE     0x4D            // Several expressions to pause trace
// Pseudonames.
#define NM_IMCALL      0xFE            // Intermodular call

#define NMHISTORY      0x40            // Converts NM_xxx to type of init list
extern "C" int     cdecl _Insertname(ulong addr,int type,char *name);


typedef enum t_status {                // Thread/process status
	STAT_NONE=0,                         // Thread/process is empty
	STAT_STOPPED,                        // Thread/process suspended
	STAT_EVENT,                          // Processing debug event, process paused
	STAT_RUNNING,                        // Thread/process running
	STAT_FINISHED,                       // Process finished
	STAT_CLOSING                         // Process is requested to terminate
} t_status;

extern "C" t_status cdecl _Getstatus(void);
