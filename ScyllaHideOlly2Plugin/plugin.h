////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                        OLLYDBG 2 PLUGIN HEADER FILE                        //
//                                                                            //
//                                Version 2.01                                //
//                                                                            //
//               Written by Oleh Yuschuk (ollydbg@t-online.de)                //
//                                                                            //
//                          Internet: www.ollydbg.de                          //
//                                                                            //
// This code is distributed "as is", without warranty of any kind, expressed  //
// or implied, including, but not limited to warranty of fitness for any      //
// particular purpose. In no event will Oleh Yuschuk be liable to you for any //
// special, incidental, indirect, consequential or any other damages caused   //
// by the use, misuse, or the inability to use of this code, including any    //
// lost profits or lost savings, even if Oleh Yuschuk has been advised of the //
// possibility of such damages.                                               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef __ODBG_PLUGIN_H
#define __ODBG_PLUGIN_H

#define PLUGIN_VERSION 0x02010001      // Version 2.01.0001 of plugin interface


////////////////////////////////////////////////////////////////////////////////
//////////////////////////// IMPORTANT INFORMATION /////////////////////////////

// 1. Plugins are UNICODE libraries!
// 2. Export all callback functions by name, NOT by ordinal!
// 3. Force byte alignment of OllyDbg structures!
// 4. Set default char type to unsigned!
// 5. Most API functions are NOT thread-safe!
// 6. Read documentation!

#if !defined(_UNICODE) && !defined(UNICODE)
  #error This version must be compiled with UNICODE on
#endif


////////////////////////////////////////////////////////////////////////////////
////////////// PREFERRED SETTINGS AND FIXES FOR BORLAND COMPILERS //////////////

#ifdef __BORLANDC__
  #pragma option -a1                   // Byte alignment
  #pragma option -K                    // Force unsigned characters!
  // Redefinition of MAKELONG removes nasty warning under Borland Builder 4.0:
  // boolean OR in one row with arithmetical shift.
  #undef  MAKELONG
  #define MAKELONG(lo,hi) ((LONG)(((WORD)(lo))|(((DWORD)((WORD)(hi)))<<16)))
#endif


////////////////////////////////////////////////////////////////////////////////
///////////// PREFERRED SETTINGS AND FIXES FOR MICROSOFT COMPILERS /////////////

// If you like Microsoft compiler, this will force byte alignment and verify
// that character is set to unsigned.
#ifdef _MSC_VER
  #pragma pack(1)                      // Force byte alignment of structures
  #ifndef _CHAR_UNSIGNED               // Verify that character is unsigned
    #error Please set default char type to unsigned (option /J)
  #endif
#endif


////////////////////////////////////////////////////////////////////////////////
//////////////////// PREFERRED SETTINGS AND FIXES FOR MINGW ////////////////////

#ifdef __MINGW32__
  #pragma pack(1)                      // Force byte alignment of structures
  #ifndef __CHAR_UNSIGNED__            // Verify that character is unsigned
    #error Please set default char type to unsigned (option -funsigned-char)
  #endif
#endif


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// GLOBAL DEFINITIONS //////////////////////////////

#ifndef _export
  #define _export      __declspec(dllexport)
#endif

#ifndef _import
  #define _import      __declspec(dllimport)
#endif

#ifndef _USERENTRY
  #define _USERENTRY   __cdecl
#endif

#define MAKEWP(lo,hi)  ((WPARAM)MAKELONG(lo,hi))
#define MAKELP(lo,hi)  ((LPARAM)MAKELONG(lo,hi))

#define LOINT(l)       ((signed short)((WORD)(l)))
#define HIINT(l)       ((signed short)(((DWORD)(l)>>16) & 0xFFFF))

#ifndef MAXPATH
  #define MAXPATH      MAX_PATH
#endif

#ifndef FIELD_OFFSET
  #define FIELD_OFFSET(type,field) ((LONG)&(((type *)0)->field))
#endif

#ifndef arraysize
  #define arraysize(x) (sizeof(x)/sizeof(x[0]))
#endif

#define TEXTLEN        256             // Max length of text string incl. '\0'
#define DATALEN        4096            // Max length of data record (max 65535)
#define ARGLEN         1024            // Max length of argument string
#define MAXMULTIPATH   8192            // Max length of multiple selection
#define SHORTNAME      32              // Max length of short or module name

typedef unsigned char  uchar;          // Unsigned character (byte)
typedef unsigned short ushort;         // Unsigned short
typedef unsigned int   uint;           // Unsigned integer
typedef unsigned long  ulong;          // Unsigned long

// Exports used by plugins are declared as stdapi if they use fixed number of
// arguments, and varapi if variable or if code is written in Assembler
// language (I use C calling conventions). OllyDbg variables are declared as
// oddata.

#ifdef __cplusplus
  #define extc         extern "C" _export
  #define stdapi(type) extern "C"               type __cdecl
  #define varapi(type) extern "C"               type __cdecl
  #define oddata(type) extern "C" const _import type
  #define pentry(type) extern "C" _export       type __cdecl
#else
  #define extc         extern     _export
  #define stdapi(type) extern                   type __cdecl
  #define varapi(type) extern                   type __cdecl
  #define oddata(type) extern     const _import type
  #define pentry(type) extern     _export       type __cdecl
#endif


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// FORWARD REFERENCES //////////////////////////////

struct t_table;                        // Forward reference
struct t_module;                       // Forward reference
struct t_dump;                         // Forward reference


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// SERVICE FUNCTIONS ///////////////////////////////

// Flags returned by functions Istext.../Israre...
#define PLAINASCII     0x01            // Plain ASCII character
#define DIACRITICAL    0x02            // Diacritical character
#define RAREASCII      0x10            // Rare ASCII character

// Flags used by Memalloc() and Virtalloc(). Note that Virtalloc() alwyas
// initializes memory to zero.
#define REPORT         0x0000          // Report memory allocation errors
#define SILENT         0x0001          // Don't report allocation errors
#define ZEROINIT       0x0002          // Initialize memory to 0

#define CONT_BROADCAST 0x0000          // Continue sending msg to MDI windows
#define STOP_BROADCAST 0x1234          // Stop sending message to MDI windows

// Symbol decoding mode, used by Decodethreadname(), Decodeaddress() and
// Decoderelativeoffset().
// Bits that determine when to decode and comment name at all.
#define DM_VALID       0x00000001      // Only decode if memory exists
#define DM_INMOD       0x00000002      // Only decode if in module
#define DM_SAMEMOD     0x00000004      // Only decode if in same module
#define DM_SYMBOL      0x00000008      // Only decode if direct symbolic name
#define DM_NONTRIVIAL  0x00000010      // Only decode if nontrivial form
// Bits that control name format.
#define DM_BINARY      0x00000100      // Don't use symbolic form
#define DM_DIFBIN      0x00000200      // No symbolic form if different module
#define DM_WIDEFORM    0x00000400      // Extended form (8 digits by hex)
#define DM_CAPITAL     0x00000800      // First letter in uppercase if possible
#define DM_OFFSET      0x00001000      // Add 'OFFSET' if data
#define DM_JUMPIMP     0x00002000      // Check if points to JMP to import
#define DM_DYNAMIC     0x00004000      // Check if points to JMP to DLL
#define DM_ORDINAL     0x00008000      // Add ordinal to thread's name
// Bits that control whether address is preceded with module name.
#define DM_NOMODNAME   0x00000000      // Never add module name
#define DM_DIFFMODNAME 0x00010000      // Add name only if different module
#define DM_MODNAME     0x00020000      // Always add module name
// Bits that control comments.
#define DM_STRING      0x00100000      // Check if pointer to ASCII or UNICODE
#define DM_STRPTR      0x00200000      // Check if points to pointer to text
#define DM_FOLLOW      0x00400000      // Check if follows to different symbol
#define DM_ENTRY       0x00800000      // Check if unnamed entry to subroutine
#define DM_EFORCE      0x01000000      // Check if named entry, too
#define DM_DIFFMOD     0x02000000      // Check if points to different module
#define DM_RELOFFS     0x04000000      // Check if points inside subroutine
#define DM_ANALYSED    0x08000000      // Check if points to decoded data

// Standard commenting mode. Note: DM_DIFFMOD and DM_RELOFFS are not included.
#define DM_COMMENT     (DM_STRING|DM_STRPTR|DM_FOLLOW|DM_ENTRY|DM_ANALYSED)

// Address decoding mode, used by Labeladdress().
#define ADDR_SYMMASK   0x00000003      // Mask to extract sym presentation mode
#define   ADDR_HEXSYM  0x00000000      // Hex, followed by symbolic name
#define   ADDR_SYMHEX  0x00000001      // Symbolic name, followed by hex
#define   ADDR_SINGLE  0x00000002      // Symbolic name, or hex if none
#define   ADDR_HEXONLY 0x00000003      // Only hexadecimal address
#define ADDR_MODNAME   0x00000004      // Add module name to symbol
#define ADDR_FORCEMOD  0x00000008      // (ADDR_SINGLE) Always add module name
#define ADDR_GRAYHEX   0x00000010      // Gray hex
#define ADDR_HILSYM    0x00000020      // Highlight symbolic name
#define ADDR_NODEFMEP  0x00000100      // Do not show <ModuleEntryPoint>
#define ADDR_BREAK     0x00000200      // Mark as unconditional breakpoint
#define ADDR_CONDBRK   0x00000400      // Mark as conditional breakpoint
#define ADDR_DISBRK    0x00000800      // Mark as disabled breakpoint
#define ADDR_EIP       0x00001000      // Mark as actual EIP
#define ADDR_CHECKEIP  0x00002000      // Mark as EIP if EIP of CPU thread
#define ADDR_SHOWNULL  0x00004000      // Display address 0

// Mode bits and return value of Browsefilename().
#define BRO_MODEMASK   0xF0000000      // Mask to extract browsing mode
#define   BRO_FILE     0x00000000      // Get file name
#define   BRO_EXE      0x10000000      // Get name of executable
#define   BRO_TEXT     0x20000000      // Get name of text log
#define   BRO_GROUP    0x30000000      // Get one or several obj or lib files
#define   BRO_MULTI    0x40000000      // Get one or several files
#define BRO_SAVE       0x08000000      // Get name in save mode
#define BRO_SINGLE     0x00800000      // Single file selected
#define BRO_MULTIPLE   0x00400000      // Multiple files selected
#define BRO_APPEND     0x00080000      // Append to existing file
#define BRO_ACTUAL     0x00040000      // Add actual contents
#define BRO_TABS       0x00020000      // Separate columns with tabs
#define BRO_GROUPMASK  0x000000FF      // Mask to extract groups
#define   BRO_GROUP1   0x00000001      // Belongs to group 1
#define   BRO_GROUP2   0x00000002      // Belongs to group 2
#define   BRO_GROUP3   0x00000004      // Belongs to group 3
#define   BRO_GROUP4   0x00000008      // Belongs to group 4

// String decoding modes.
#define DS_DIR         0               // Direct quote
#define DS_ASM         1               // Assembler style
#define DS_C           2               // C style

varapi (void)    Error(wchar_t *format,...);
varapi (void)    Conderror(int *cond,wchar_t *title,wchar_t *format,...);
varapi (int)     Condyesno(int *cond,wchar_t *title,wchar_t *format,...);
stdapi (int)     Stringfromini(wchar_t *section,wchar_t *key,wchar_t *s,
                   int length);
stdapi (int)     Filefromini(wchar_t *key,wchar_t *name,wchar_t *defname);
varapi (int)     Getfromini(wchar_t *file,wchar_t *section,wchar_t *key,
                   wchar_t *format,...);
varapi (int)     Writetoini(wchar_t *file,wchar_t *section,wchar_t *key,
                   wchar_t *format,...);
stdapi (int)     Filetoini(wchar_t *key,wchar_t *name);
stdapi (void)    Deleteinisection(wchar_t *file,wchar_t *section);
stdapi (int)     Getfromsettings(wchar_t *key,int defvalue);
stdapi (void)    Addtosettings(wchar_t *key,int value);
stdapi (void)    Replacegraphs(int mode,wchar_t *s,uchar *mask,
                   int select,int n);
stdapi (int)     Unicodetoascii(const wchar_t *w,int nw,char *s,int ns);
stdapi (int)     Asciitounicode(const char *s,int ns,wchar_t *w,int nw);
stdapi (int)     Unicodetoutf(const wchar_t *w,int nw,char *t,int nt);
stdapi (int)     Utftounicode(const char *t,int nt,wchar_t *w,int nw);
stdapi (HGLOBAL) Unicodebuffertoascii(HGLOBAL hunicode);
stdapi (int)     Iszero(void *data,int n);
stdapi (int)     Guidtotext(uchar *guid,wchar_t *s);
varapi (int)     Swprintf(wchar_t *s,wchar_t *format,...);
stdapi (void *)  Memalloc(ulong size,int flags);
stdapi (void)    Memfree(void *data);
stdapi (void *)  Mempurge(void *data,int count,ulong itemsize,int *newcount);
stdapi (void *)  Memdouble(void *data,int *pcount,ulong itemsize,
                   int *failed,int flags);
stdapi (void *)  Virtalloc(ulong size,int flags);
stdapi (void)    Virtfree(void *data);
stdapi (int)     Broadcast(UINT msg,WPARAM wp,LPARAM lp);
stdapi (int)     Browsefilename(wchar_t *title,wchar_t *name,wchar_t *args,
                   wchar_t *currdir,wchar_t *defext,HWND hwnd,int mode);
stdapi (int)     Browsedirectory(HWND hw,wchar_t *comment,wchar_t *dir);
stdapi (void)    Relativizepath(wchar_t *path);
stdapi (void)    Absolutizepath(wchar_t *path);
stdapi (int)     Confirmoverwrite(wchar_t *path);
stdapi (int)     Labeladdress(wchar_t *text,ulong addr,ulong reladdr,int relreg,
                   int index,uchar *mask,int *select,ulong mode);
stdapi (int)     Simpleaddress(wchar_t *text,ulong addr,
                   uchar *mask,int *select);
stdapi (void)    Heapsort(void *data,const int count,const int size,
                   int (_USERENTRY *compare)(const void *,const void *));
stdapi (void)    Heapsortex(void *data,const int count,const int size,
                   int (_USERENTRY *compareex)(const void *,const void *,ulong),
                   ulong lp);
stdapi (uchar *) Readfile(wchar_t *path,ulong fixsize,ulong *psize);
stdapi (int)     Devicenametodosname(wchar_t *devname,wchar_t *dosname);
stdapi (int)     Filenamefromhandle(HANDLE hfile,wchar_t *path);
stdapi (void)    Quicktimerstart(int timer);
stdapi (void)    Quicktimerstop(int timer);
stdapi (void)    Quicktimerflush(int timer);


////////////////////////////////////////////////////////////////////////////////
////////////////// FAST SERVICE ROUTINES WRITTEN IN ASSEMBLER //////////////////

varapi (int)     StrcopyA(char *dest,int n,const char *src);
varapi (int)     StrcopyW(wchar_t *dest,int n,const wchar_t *src);
varapi (int)     StrlenA(const char *src,int n);
varapi (int)     StrlenW(const wchar_t *src,int n);
varapi (int)     HexprintA(char *s,ulong u);
varapi (int)     HexprintW(wchar_t *s,ulong u);
varapi (int)     Hexprint4A(char *s,ulong u);
varapi (int)     Hexprint4W(wchar_t *s,ulong u);
varapi (int)     Hexprint8A(char *s,ulong u);
varapi (int)     Hexprint8W(wchar_t *s,ulong u);
varapi (int)     SignedhexA(char *s,ulong u);
varapi (int)     SignedhexW(wchar_t *s,ulong u);
varapi (void)    Swapmem(void *base,int size,int i1,int i2);
varapi (int)     HexdumpA(char *s,uchar *code,int n);
varapi (int)     HexdumpW(wchar_t *s,uchar *code,int n);
varapi (int)     Bitcount(ulong u);

varapi (char *)  SetcaseA(char *s);
varapi (wchar_t *) SetcaseW(wchar_t *s);
varapi (int)     StrcopycaseA(char *dest,int n,const char *src);
varapi (int)     StrcopycaseW(wchar_t *dest,int n,const wchar_t *src);
varapi (int)     StrnstrA(char *data,int ndata,
                   char *pat,int npat,int ignorecase);
varapi (int)     StrnstrW(wchar_t *data,int ndata,
                   wchar_t *pat,int npat,int ignorecase);
varapi (int)     StrcmpW(const wchar_t *s1,const wchar_t *s2);
varapi (ulong)   Div64by32(ulong low,ulong hi,ulong div);
varapi (ulong)   CRCcalc(uchar *datacopy,ulong datasize);
varapi (int)     Getcpuidfeatures(void);
varapi (void)    Maskfpu(void);
varapi (void)    Clearfpu(void);


////////////////////////////////////////////////////////////////////////////////
////////////////////// DATA COMPRESSION AND DECOMPRESSION //////////////////////

stdapi (ulong)   Compress(uchar *bufin,ulong nbufin,
                   uchar *bufout,ulong nbufout);
stdapi (ulong)   Getoriginaldatasize(uchar *bufin,ulong nbufin);
stdapi (ulong)   Decompress(uchar *bufin,ulong nbufin,
                   uchar *bufout,ulong nbufout);


////////////////////////////////////////////////////////////////////////////////
/////////////////////// TAGGED DATA FILES AND RESOURCES ////////////////////////

#define MI_SIGNATURE   0x00646F4DL     // Signature of tagged file
#define MI_VERSION     0x7265560AL     // File version
#define MI_FILENAME    0x6C69460AL     // Record with full name of executable
#define MI_FILEINFO    0x7263460AL     // Length, date, CRC (t_fileinfo)
#define MI_DATA        0x7461440AL     // Name or data (t_nameinfo)
#define MI_CALLBRA     0x7262430AL     // Call brackets
#define MI_LOOPBRA     0x72624C0AL     // Loop brackets
#define MI_PROCDATA    0x6372500AL     // Procedure data (set of t_procdata)
#define MI_INT3BREAK   0x336E490AL     // INT3 breakpoint (t_bpoint)
#define MI_MEMBREAK    0x6D70420AL     // Memory breakpoint (t_bpmem)
#define MI_HWBREAK     0x6870420AL     // Hardware breakpoint (t_bphard)
#define MI_ANALYSIS    0x616E410AL     // Record with analysis data
#define MI_SWITCH      0x6977530AL     // Switch (addr+dt_switch)
#define MI_CASE        0x7361430AL     // Case (addr+dt_case)
#define MI_MNEMO       0x656E4D0AL     // Decoding of mnemonics (addr+dt_mnemo)
#define MI_JMPDATA     0x74644A0AL     // Jump data
#define MI_NETSTREAM   0x74734E0AL     // .NET streams (t_netstream)
#define MI_METADATA    0x74644D0AL     // .NET MetaData tables (t_metadata)
#define MI_BINSAV      0x7673420AL     // Last entered binary search patterns
#define MI_MODDATA     0x61624D0AL     // Module base, size and path
#define MI_PREDICT     0x6472500AL     // Predicted command execution results
#define MI_LASTSAV     0x61734C0AL     // Last entered strings (t_nameinfo)
#define MI_SAVEAREA    0x7661530AL     // Save area (t_savearea)
#define MI_RTCOND      0x6374520AL     // Run trace pause condition
#define MI_RTPROT      0x7074520AL     // Run trace protocol condition
#define MI_WATCH       0x6374570AL     // Watch in watch window
#define MI_LOADDLL     0x64644C0AL     // Packed loaddll.exe
#define MI_PATCH       0x7461500AL     // Patch data (compressed t_patch)
#define MI_PLUGIN      0x676C500AL     // Plugin prefix descriptor
#define MI_END         0x646E450AL     // End of tagged file

#ifdef FILE                            // Requires <stdio.h>

typedef struct t_fileinfo {            // Length, date, CRC (MI_FILEINFO)
  ulong          size;                 // Length of executable file
  FILETIME       filetime;             // Time of last modification
  ulong          crc;                  // CRC of executable file
  int            issfx;                // Whether self-extractable
  ulong          sfxentry;             // Offset of original entry after SFX
} t_fileinfo;

typedef struct t_tagfile {             // Descriptor of tagged file (reading)
  FILE           *f;                   // File descriptor
  ulong          filesize;             // File size
  ulong          offset;               // Actual offset
  ulong          tag;                  // Tag of next accessed record
  ulong          recsize;              // Size of next accessed record
} t_tagfile;

stdapi (FILE *)  Createtaggedfile(wchar_t *name,char *signature,ulong version);
stdapi (int)     Savetaggedrecord(FILE *f,ulong tag,ulong size,void *data);
stdapi (int)     Savepackedrecord(FILE *f,ulong tag,ulong size,void *data);
stdapi (void)    Finalizetaggedfile(FILE *f);
stdapi (int)     Opentaggedfile(t_tagfile *tf,wchar_t *name,char *signature);
stdapi (int)     Gettaggedrecordsize(t_tagfile *tf,ulong *tag,ulong *size);
stdapi (ulong)   Gettaggedfiledata(t_tagfile *tf,void *buf,ulong bufsize);
stdapi (void)    Closetaggedfile(t_tagfile *tf);

#endif

typedef struct t_nameinfo {            // Header of name/data record (MI_NAME)
  ulong          offs;                 // Offset in module
  uchar          type;                 // Name/data type, one of NM_xxx/DT_xxx
} t_nameinfo;

typedef struct t_uddsave {             // .udd file descriptor used by plugins
  void           *file;                // .udd file
  ulong          uddprefix;            // .udd tag prefix
} t_uddsave;

stdapi (int)     Pluginsaverecord(t_uddsave *psave,ulong tag,
                   ulong size,void *data);
stdapi (int)     Pluginpackedrecord(t_uddsave *psave,ulong tag,
                   ulong size,void *data);
stdapi (void)    Pluginmodulechanged(ulong addr);
stdapi (int)     Plugingetuniquedatatype(void);
stdapi (int)     Plugintempbreakpoint(ulong addr,ulong type,int forceint3);
stdapi (void)    Pluginshowoptions(struct t_control *options);


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// LEXICAL SCANNER ////////////////////////////////

#define SMODE_UPCASE   0x00000001      // Convert keywords to uppercase
#define SMODE_NOEOL    0x00000010      // Don't report SCAN_EOL, just skip it
#define SMODE_NOSPEC   0x00000020      // Don't translate specsymbols
#define SMODE_EXTKEY   0x00000040      // Allow &# and .!?%~ inside keywords
#define SMODE_NOUSKEY  0x00000080      // Underscore (_) is not part of keyword
#define SMODE_NODEC    0x00000100      // nn. is not decimal, but nn and '.'
#define SMODE_NOFLOAT  0x00000200      // nn.mm is not float, but nn, '.', mm
#define SMODE_RADIX10  0x00000400      // Default base is 10, not 16
#define SMODE_ANGLES   0x00000800      // Use angular brackets (<>) for text
#define SMODE_MASK     0x00001000      // Allow masked nibbles in SCAN_INT

#define SCAN_EOF       0               // End of data
#define SCAN_EOL       1               // End of line
#define SCAN_KEY       2               // Keyword in text
#define SCAN_TEXT      3               // Text string (without quotes) in text
#define SCAN_INT       4               // Integer in ival or uval
#define SCAN_FLOAT     5               // Floating-point number in fval
#define SCAN_OP        6               // Operator or punctuator in ival
#define SCAN_INVALID   7               // Invalid character in ival
#define SCAN_SYNTAX    8               // Syntactical error in errmsg
#define SCAN_USER      10              // Base for user-defined types

typedef struct t_scan {                // Scan descriptor
  // Fill these fields before the first scan. Set line to 1 for 1-based numbers.
  ulong          mode;                 // Scanning mode, set of SMODE_xxx
  wchar_t        *src;                 // Pointer to UNICODE source data
  ulong          length;               // Length of source data, characters
  ulong          caret;                // Next processed symbol, characters
  int            line;                 // Number of encountered EOLs
  // Call to Scan() fills some of these fields with scan data.
  union {
    int          ival;                 // Scanned item as integer number
    ulong        uval;                 // Scanned item as unsigned number
  };
  ulong          mask;                 // Binary mask for uval, SCAN_INT only
  long double    fval;                 // Scanned item as floating number
  wchar_t        text[TEXTLEN];        // Scanned item as a text string
  int            ntext;                // Length of text, characters
  wchar_t        errmsg[TEXTLEN];      // Error message
  int            type;                 // Type of last scanned item, SCAN_xxx
} t_scan;

stdapi (int)     Skipspaces(t_scan *ps);
stdapi (void)    Scan(t_scan *ps);
stdapi (int)     Optostring(wchar_t *s,int op);


////////////////////////////////////////////////////////////////////////////////
///////////////////////// SHORTCUTS, MENUS AND TOOLBAR /////////////////////////

// Input modes of menu functions.
#define MENU_VERIFY    0               // Check if menu item applies
#define MENU_EXECUTE   1               // Execute menu item
// Values returned by menu functions on MENU_VERIFY.
#define MENU_ABSENT    0               // Item doesn't appear in menu
#define MENU_NORMAL    1               // Ordinary menu item
#define MENU_CHECKED   2               // Checked menu item
#define MENU_CHKPARENT 3               // Checked menu item + checked parent
#define MENU_GRAYED    4               // Inactive menu item
#define MENU_SHORTCUT  5               // Shortcut only, not in menu
// Values returned by menu functions on MENU_EXECUTE.
#define MENU_NOREDRAW  0               // Do not redraw owning window
#define MENU_REDRAW    1               // Redraw owning window

// Shortcut descriptions.
#define KK_KEYMASK     0x0000FFFF      // Mask to extract key
#define KK_CHAR        0x00010000      // Process as WM_CHAR
#define KK_SHIFT       0x00020000      // Shortcut includes Shift key
#define KK_CTRL        0x00040000      // Shortcut includes Ctrl key
#define KK_ALT         0x00080000      // Shortcut includes Alt key
#define KK_WIN         0x00100000      // Shortcut includes WIN key
#define KK_NOSH        0x00200000      // Shortcut ignores Shift in main menu
#define KK_UNUSED      0x7FC00000      // Unused shortcut data bits
#define KK_DIRECT      0x80000000      // Direct shortcut in menu

// Global shortcuts. They may be re-used by plugins.
#define K_NONE         0               // No shortcut
// Global shortcuts: File functions.
#define K_OPENNEW      100             // Open new executable to debug
#define K_SETARGS      101             // Set command line args for next run
#define K_ATTACH       102             // Attach to the running process
#define K_DETACH       103             // Detach from the debugged process
#define K_EXIT         104             // Close OllyDbg
// Global shortcuts: View functions.
#define K_LOGWINDOW    110             // Open Log window
#define K_MODULES      111             // Open Executable modules window
#define K_MEMORY       112             // Open Memory map window
#define K_WINDOWS      113             // Open list of windows
#define K_THREADS      114             // Open Threads window
#define K_CPU          115             // Open CPU window
#define K_WATCHES      116             // Open Watches window
#define K_SEARCHES     117             // Open Search results window
#define K_RTRACE       118             // Open Run trace window
#define K_PATCHES      119             // Open Patches window
#define K_BPOINTS      120             // Open INT3 breakpoints window
#define K_BPMEM        121             // Open Memory breakpoints window
#define K_BPHARD       122             // Open Hardware breakpoints window
#define K_SOURCES      123             // Open list of source files
#define K_FILE         124             // Open file
// Global shortcuts: Debug functions.
#define K_RUN          130             // Run debugged application
#define K_RUNTHREAD    131             // Run only actual thread
#define K_PAUSE        132             // Pause debugged application
#define K_STEPIN       133             // Step into
#define K_STEPOVER     134             // Step over
#define K_TILLRET      135             // Execute till return
#define K_TILLUSER     136             // Execute till user code
#define K_CALLDLL      137             // Call DLL export
#define K_RESTART      138             // Restart last debugged executable
#define K_CLOSE        139             // Close debuggee
#define K_AFFINITY     140             // Set affinity
// Global shortcuts: Trace functions.
#define K_OPENTRACE    150             // Open Run trace
#define K_CLOSETRACE   151             // Close Run trace
#define K_ANIMIN       152             // Animate into
#define K_ANIMOVER     153             // Animate over
#define K_TRACEIN      154             // Trace into
#define K_TRACEOVER    155             // Trace over
#define K_RUNHIT       156             // Run hit trace
#define K_STOPHIT      157             // Stop hit trace
#define K_RTCOND       158             // Set run trace break condition
#define K_RTLOG        159             // Set run trace log condition
// Global shortcuts: Options.
#define K_OPTIONS      170             // Open Options dialog
#define K_PLUGOPTIONS  171             // Open Plugin options dialog
#define K_SHORTCUTS    172             // Open Shortcut editor
// Global shortcuts: Windows functions.
#define K_TOPMOST      180             // Toggle topmost status of main window
#define K_CASCADE      181             // Cascade MDI windows
#define K_TILEHOR      182             // Tile MDI windows horizontally
#define K_TILEVER      183             // Tile MDI windows vertically
#define K_ICONS        184             // Arrange icons
#define K_CLOSEMDI     185             // Close all MDI windows
#define K_RESTORE      186             // Maximize or restore active MDI window
#define K_PREVMDI      187             // Go to previous MDI window
#define K_NEXTMDI      188             // Go to next MDI window
// Global shortcuts: Help functions.
#define K_ABOUT        190             // Open About dialog
// Generic table shortcuts.
#define K_PREVFRAME    200             // Go to previous frame in table
#define K_NEXTFRAME    201             // Go to next frame in table
#define K_UPDATE       202             // Update table
#define K_COPY         203             // Copy to clipboard
#define K_COPYALL      204             // Copy whole table to clipboard
#define K_CUT          205             // Cut to clipboard
#define K_PASTE        206             // Paste
#define K_TOPMOSTMDI   207             // Make MDI window topmost
#define K_AUTOUPDATE   208             // Periodically update contents of window
#define K_SHOWBAR      209             // Show/hide bar
#define K_HSCROLL      210             // Show/hide horizontal scroll
#define K_DEFCOLUMNS   211             // Resize all columns to default width
// Shortcuts used by different windows.
#define K_SEARCHAGAIN  220             // Repeat last search
#define K_SEARCHREV    221             // Repeat search in inverse direction
// Dump: Data backup.
#define K_BACKUP       240             // Create or update backup
#define K_SHOWBKUP     241             // Toggle backup display
// Dump: Edit.
#define K_UNDO         250             // Undo selection
#define K_COPYADDR     251             // Copy address
#define K_COPYHEX      252             // Copy data in hexadecimal format
#define K_PASTEHEX     253             // Paste data in hexadecimal format
#define K_EDITITEM     254             // Edit first selected item
#define K_EDIT         255             // Edit selection
#define K_FILLZERO     256             // Fill selection with zeros
#define K_FILLNOP      257             // Fill selection with NOPs
#define K_FILLFF       258             // Fill selection with FF code
#define K_SELECTALL    259             // Select all
#define K_SELECTPROC   260             // Select procedure or structure
#define K_COPYTOEXE    261             // Copy selection to executable file
#define K_ZERODUMP     262             // Zero whole dump
#define K_LABEL        263             // Add custom label
#define K_ASSEMBLE     264             // Assemble
#define K_COMMENT      265             // Add custom comment
#define K_SAVEFILE     266             // Save file
// Dump: Breakpoints.
#define K_BREAK        280             // Toggle simple INT3 breakpoint
#define K_CONDBREAK    281             // Set or edit cond INT3 breakpoint
#define K_LOGBREAK     282             // Set or edit logging INT3 breakpoint
#define K_RUNTOSEL     283             // Run to selection
#define K_ENABLEBRK    284             // Enable or disable INT3 breakpoint
#define K_MEMBREAK     285             // Set or edit memory breakpoint
#define K_MEMLOGBREAK  286             // Set or edit memory log breakpoint
#define K_MEMENABLE    287             // Enable or disable memory breakpoint
#define K_MEMDEL       288             // Delete memory breakpoint
#define K_HWBREAK      289             // Set or edit hardware breakpoint
#define K_HWLOGBREAK   290             // Set or edit hardware log breakpoint
#define K_HWENABLE     291             // Enable or disable hardware breakpoint
#define K_HWDEL        292             // Delete hardware breakpoint
// Dump: Jumps to location.
#define K_NEWORIGIN    300             // Set new origin
#define K_FOLLOWDASM   301             // Follow address in Disassembler
#define K_ORIGIN       302             // Go to origin
#define K_GOTO         303             // Go to expression
#define K_JMPTOSEL     304             // Follow jump or call to selection
#define K_SWITCHCASE   305             // Go to switch case
#define K_PREVHIST     306             // Go to previous history location
#define K_NEXTHIST     307             // Go to next history location
#define K_PREVTRACE    308             // Go to previous run trace record
#define K_NEXTTRACE    309             // Go to next run trace record
#define K_PREVPROC     310             // Go to previous procedure
#define K_NEXTPROC     311             // Go to next procedure
#define K_PREVREF      312             // Go to previous found item
#define K_NEXTREF      313             // Go to next found item
#define K_FOLLOWEXE    314             // Follow selection in executable file
// Dump: Structures.
#define K_DECODESTR    330             // Decode as structure
#define K_DECODESPTR   331             // Decode as pointer to structure
// Dump: Search.
#define K_NAMES        380             // Show list of names
#define K_FINDCMD      381             // Find command
#define K_FINDCMDSEQ   382             // Find sequence of commands
#define K_FINDCONST    383             // Find constant
#define K_FINDBIN      384             // Find binary string
#define K_FINDMOD      385             // Find modification
#define K_ALLCALLS     386             // Search for all intermodular calls
#define K_ALLCMDS      387             // Search for all commands
#define K_ALLCMDSEQ    388             // Search for all command sequences
#define K_ALLCONST     389             // Search for all constants
#define K_ALLMODS      390             // Search for all modifications
#define K_ALLSTRS      391             // Search for all referenced strings
#define K_ALLGUIDS     392             // Search for all referenced GUIDs
#define K_ALLCOMMENTS  393             // Search for all user-defined comments
#define K_ALLSWITCHES  394             // Search for all switches
#define K_ALLFLOATS    395             // Search for all floating constants
#define K_LASTRTREC    396             // Find last record in run trace
// Dump: References.
#define K_REFERENCES   410             // Find all references
// Dump: Addressing.
#define K_ABSADDR      420             // Show absolute addresses
#define K_RELADDR      421             // Show offsets from current selection
#define K_BASEADDR     422             // Show offsets relative to module base
// Dump: Comments.
#define K_COMMSRC      430             // Toggle between comments and source
#define K_SHOWPROF     431             // Show or hide run trace profile
// Dump: Analysis.
#define K_ANALYSE      440             // Analyse module
#define K_REMANAL      441             // Remove analysis from selection
#define K_REMANMOD     442             // Remove analysis from the module
// Dump: Help.
#define K_HELPCMD      450             // Help on command
#define K_HELPAPI      451             // Help on Windows API function
// Dump: Data presentation.
#define K_DUMPHA16     460             // Dump as 16 hex bytes and ASCII text
#define K_DUMPHA8      461             // Dump as 8 hex bytes and ASCII text
#define K_DUMPHU16     462             // Dump as 16 hex bytes and UNICODE text
#define K_DUMPHU8      463             // Dump as 8 hex bytes and UNICODE text
#define K_DUMPA64      464             // Dump as 64 ASCII characters
#define K_DUMPA32      465             // Dump as 32 ASCII characters
#define K_DUMPU64      466             // Dump as 64 UNICODE characters
#define K_DUMPU32      467             // Dump as 32 UNICODE characters
#define K_DUMPU16      468             // Dump as 16 UNICODE characters
#define K_DUMPISHORT   469             // Dump as 16-bit signed numbers
#define K_DUMPUSHORT   470             // Dump as 16-bit unsigned numbers
#define K_DUMPXSHORT   471             // Dump as 16-bit hexadecimal numbers
#define K_DUMPILONG    472             // Dump as 32-bit signed numbers
#define K_DUMPULONG    473             // Dump as 32-bit unsigned numbers
#define K_DUMPXLONG    474             // Dump as 32-bit hexadecimal numbers
#define K_DUMPADR      475             // Dump as address with comments
#define K_DUMPADRA     476             // Dump as address with ASCII & comments
#define K_DUMPADRU     477             // Dump as address with UNICODE & comms
#define K_DUMPF32      478             // Dump as 32-bit floats
#define K_DUMPF64      479             // Dump as 64-bit floats
#define K_DUMPF80      480             // Dump as 80-bit floats
#define K_DUMPDA       481             // Dump as disassembly
#define K_DUMPSTRUCT   482             // Dump as known structure
// Stack-specific shortcuts.
#define K_LOCKSTK      490             // Toggle stack lock
#define K_PUSH         491             // Push doubleword
#define K_POP          492             // Pop doubleword
#define K_STACKINDASM  493             // Follow stack doubleword in CPU
#define K_GOTOESP      494             // Go to ESP
#define K_GOTOEBP      495             // Go to EBP
#define K_ESPADDR      496             // Show offsets relative to ESP
#define K_EBPADDR      497             // Show offsets relative to EBP
// Shortcuts of Register pane.
#define K_INCREMENT    500             // Increment register
#define K_DECREMENT    501             // Decrement register
#define K_ZERO         502             // Zero selected register
#define K_SET1         503             // Set register to 1
#define K_MODIFY       504             // Modify contents of register
#define K_UNDOREG      505
#define K_PUSHFPU      506             // Push FPU stack
#define K_POPFPU       507             // Pop FPU stack
#define K_REGINDASM    508             // Follow register in CPU Disassembler
#define K_REGINDUMP    509             // Follow register in CPU Dump
#define K_REGINSTACK   510             // Follow register in CPU Stack
#define K_VIEWFPU      511             // View FPU registers
#define K_VIEWMMX      512             // View MMX registers
#define K_VIEW3DNOW    513             // View 3DNow! registers
#define K_HELPREG      514             // Help on register
// Shortcuts of Information pane.
#define K_EDITOP       520             // Edit contents of operand in info pane
#define K_INFOINDASM   521             // Follow information in CPU Disassembler
#define K_INFOINDUMP   522             // Follow information in CPU Dump
#define K_INFOINSTACK  523             // Follow information in CPU Stack
#define K_LISTJUMPS    524             // List jumps and calls to command
#define K_LISTCASES    525             // List switch cases
#define K_INFOSRC      526             // Follow address in Source code
// Log window.
#define K_LOGINDASM    530             // Follow log address in CPU Disassembler
#define K_LOGINDUMP    531             // Follow log address in CPU Dump
#define K_LOGINSTACK   532             // Follow log address in CPU Stack
#define K_LOGCLEAR     533             // Clear log
#define K_LOGTOFILE    534             // Start logging to file
#define K_STOPLOG      535             // Stop logging to file
// Executable modules.
#define K_MODINDASM    540             // Follow module entry point in CPU
#define K_MODDATA      541             // View module data section in CPU Dump
#define K_MODEXE       542             // Open executable in standalone Dump
#define K_MODNAMES     543             // Show names declared in the module
#define K_GLOBNAMES    544             // Show global list of names
#define K_MODCALLS     545             // Find intermodular calls in module
#define K_MODANALYSE   546             // Analyse selected module
#define K_SAVEUDD      547             // Save module data to .udd file
#define K_LOADUDD      548             // Load module data from .udd file
// Memory map.
#define K_MEMBACKUP    550             // Create backup of memory block
#define K_MEMINDASM    551             // Open memory block in CPU Disassembler
#define K_MEMINDUMP    552             // Open memory block in CPU Dump
#define K_DUMP         553             // Dump memory block in separate window
#define K_SEARCHMEM    554             // Search memory block for binary string
#define K_MEMBPACCESS  555             // Toggle break on access
// List of windows.
#define K_WININDASM    560             // Follow WinProc in CPU Disassembler
#define K_CLSINDASM    561             // Follow ClassProc in CPU Disassembler
// Threads.
#define K_THRINCPU     570             // Open thread in CPU window
#define K_THRTIB       571             // Dump Thread Information Block
#define K_REGISTERS    572             // Open Registers window
#define K_THRSUSPEND   573             // Suspend selected thread
#define K_THRRESUME    574             // Resume selected thread
#define K_THRKILL      575             // Kill selected thread
// Watches.
#define K_ADDWATCH     580             // Add watch
#define K_EDITWATCH    581             // Edit existing watch
#define K_DELWATCH     582             // Delete watch
#define K_WATCHUP      583             // Move watch up
#define K_WATCHDN      584             // Move watch down
#define K_EDITCONT     585             // Edit contents of register or memory
#define K_WATCHINDASM  586             // Follow watch value in CPU Disassembler
#define K_WATCHINDUMP  587             // Follow watch value in CPU Dump
#define K_WATCHINSTACK 588             // Follow watch value in CPU Stack
// Search results.
#define K_SEARCHINDASM 600             // Follow address of found item in CPU
#define K_PREVSEARCH   601             // Follow previous found item in Disasm
#define K_NEXTSEARCH   602             // Follow next found item in Disasm
#define K_FINDTEXT     603             // Find text substring in search results
#define K_BREAKALL     604             // Set breakpoint on all found commands
#define K_CONDBPALL    605             // Set conditional bp on all commands
#define K_LOGBPALL     606             // Set logging bp on all commands
#define K_DELBPALL     607             // Remove breakpoints from all commands
#define K_BREAKCALLS   608             // Set break on calls to function
#define K_CONDBPCALLS  609             // Set cond break on calls to function
#define K_LOGBPCALLS   610             // Set logging break on calls to function
#define K_DELBPCALLS   611             // Remove breakpoints from calls
// Run trace.
#define K_RTPREV       620             // Show previous run trace in Disasm
#define K_RTNEXT       621             // Show next run trace in Disasm
#define K_TRACEINDASM  622             // Follow traced command in CPU
#define K_CLRTRACE     623             // Clear run trace
#define K_REGMODE      624             // Toggle register display mode
#define K_MARKTRACE    625             // Mark address in run trace
#define K_FINDTRADDR   626             // Enter address to mark in run trace
#define K_PREVMARK     627             // Find previous marked address
#define K_NEXTMARK     628             // Find next marked address
#define K_CLEARMARK    629             // Clear address marks in run trace
#define K_PROFILE      630             // Profile selected module
#define K_GLOBPROFILE  631             // Profile whole memory
#define K_SAVETRACE    632             // Save run trace data to the file
#define K_STOPSAVETR   633             // Close run trace log file
// Profile.
#define K_PROFINDASM   640             // Follow profiled command in CPU
#define K_PREVPROF     641             // Follow previous profile item in Disasm
#define K_NEXTPROF     642             // Follow next profile item in Disasm
#define K_PROFMARK     643             // Mark profile address in run trace
// Patches.
#define K_PATCHINDASM  650             // Follow patch in CPU Disassembler
#define K_PREVPATCH    651             // Go to previous patch
#define K_NEXTPATCH    652             // Go to next patch
#define K_APPLYPATCH   653             // Apply patch
#define K_RESTOREPT    654             // Restore original code
#define K_DELPATCH     655             // Delete patch record
// Breakpoint lists.
#define K_DELETEBP     660             // Delete breakpoint
#define K_ENABLEBP     661             // Enable or disable breakpoint
#define K_BPINDASM     662             // Follow breakpoint in CPU Disassembler
#define K_BPINDUMP     663             // Follow breakpoint in CPU Dump
#define K_DISABLEALLBP 664             // Disable all breakpoints
#define K_ENABLEALLBP  665             // Enable all breakpoints
// Source.
#define K_SOURCEINDASM 670             // Follow source line in CPU Disassembler
// List of source files.
#define K_VIEWSRC      680             // View source file
// Names.
#define K_FOLLOWIMP    690             // Follow import in CPU Disassembler
#define K_NAMEINDASM   691             // Follow label in CPU Disassembler
#define K_NAMEINDUMP   692             // Follow label in CPU Dump
#define K_NAMEREFS     693             // Find references to name
#define K_NAMEHELPAPI  694             // Help on selected API function
// Special non-changeable shortcuts.
#define K_0            1008            // Digit 0
#define K_1            1009            // Digit 1
#define K_2            1010            // Digit 2
#define K_3            1011            // Digit 3
#define K_4            1012            // Digit 4
#define K_5            1013            // Digit 5
#define K_6            1014            // Digit 6
#define K_7            1015            // Digit 7
#define K_8            1016            // Digit 8
#define K_9            1017            // Digit 9
#define K_A            1018            // Hex digit A
#define K_B            1019            // Hex digit B
#define K_C            1020            // Hex digit C
#define K_D            1021            // Hex digit D
#define K_E            1022            // Hex digit E
#define K_F            1023            // Hex digit F

// Native OllyDbg tables that support embedded plugin menus:
#define PWM_ATTACH     L"ATTACH"       // List of processes in Attach window
#define PWM_BPHARD     L"BPHARD"       // Hardware breakpoints
#define PWM_BPMEM      L"BPMEM"        // Memory breakpoints
#define PWM_BPOINT     L"BPOINT"       // INT3 breakpoints
#define PWM_DISASM     L"DISASM"       // CPU Disassembler pane
#define PWM_DUMP       L"DUMP"         // All dumps except CPU disasm & stack
#define PWM_INFO       L"INFO"         // CPU Info pane
#define PWM_LOG        L"LOG"          // Log window
#define PWM_MAIN       L"MAIN"         // Main OllyDbg menu
#define PWM_MEMORY     L"MEMORY"       // Memory window
#define PWM_MODULES    L"MODULES"      // Modules window
#define PWM_NAMELIST   L"NAMELIST"     // List of names (labels)
#define PWM_PATCHES    L"PATCHES"      // List of patches
#define PWM_PROFILE    L"PROFILE"      // Profile window
#define PWM_REGISTERS  L"REGISTERS"    // Registers, including CPU
#define PWM_SEARCH     L"SEARCH"       // Search tabs
#define PWM_SOURCE     L"SOURCE"       // Source code window
#define PWM_SRCLIST    L"SRCLIST"      // List of source files
#define PWM_STACK      L"STACK"        // CPU Stack pane
#define PWM_THREADS    L"THREADS"      // Threads window
#define PWM_TRACE      L"TRACE"        // Run trace window
#define PWM_WATCH      L"WATCH"        // Watches
#define PWM_WINDOWS    L"WINDOWS"      // List of windows

typedef int  MENUFUNC(struct t_table *,wchar_t *,ulong,int);

typedef struct t_menu {                // Menu descriptor
  wchar_t        *name;                // Menu command
  wchar_t        *help;                // Explanation of command
  int            shortcutid;           // Shortcut identifier, K_xxx
  MENUFUNC       *menufunc;            // Function that executes menu command
  struct t_menu  *submenu;             // Pointer to descriptor of popup menu
  union {
    ulong        index;                // Argument passed to menu function
    HMENU        hsubmenu;             // Handle of pulldown menu
  };
} t_menu;

stdapi (int)     Callmenufunction(struct t_table *pt,t_menu *pm,
                   MENUFUNC *menufunc,ulong index);


////////////////////////////////////////////////////////////////////////////////
///////////////////////////// MAIN OLLYDBG WINDOW //////////////////////////////

typedef enum t_status {                // Thread/process status
  STAT_IDLE,                           // No process to debug
  STAT_LOADING,                        // Loading new process
  STAT_ATTACHING,                      // Attaching to the running process
  STAT_RUNNING,                        // All threads are running
  STAT_RUNTHR,                         // Single thread is running
  STAT_STEPIN,                         // Stepping into, single thread
  STAT_STEPOVER,                       // Stepping over, single thread
  STAT_ANIMIN,                         // Animating into, single thread
  STAT_ANIMOVER,                       // Animating over, single thread
  STAT_TRACEIN,                        // Tracing into, single thread
  STAT_TRACEOVER,                      // Tracing over, single thread
  STAT_SFXRUN,                         // SFX using run trace, single thread
  STAT_SFXHIT,                         // SFX using hit trace, single thread
  STAT_SFXKNOWN,                       // SFX to known entry, single thread
  STAT_TILLRET,                        // Stepping until return, single thread
  STAT_OVERRET,                        // Stepping over return, single thread
  STAT_TILLUSER,                       // Stepping till user code, single thread
  STAT_PAUSING,                        // Process is requested to pause
  STAT_PAUSED,                         // Process paused on debugging event
  STAT_FINISHED,                       // Process is terminated but in memory
  STAT_CLOSING                         // Process is requested to close/detach
} t_status;

varapi (void)    Info(wchar_t *format,...);
varapi (void)    Message(ulong addr,wchar_t *format,...);
varapi (void)    Tempinfo(wchar_t *format,...);
varapi (void)    Flash(wchar_t *format,...);
varapi (void)    Progress(int promille,wchar_t *format,...);
stdapi (void)    Moveprogress(int promille);
stdapi (void)    Setstatus(t_status newstatus);


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// DATA FUNCTIONS ////////////////////////////////

// Name and data types. Do not change order, it's important! Always keep values
// of demangled names 1 higher than originals, and NM_ALIAS higher than
// NM_EXPORT - name search routines rely on these facts!
#define NM_NONAME      0x00            // Means that name is absent
#define DT_NONE        0x00            // Ditto
#define NM_LABEL       0x21            // User-defined label
#define NM_EXPORT      0x22            // Exported name
#define NM_DEEXP       (NM_EXPORT+1)   // Demangled exported name
#define DT_EORD        (NM_EXPORT+2)   // Exported ordinal (ulong)
#define NM_ALIAS       (NM_EXPORT+3)   // Alias of NM_EXPORT
#define NM_IMPORT      0x26            // Imported name (module.function)
#define NM_DEIMP       (NM_IMPORT+1)   // Demangled imported name
#define DT_IORD        (NM_IMPORT+2)   // Imported ordinal (struct dt_iord)
#define NM_DEBUG       0x29            // Name from debug data
#define NM_DEDEBUG     (NM_DEBUG+1)    // Demangled name from debug data
#define NM_ANLABEL     0x2B            // Name added by Analyser
#define NM_COMMENT     0x30            // User-defined comment
#define NM_ANALYSE     0x31            // Comment added by Analyser
#define NM_MARK        0x32            // Important parameter
#define NM_CALLED      0x33            // Name of called function
#define DT_ARG         0x34            // Name and type of argument or data
#define DT_NARG        0x35            // Guessed number of arguments at CALL
#define NM_RETTYPE     0x36            // Type of data returned in EAX
#define NM_MODCOMM     0x37            // Automatical module comments
#define NM_TRICK       0x38            // Parentheses of tricky sequences
#define DT_SWITCH      0x40            // Switch descriptor (struct dt_switch)
#define DT_CASE        0x41            // Case descriptor (struct dt_case)
#define DT_MNEMO       0x42            // Alternative mnemonics data (dt_mnemo)
#define NM_DLLPARMS    0x44            // Parameters of Call DLL dialog
#define DT_DLLDATA     0x45            // Parameters of Call DLL dialog

#define DT_DBGPROC     0x4A            // t_function from debug, don't save!

#define NM_INT3BASE    0x51            // Base for INT3 breakpoint names
#define   NM_INT3COND  (NM_INT3BASE+0) // INT3 breakpoint condition
#define   NM_INT3EXPR  (NM_INT3BASE+1) // Expression to log at INT3 breakpoint
#define   NM_INT3TYPE  (NM_INT3BASE+2) // Type used to decode expression
#define NM_MEMBASE     0x54            // Base for memory breakpoint names
#define   NM_MEMCOND   (NM_MEMBASE+0)  // Memory breakpoint condition
#define   NM_MEMEXPR   (NM_MEMBASE+1)  // Expression to log at memory break
#define   NM_MEMTYPE   (NM_MEMBASE+2)  // Type used to decode expression
#define NM_HARDBASE    0x57            // Base for hardware breakpoint names
#define   NM_HARDCOND  (NM_HARDBASE+0) // Hardware breakpoint condition
#define   NM_HARDEXPR  (NM_HARDBASE+1) // Expression to log at hardware break
#define   NM_HARDTYPE  (NM_HARDBASE+2) // Type used to decode expression

#define NM_LABELSAV    0x60            // NSTRINGS last user-defined labels
#define NM_ASMSAV      0x61            // NSTRINGS last assembled commands
#define NM_ASRCHSAV    0x62            // NSTRINGS last assemby searches
#define NM_COMMSAV     0x63            // NSTRINGS last user-defined comments
#define NM_WATCHSAV    0x64            // NSTRINGS last watch expressions
#define NM_GOTOSAV     0x65            // NSTRINGS last GOTO expressions
#define DT_BINSAV      0x66            // NSTRINGS last binary search patterns
#define NM_CONSTSAV    0x67            // NSTRINGS last constants to search
#define NM_STRSAV      0x68            // NSTRINGS last strings to search
#define NM_ARGSAV      0x69            // NSTRINGS last arguments (ARGLEN!)
#define NM_CURRSAV     0x6A            // NSTRINGS last current dirs (MAXPATH!)

#define NM_SEQSAV      0x6F            // NSTRINGS last sequences (DATALEN!)

#define NM_RTCOND1     0x70            // First run trace pause condition
#define NM_RTCOND2     0x71            // Second run trace pause condition
#define NM_RTCOND3     0x72            // Third run trace pause condition
#define NM_RTCOND4     0x73            // Fourth run trace pause condition
#define NM_RTCMD1      0x74            // First run trace match command
#define NM_RTCMD2      0x75            // Second run trace match command
#define NM_RANGE0      0x76            // Low range limit
#define NM_RANGE1      0x77            // High range limit

#define DT_ANYDATA     0xFF            // Special marker, not a real data

#define NMOFS_COND     0               // Offset to breakpoint condition
#define NMOFS_EXPR     1               // Offset to breakpoint log expression
#define NMOFS_TYPE     2               // Offset to expression decoding type

typedef struct dt_iord {               // Descriptor of DT_IORD data
  ulong          ord;                  // Ordinal
  wchar_t        modname[SHORTNAME];   // Short name of the module
} dt_iord;

#define NSWEXIT        256             // Max no. of switch exits, incl. default
#define NSWCASE        128             // Max no. of cases in exit

// Types of switches and switch exits.
#define CASE_CASCADED  0x00000001      // Cascaded IF
#define CASE_HUGE      0x00000002      // Huge switch, some cases are lost
#define CASE_DEFAULT   0x00000004      // Has default (is default for dt_case)
#define CASE_TYPEMASK  0x00000070      // Mask to extract case type
#define   CASE_ASCII   0x00000010      // Intreprete cases as ASCII characters
#define   CASE_MSG     0x00000020      // Interprete cases as WM_xxx
#define   CASE_EXCPTN  0x00000040      // Interprete cases as exception codes
#define CASE_SIGNED    0x00000080      // Interprete cases as signed

typedef struct dt_switch {             // Switch descriptor DT_SWITCH
  ulong          casemin;              // Minimal case
  ulong          casemax;              // Maximal case
  ulong          type;                 // Switch type, set of CASE_xxx
  int            nexit;                // Number of exits including default
  ulong          exitaddr[NSWEXIT];    // List of exits (point to dt_case)
} dt_switch;

typedef struct dt_case {               // Switch exit descriptor DT_CASE
  ulong          swbase;               // Address of a switch descriptor
  ulong          type;                 // Switch type, set of CASE_xxx
  int            ncase;                // Number of cases (1..64, 0: default)
  ulong          value[NSWCASE];       // List of cases for exit
} dt_case;

// Flags indicating alternative forms of assembler mnemonics.
#define MF_JZ          0x01            // JZ, JNZ instead of JE, JNE
#define MF_JC          0x02            // JC, JNC instead of JAE, JB

typedef struct dt_mnemo {              // Mnemonics decoding DT_MNEMO
  uchar          flags;                // Set of MF_xxx
} dt_mnemo;

stdapi (int)     Insertdata(ulong addr,int type,void *data,ulong datasize);
stdapi (ulong)   Finddata(ulong addr,int type,void *data,ulong datasize);
stdapi (void *)  Finddataptr(ulong addr,int type,ulong *datasize);
stdapi (void)    Startnextdata(ulong addr0,ulong addr1,int type);
stdapi (ulong)   Findnextdata(ulong *addr,void *data,ulong datasize);
stdapi (void)    Startnextdatalist(ulong addr0,ulong addr1,int *list,int n);
stdapi (int)     Findnextdatalist(ulong *addr,int *type,
                   void *data,ulong datasize);
stdapi (int)     Isdataavailable(ulong addr,int type1,int type2,int type3);
stdapi (int)     Isdatainrange(ulong addr0,ulong addr1,
                   int type1,int type2,int type3);
stdapi (void)    Deletedatarange(ulong addr0,ulong addr1,
                   int type1,int type2,int type3);
stdapi (void)    Deletedatarangelist(ulong addr0,ulong addr1,int *list,int n);
stdapi (int)     Quickinsertdata(ulong addr,int type,
                   void *data,ulong datasize);
stdapi (void)    Mergequickdata(void);
stdapi (int)     DemanglenameW(wchar_t *name,wchar_t *undecorated,int recurs);
stdapi (int)     InsertnameW(ulong addr,int type,wchar_t *s);
stdapi (int)     QuickinsertnameW(ulong addr,int type,wchar_t *s);
stdapi (int)     FindnameW(ulong addr,int type,wchar_t *name,int nname);
stdapi (int)     FindnextnameW(ulong *addr,wchar_t *name,int nname);
stdapi (void)    Startnextnamelist(ulong addr0,ulong addr1,int *list,int n);
stdapi (int)     FindnextnamelistW(ulong *addr,int *type,
                   wchar_t *name,int nname);
stdapi (int)     Findlabel(ulong addr,wchar_t *name,int firsttype);
stdapi (int)     FindaddressW(wchar_t *name,struct t_module *pmod,
                   ulong *addr,wchar_t *errtxt);


////////////////////////////////////////////////////////////////////////////////
///////////////////////////// SIMPLE DATA FUNCTIONS ////////////////////////////

typedef struct t_simple {              // Simple data container
  uchar          *heap;                // Data heap
  ulong          itemsize;             // Size of data element, bytes
  int            maxitem;              // Size of allocated data heap, items
  int            nitem;                // Actual number of data items
  int            sorted;               // Whether data is sorted
} t_simple;

stdapi (void)    Destroysimpledata(t_simple *pdat);
stdapi (int)     Createsimpledata(t_simple *pdat,ulong itemsize);
stdapi (int)     Addsimpledata(t_simple *pdat,void *data);
stdapi (void)    Sortsimpledata(t_simple *pdat);
stdapi (void *)  Findsimpledata(t_simple *pdat,ulong addr);
stdapi (int)     Getsimpledataindexbyaddr(t_simple *pdat,ulong addr);
stdapi (void *)  Getsimpledatabyindex(t_simple *pdat,int index);
stdapi (void)    Deletesimpledatarange(t_simple *pdat,ulong addr0,ulong addr1);

// Bits that describe the state of predicted data, similar to PST_xxx.
#define PRED_SHORTSP   0x8000          // Offset of ESP is 1 byte, .udd only
#define PRED_SHORTBP   0x4000          // Offset of EBP is 1 byte, .udd only
#define PRED_ESPRET    0x0400          // Offset of ESP backtraced from return
#define PRED_ESPOK     0x0200          // Offset of ESP valid
#define PRED_EBPOK     0x0100          // Offset of EBP valid
#define PRED_REL       0x0080          // Result constant fixuped or relative
#define PRED_RESMASK   0x003F          // Mask to extract description of result
#define   PRED_VALID   0x0020          // Result constant valid
#define   PRED_ADDR    0x0010          // Result is address
#define   PRED_ORIG    0x0008          // Result is based on original register
#define   PRED_OMASK   0x0007          // Mask to extract original register

#define PRED_ESPKNOWN  (PRED_ESPRET|PRED_ESPOK)

typedef struct sd_pred {               // Descriptor of predicted data
  ulong          addr;                 // Address of predicted command
  ushort         mode;                 // Combination of PRED_xxx
  long           espconst;             // Offset of ESP to original ESP
  long           ebpconst;             // Offset of EBP to original ESP
  ulong          resconst;             // Constant in result of execution
} sd_pred;


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// SORTED DATA //////////////////////////////////

#define SDM_INDEXED    0x00000001      // Indexed sorted data
#define SDM_EXTADDR    0x00000002      // Address is extended by TY_AEXTMASK
#define SDM_NOSIZE     0x00000004      // Header without size and type
#define SDM_NOEXTEND   0x00000008      // Don't reallocate memory, fail instead

// Address extension.
#define TY_AEXTMASK    0x000000FF      // Mask to extract address extension
// General item types.
#define TY_NEW         0x00000100      // Item is new
#define TY_CONFIRMED   0x00000200      // Item still exists
#define TY_EXTADDR     0x00000400      // Address extension active
#define TY_SELECTED    0x00000800      // Reserved for multiple selection
// Module-related item types (used in t_module and t_premod).
#define MOD_MAIN       0x00010000      // Main module
#define MOD_SFX        0x00020000      // Self-extractable file
#define   MOD_SFXDONE  0x00040000      // SFX file extracted
#define MOD_RUNDLL     0x00080000      // DLL loaded by LOADDLL.EXE
#define MOD_SYSTEMDLL  0x00100000      // System DLL
#define MOD_SUPERSYS   0x00200000      // System DLL that uses special commands
#define MOD_DBGDATA    0x00400000      // Debugging data is available
#define MOD_ANALYSED   0x00800000      // Module is already analysed
#define MOD_NODATA     0x01000000      // Module data is not yet available
#define MOD_HIDDEN     0x02000000      // Module is loaded in stealth mode
#define MOD_NETAPP     0x04000000      // .NET application
#define MOD_RESOLVED   0x40000000      // All static imports are resolved
// Memory-related item types (used in t_memory), see also t_memory.special.
#define MEM_ANYMEM     0x0FFFF000      // Mask for memory attributes
#define   MEM_CODE     0x00001000      // Contains image of code section
#define   MEM_DATA     0x00002000      // Contains image of data section
#define   MEM_SFX      0x00004000      // Contains self-extractor
#define   MEM_IMPDATA  0x00008000      // Contains import data
#define   MEM_EXPDATA  0x00010000      // Contains export data
#define   MEM_RSRC     0x00020000      // Contains resources
#define   MEM_RELOC    0x00040000      // Contains relocation data
#define   MEM_STACK    0x00080000      // Contains stack of some thread
#define   MEM_STKGUARD 0x00100000      // Guarding page of the stack
#define   MEM_THREAD   0x00200000      // Contains data block of some thread
#define   MEM_HEADER   0x00400000      // Contains COFF header
#define   MEM_DEFHEAP  0x00800000      // Contains default heap
#define   MEM_HEAP     0x01000000      // Contains non-default heap
#define   MEM_NATIVE   0x02000000      // Contains JIT-compiled native code
#define   MEM_GAP      0x08000000      // Free or reserved space
#define MEM_SECTION    0x10000000      // Section of the executable file
#define MEM_GUARDED    0x40000000      // NT only: guarded memory block
#define MEM_TEMPGUARD  0x80000000      // NT only: temporarily guarded block
// Thread-related item types (used in t_thread).
#define THR_MAIN       0x00010000      // Main thread
#define THR_NETDBG     0x00020000      // .NET debug helper thread
#define THR_ORGHANDLE  0x00100000      // Original thread's handle, don't close
// Window-related item types (used in t_window).
#define WN_UNICODE     0x00010000      // UNICODE window
// Procedure-related item types (used in t_procdata).
#define PD_CALLBACK    0x00001000      // Used as a callback
#define PD_RETSIZE     0x00010000      // Return size valid
#define PD_TAMPERRET   0x00020000      // Tampers with the return address
#define PD_NORETURN    0x00040000      // Calls function without return
#define PD_PURE        0x00080000      // Doesn't modify memory & make calls
#define PD_ESPALIGN    0x00100000      // Aligns ESP on entry
#define PD_ARGMASK     0x07E00000      // Mask indicating valid narg
#define   PD_FIXARG    0x00200000      // narg is fixed number of arguments
#define   PD_FORMATA   0x00400000      // narg-1 is ASCII printf format
#define   PD_FORMATW   0x00800000      // narg-1 is UNICODE printf format
#define   PD_SCANA     0x01000000      // narg-1 is ASCII scanf format
#define   PD_SCANW     0x02000000      // narg-1 is UNICODE scanf format
#define   PD_COUNT     0x04000000      // narg-1 is count of following args
#define PD_GUESSED     0x08000000      // narg and type are guessed, not known
#define PD_NGUESS      0x10000000      // nguess valid
#define PD_VARGUESS    0x20000000      // nguess variable, set to minimum!=0
#define PD_NPUSH       0x40000000      // npush valid
#define PD_VARPUSH     0x80000000      // npush valid, set to maximum
// Argument prediction-related types (used in t_predict).
#define PR_PUSHBP      0x00010000      // PUSH EBP or ENTER executed
#define PR_MOVBPSP     0x00020000      // MOV EBP,ESP or ENTER executed
#define PR_SETSEH      0x00040000      // Structured exception handler set
#define PR_RETISJMP    0x00100000      // Return is (mis)used as a jump
#define PR_DIFFRET     0x00200000      // Return changed, destination unknown
#define PR_JMPTORET    0x00400000      // Jump to original return address
#define PR_TAMPERRET   0x00800000      // Retaddr on stack accessed or modified
#define PR_BADESP      0x01000000      // ESP of actual generation is invalid
#define PR_RET         0x02000000      // Return from subroutine
#define PR_STEPINTO    0x10000000      // Step into CALL command
// Breakpoint-related types (used in t_bpoint, t_bpmem and t_bphard).
#define BP_BASE        0x0000F000      // Mask to extract basic breakpoint type
#define   BP_MANUAL    0x00001000      // Permanent breakpoint
#define   BP_ONESHOT   0x00002000      // Stop and reset this bit
#define   BP_TEMP      0x00004000      // Reset this bit and continue
#define   BP_TRACE     0x00008000      // Used for hit trace
#define BP_SET         0x00010000      // Code INT3 is in memory, cmd is valid
#define BP_DISABLED    0x00020000      // Permanent breakpoint is disabled
#define BP_COND        0x00040000      // Conditional breakpoint
#define BP_PERIODICAL  0x00080000      // Periodical (pauses each passcount)
#define BP_ACCESSMASK  0x00E00000      // Access conditions (memory+hard)
#define   BP_READ      0x00200000      // Break on read memory access
#define   BP_WRITE     0x00400000      // Break on write memory access
#define   BP_EXEC      0x00800000      // Break on code execution
#define BP_BREAKMASK   0x03000000      // When to pause execution
#define   BP_NOBREAK   0x00000000      // No pause
#define   BP_CONDBREAK 0x01000000      // Pause if condition is true
#define   BP_BREAK     0x03000000      // Pause always
#define BP_LOGMASK     0x0C000000      // When to log value of expression
#define   BP_NOLOG     0x00000000      // Don't log expression
#define   BP_CONDLOG   0x04000000      // Log expression if condition is true
#define   BP_LOG       0x0C000000      // Log expression always
#define BP_ARGMASK     0x30000000      // When to log arguments of a function
#define   BP_NOARG     0x00000000      // Don't log arguments
#define   BP_CONDARG   0x10000000      // Log arguments if condition is true
#define   BP_ARG       0x30000000      // Log arguments always
#define BP_RETMASK     0xC0000000      // When to log return value of a function
#define   BP_NORET     0x00000000      // Don't log return value
#define   BP_CONDRET   0x40000000      // Log return value if condition is true
#define   BP_RET       0xC0000000      // Log return value always
#define BP_MANMASK (BP_PERIODICAL|BP_BREAKMASK|BP_LOGMASK|BP_ARGMASK|BP_RETMASK)
#define BP_CONFIRM     TY_CONFIRMED    // Internal OllyDbg use
// Search-related types (used in t_search).
#define SE_ORIGIN      0x00010000      // Search origin
#define SE_STRING      0x00020000      // Data contains string address
#define SE_FLOAT       0x00040000      // Data contains floating constant
#define SE_GUID        0x00080000      // Data contains GUID
#define SE_CONST       0x01000000      // Constant, not referencing command
// Source-related types (used in t_source).
#define SRC_ABSENT     0x00010000      // Source file is absent
// Namelist-related types (used in t_namelist).
#define NL_EORD        0x00010000      // Associated export ordinal available
#define NL_IORD        0x00020000      // Associated import ordinal available

typedef struct t_sorthdr {             // Header of sorted data item
  ulong          addr;                 // Base address of the entry
  ulong          size;                 // Size of the entry
  ulong          type;                 // Type and address extension, TY_xxx
} t_sorthdr;

typedef struct t_sorthdr_nosize {      // Header of SDM_NOSIZE item
  ulong          addr;                 // Base address of the entry
} t_sorthdr_nosize;

typedef int  SORTFUNC(const t_sorthdr *,const t_sorthdr *,const int);
typedef void DESTFUNC(t_sorthdr *);

#define AUTOARRANGE    ((SORTFUNC *)1) // Autoarrangeable sorted data

#define NBLOCK         2048            // Max number of data blocks
#define BLOCKSIZE      1048576         // Size of single data block, bytes

typedef struct t_sorted {              // Descriptor of sorted data
  int            n;                    // Actual number of entries
  int            nmax;                 // Maximal number of entries
  ulong          itemsize;             // Size of single entry
  int            mode;                 // Storage mode, set of SDM_xxx
  void           *data;                // Sorted data, NULL if SDM_INDEXED
  void           **block;              // NBLOCK sorted data blocks, or NULL
  int            nblock;               // Number of allocated blocks
  ulong          version;              // Changes on each modification
  void           **dataptr;            // Pointers to data, sorted by address
  int            selected;             // Index of selected entry
  ulong          seladdr;              // Base address of selected entry
  ulong          selsubaddr;           // Subaddress of selected entry
  SORTFUNC       *sortfunc;            // Function which sorts data or NULL
  DESTFUNC       *destfunc;            // Destructor function or NULL
  int            sort;                 // Sorting criterium (column)
  int            sorted;               // Whether indexes are sorted
  int            *sortindex;           // Indexes, sorted by criterium
} t_sorted;

stdapi (void)    Destroysorteddata(t_sorted *sd);
stdapi (int)     Createsorteddata(t_sorted *sd,ulong itemsize,int nexp,
                   SORTFUNC *sortfunc,DESTFUNC *destfunc,int mode);
stdapi (void)    Deletesorteddata(t_sorted *sd,ulong addr,ulong subaddr);
stdapi (int)     Deletesorteddatarange(t_sorted *sd,ulong addr0,ulong addr1);
stdapi (void *)  Addsorteddata(t_sorted *sd,void *item);
stdapi (int)     Replacesorteddatarange(t_sorted *sd,void *data,int n,
                   ulong addr0,ulong addr1);
stdapi (void)    Renumeratesorteddata(t_sorted *sd);
stdapi (int)     Confirmsorteddata(t_sorted *sd,int confirm);
stdapi (int)     Deletenonconfirmedsorteddata(t_sorted *sd);
stdapi (void)    Unmarknewsorteddata(t_sorted *sd);
stdapi (void *)  Findsorteddata(t_sorted *sd,ulong addr,ulong subaddr);
stdapi (void *)  Findsorteddatarange(t_sorted *sd,ulong addr0,ulong addr1);
stdapi (int)     Findsortedindexrange(t_sorted *sd,ulong addr0,ulong addr1);
stdapi (void *)  Getsortedbyindex(t_sorted *sd,int index);
stdapi (int)     Sortsorteddata(t_sorted *sd,int sort);
stdapi (void *)  Getsortedbyselection(t_sorted *sd,int index);
stdapi (int)     Issortedinit(t_sorted *sd);


////////////////////////////////////////////////////////////////////////////////
///////////////////////// SORTED DATA WINDOWS (TABLES) /////////////////////////

#define NBAR           17              // Max allowed number of segments in bar

#define BAR_FLAT       0x00000000      // Flat segment
#define BAR_BUTTON     0x00000001      // Segment sends WM_USER_BAR
#define BAR_SORT       0x00000002      // Segment re-sorts sorted data
#define BAR_DISABLED   0x00000004      // Bar segment disabled
#define BAR_NORESIZE   0x00000008      // Bar column cannot be resized
#define BAR_SHIFTSEL   0x00000010      // Selection shifted 1/2 char to left
#define BAR_WIDEFONT   0x00000020      // Twice as wide characters
#define BAR_SEP        0x00000040      // Treat '|' as separator
#define BAR_ARROWS     0x00000080      // Arrows if segment is shifted
#define BAR_PRESSED    0x00000100      // Bar segment pressed, used internally
#define BAR_SPMASK     0x0000F000      // Mask to extract speech type
#define   BAR_SPSTD    0x00000000      // Standard speech with all conversions
#define   BAR_SPASM    0x00001000      // Disassembler-oriented speech
#define   BAR_SPEXPR   0x00002000      // Expression-oriented speech
#define   BAR_SPEXACT  0x00003000      // Pass to speech engine as is
#define   BAR_SPELL    0x00004000      // Text, spell symbol by symbol
#define   BAR_SPHEX    0x00005000      // Hexadecimal, spell symbol by symbol
#define   BAR_SPNONE   0x0000F000      // Column is excluded from speech

typedef struct t_bar {                 // Descriptor of columns in table window
  // These variables must be filled before table window is created.
  int            nbar;                 // Number of columns
  int            visible;              // Bar visible
  wchar_t        *name[NBAR];          // Column names (may be NULL)
  wchar_t        *expl[NBAR];          // Explanations of columns
  int            mode[NBAR];           // Combination of bits BAR_xxx
  int            defdx[NBAR];          // Default widths of columns, chars
  // These variables are initialized by window creation function.
  int            dx[NBAR];             // Actual widths of columns, pixels
  int            captured;             // One of CAPT_xxx
  int            active;               // Info about where mouse was captured
  int            scrollvx;             // X scrolling speed
  int            scrollvy;             // Y scrolling speed
  int            prevx;                // Previous X mouse coordinate
  int            prevy;                // Previous Y mouse coordinate
} t_bar;

#define TABLE_USERDEF  0x00000001      // User-drawn table
#define TABLE_STDSCR   0x00000002      // User-drawn but standard scrolling
#define TABLE_SIMPLE   0x00000004      // Non-sorted, address is line number
#define TABLE_DIR      0x00000008      // Bottom-to-top table
#define TABLE_COLSEL   0x00000010      // Column-wide selection
#define TABLE_BYTE     0x00000020      // Allows for bytewise scrolling
#define TABLE_FASTSEL  0x00000040      // Update when selection changes
#define TABLE_RIGHTSEL 0x00000080      // Right click can select items
#define TABLE_RFOCUS   0x00000100      // Right click sets focus
#define TABLE_NOHSCR   0x00000200      // Table contains no horizontal scroll
#define TABLE_NOVSCR   0x00000400      // Table contains no vertical scroll
#define TABLE_NOBAR    0x00000800      // Bar is always hidden
#define TABLE_STATUS   0x00001000      // Table contains status bar
#define TABLE_MMOVX    0x00002000      // Table is moveable by mouse in X
#define TABLE_MMOVY    0x00004000      // Table is moveable by mouse in Y
#define TABLE_WANTCHAR 0x00008000      // Table processes characters
#define TABLE_SAVEAPP  0x00010000      // Save appearance to .ini
#define TABLE_SAVEPOS  0x00020000      // Save position to .ini
#define TABLE_SAVECOL  0x00040000      // Save width of columns to .ini
#define TABLE_SAVESORT 0x00080000      // Save sort criterium to .ini
#define TABLE_SAVECUST 0x00100000      // Save table-specific data to .ini
#define TABLE_GRAYTEXT 0x00200000      // Text in table is grayed
#define TABLE_NOGRAY   0x00400000      // Text in pane is never grayed
#define TABLE_UPDFOCUS 0x00800000      // Update frame pane on focus change
#define TABLE_AUTOUPD  0x01000000      // Table allows periodical autoupdate
#define TABLE_SYNTAX   0x02000000      // Table allows syntax highlighting
#define TABLE_PROPWID  0x04000000      // Column width means proportional width
#define TABLE_INFRAME  0x10000000      // Table belongs to the frame window
#define TABLE_BORDER   0x20000000      // Table has sunken border
#define TABLE_KEEPOFFS 0x80000000      // Keep xshift, offset, colsel

#define TABLE_MOUSEMV  (TABLE_MMOVX|TABLE_MMOVY)
#define TABLE_SAVEALL (TABLE_SAVEAPP|TABLE_SAVEPOS|TABLE_SAVECOL|TABLE_SAVESORT)

#define DRAW_COLOR     0x0000001F      // Mask to extract colour/bkgnd index
// Direct colour/background pairs.
#define   DRAW_NORMAL  0x00000000      // Normal text
#define   DRAW_HILITE  0x00000001      // Highlighted text
#define   DRAW_GRAY    0x00000002      // Grayed text
#define   DRAW_EIP     0x00000003      // Actual EIP
#define   DRAW_BREAK   0x00000004      // Unconditional breakpoint
#define   DRAW_COND    0x00000005      // Conditional breakpoint
#define   DRAW_BDIS    0x00000006      // Disabled breakpoint
#define   DRAW_IPBREAK 0x00000007      // Breakpoint at actual EIP
#define   DRAW_AUX     0x00000008      // Auxiliary colours
#define   DRAW_SELUL   0x00000009      // Selection and underlining
// Indirect pairs used to highlight commands.
#define   DRAW_PLAIN   0x0000000C      // Plain commands
#define   DRAW_JUMP    0x0000000D      // Unconditional jump commands
#define   DRAW_CJMP    0x0000000E      // Conditional jump commands
#define   DRAW_PUSHPOP 0x0000000F      // PUSH/POP commands
#define   DRAW_CALL    0x00000010      // CALL commands
#define   DRAW_RET     0x00000011      // RET commands
#define   DRAW_FPU     0x00000012      // FPU, MMX, 3DNow! and SSE commands
#define   DRAW_SUSPECT 0x00000013      // Bad, system and privileged commands
#define   DRAW_FILL    0x00000014      // Filling commands
#define   DRAW_MOD     0x00000015      // Modified commands
// Indirect pairs used to highlight operands.
#define   DRAW_IREG    0x00000018      // General purpose registers
#define   DRAW_FREG    0x00000019      // FPU, MMX and SSE registers
#define   DRAW_SYSREG  0x0000001A      // Segment and system registers
#define   DRAW_STKMEM  0x0000001B      // Memory accessed over ESP or EBP
#define   DRAW_MEM     0x0000001C      // Any other memory
#define   DRAW_MCONST  0x0000001D      // Constant pointing to memory
#define   DRAW_CONST   0x0000001E      // Any other constant
#define DRAW_APP       0x00000060      // Mask to extract appearance
#define   DRAW_TEXT    0x00000000      // Plain text
#define   DRAW_ULTEXT  0x00000020      // Underlined text
#define   DRAW_GRAPH   0x00000060      // Graphics (text consists of G_xxx)
#define DRAW_SELECT    0x00000080      // Use selection background
#define DRAW_MASK      0x00000100      // Mask in use
#define DRAW_VARWIDTH  0x00000200      // Variable width possible
#define DRAW_EXTSEL    0x00000800      // Extend mask till end of column
#define DRAW_TOP       0x00001000      // Draw upper half of the two-line text
#define DRAW_BOTTOM    0x00002000      // Draw lower half of the two-line text
#define DRAW_INACTIVE  0x00004000      // Gray everything except hilited text
#define DRAW_RAWDATA   0x00008000      // Don't convert glyphs and multibytes
#define DRAW_NEW       0x00010000      // Use highlighted foreground

typedef struct t_drawheader {          // Draw descriptor for TABLE_USERDEF
  int            line;                 // Line in window
  int            n;                    // Total number of visible lines
  ulong          nextaddr;             // First address on next line, or 0
  // Following elements can be freely used by drawing routine. They do not
  // change between calls within one table.
  ulong          addr;                 // Custom data
  uchar          s[TEXTLEN];           // Custom data
} t_drawheader;

// Constants used for scrolling and selection.
#define MOVETOP        0x8000          // Move selection to top of table
#define MOVEBOTTOM     0x7FFF          // Move selection to bottom of table

#define DF_CACHESIZE   (-4)            // Request for draw cache size
#define DF_FILLCACHE   (-3)            // Request to fill draw cache
#define DF_FREECACHE   (-2)            // Request to free cached resources
#define DF_NEWROW      (-1)            // Request to start new row in window

// Reasons why t_table.tableselfunc() was called.
#define TSC_KEY        1               // Keyboard key pressed
#define TSC_MOUSE      2               // Selection changed by mouse
#define TSC_CALL       3               // Call to selection move function

typedef long TABFUNC(struct t_table *,HWND,UINT,WPARAM,LPARAM);
typedef int  UPDATEFUNC(struct t_table *);
typedef int  DRAWFUNC(wchar_t *,uchar *,int *,struct t_table *,
  t_sorthdr *,int,void *);
typedef void TABSELFUNC(struct t_table *,int,int);

typedef struct t_table {               // Window with sorted data and bar
  // These variables must be filled before table window is created.
  wchar_t        name[SHORTNAME];      // Name used to save/restore position
  int            mode;                 // Combination of bits TABLE_xxx
  t_sorted       sorted;               // Sorted data
  int            subtype;              // User-defined subtype
  t_bar          bar;                  // Description of bar
  int            bottomspace;          // Height of free space on the bottom
  int            minwidth;             // Minimal width of the table, pixels
  TABFUNC        *tabfunc;             // Custom message function or NULL
  UPDATEFUNC     *updatefunc;          // Data update function or NULL
  DRAWFUNC       *drawfunc;            // Drawing function
  TABSELFUNC     *tableselfunc;        // Callback indicating selection change
  t_menu         *menu;                // Menu descriptor
  // Table functions neither initialize nor use these variables.
  ulong          custommode;           // User-defined custom data
  void           *customdata;          // Pointer to more custom data
  // These variables are initialized and/or used by table functions.
  HWND           hparent;              // Handle of MDI container or NULL
  HWND           hstatus;              // Handle of status bar or NULL
  HWND           hw;                   // Handle of child table or NULL
  HWND           htooltip;             // Handle of tooltip window or NULL
  int            font;                 // Index of font used by window
  int            scheme;               // Colour scheme used by window
  int            hilite;               // Highlighting scheme used by window
  int            hscroll;              // Whether horizontal scroll visible
  int            xshift;               // Shift in X direction, pixels
  int            offset;               // First displayed row
  int            colsel;               // Column in TABLE_COLSEL window
  ulong          version;              // Version of sorted on last update
  ulong          timerdraw;            // Timer redraw is active (period, ms)
  RECT           rcprev;               // Temporary storage for old position
  int            rtback;               // Back step in run trace, 0 - actual
} t_table;

#define GWL_USR_TABLE  0               // Offset to pointer to t_table

// Custom messages.
#define WM_USER_CREATE (WM_USER+100)   // Table window is created
#define WM_USER_HSCR   (WM_USER+101)   // Update horizontal scroll
#define WM_USER_VSCR   (WM_USER+102)   // Update vertical scroll
#define WM_USER_MOUSE  (WM_USER+103)   // Mouse moves, set custom cursor
#define WM_USER_VINC   (WM_USER+104)   // Scroll contents of window by lines
#define WM_USER_VPOS   (WM_USER+105)   // Scroll contents of window by position
#define WM_USER_VBYTE  (WM_USER+106)   // Scroll contents of window by bytes
#define WM_USER_SETS   (WM_USER+107)   // Start selection in window
#define WM_USER_CNTS   (WM_USER+108)   // Continue selection in window
#define WM_USER_MMOV   (WM_USER+109)   // Move window's contents by mouse
#define WM_USER_MOVS   (WM_USER+110)   // Keyboard scrolling and selection
#define WM_USER_KEY    (WM_USER+111)   // Key pressed
#define WM_USER_BAR    (WM_USER+112)   // Message from bar segment as button
#define WM_USER_DBLCLK (WM_USER+113)   // Doubleclick in column
#define WM_USER_SELXY  (WM_USER+114)   // Get coordinates of selection
#define WM_USER_FOCUS  (WM_USER+115)   // Set focus to child of frame window
#define WM_USER_UPD    (WM_USER+116)   // Autoupdate contents of the window
#define WM_USER_MTAB   (WM_USER+117)   // Middle click on tab in tab parent
// Custom broadcasts and notifications.
#define WM_USER_CHGALL (WM_USER+132)   // Update all windows
#define WM_USER_CHGCPU (WM_USER+133)   // CPU thread has changed
#define WM_USER_CHGMEM (WM_USER+134)   // List of memory blocks has changed
#define WM_USER_BKUP   (WM_USER+135)   // Global backup is changed
#define WM_USER_FILE   (WM_USER+136)   // Query for file dump
#define WM_USER_NAMES  (WM_USER+137)   // Query for namelist window
#define WM_USER_SAVE   (WM_USER+138)   // Query for unsaved data
#define WM_USER_CLEAN  (WM_USER+139)   // End of process, close related windows
#define WM_USER_HERE   (WM_USER+140)   // Query for windows to restore
#define WM_USER_CLOSE  (WM_USER+141)   // Internal substitute for WM_CLOSE

#define KEY_ALT        0x04            // Alt key pressed
#define KEY_CTRL       0x02            // Ctrl key pressed
#define KEY_SHIFT      0x01            // Shift key pressed

// Control alignment modes for Createtablechild().
#define ALIGN_MASK     0xC000          // Mask to extract control alignment
#define   ALIGN_LEFT   0x0000          // Control doesn't move
#define   ALIGN_RIGHT  0x4000          // Control moves with right border
#define   ALIGN_WIDTH  0x8000          // Control resizes with right border
#define ALIGN_IDMASK   0x0FFF          // Mask to extract control ID

stdapi (void)    Processwmmousewheel(HWND hw,WPARAM wp);
stdapi (int)     Getcharacterwidth(t_table *pt,int column);
stdapi (void)    Defaultbar(t_table *pt);
stdapi (int)     Linecount(t_table *pt);
stdapi (int)     Gettabletext(t_table *pt,int row,int column,
                   wchar_t *text,uchar *tmask,int *tselect);
stdapi (int)     Gettableselectionxy(t_table *pt,int column,POINT *coord);
stdapi (int)     Maketableareavisible(t_table *pt,int column,
                   int x0,int y0,int x1,int y1);
stdapi (int)     Movetableselection(t_table *pt,int n);
stdapi (int)     Settableselection(t_table *pt,int selected);
stdapi (int)     Removetableselection(t_table *pt);
stdapi (void)    Updatetable(t_table *pt,int force);
stdapi (void)    Delayedtableredraw(t_table *pt);
stdapi (void)    Setautoupdate(t_table *pt,int autoupdate);
stdapi (HGLOBAL) Copytableselection(t_table *pt,int column);
stdapi (HGLOBAL) Copywholetable(t_table *pt,int compatible);
stdapi (HWND)    Createottablewindow(HWND hparent,t_table *pt,RECT *rpos);
stdapi (HWND)    Createtablewindow(t_table *pt,int nrow,int ncolumn,
                   HINSTANCE hi,wchar_t *icon,wchar_t *title);
stdapi (HWND)    Activatetablewindow(t_table *pt);
stdapi (HWND)    Createtablechild(t_table *pt,wchar_t *classname,wchar_t *name,
                   wchar_t *help,ulong style,int x,int y,int dx,int dy,
                   int idalign);


////////////////////////////////////////////////////////////////////////////////
//////////////////////////// FRAME AND TAB WINDOWS /////////////////////////////

#define BLK_NONE       0               // Mouse outside the dividing line
#define BLK_HDIV       1               // Divide horizontally
#define BLK_VDIV       2               // Divide vertically
#define BLK_TABLE      3               // Leaf that describes table window

typedef struct t_block {               // Block descriptor
  int            index;                // Index of pos record in the .ini file
  int            type;                 // One of BLK_xxx
  int            percent;              // Percent of block in left/top subblock
  int            offset;               // Offset of dividing line, pixels
  struct t_block *blk1;                // Top/left subblock, NULL if leaf
  int            minp1;                // Min size of 1st subblock, pixels
  int            maxc1;                // Max size of 1st subblock, chars, or 0
  struct t_block *blk2;                // Bottom/right subblock, NULL if leaf
  int            minp2;                // Min size of 2nd subblock, pixels
  int            maxc2;                // Max size of 2nd subblock, chars, or 0
  t_table        *table;               // Descriptor of table window
  wchar_t        tabname[SHORTNAME];   // Tab (tab window only)
  wchar_t        title[TEXTLEN];       // Title (tab window) or speech name
  wchar_t        status[TEXTLEN];      // Status (tab window only)
} t_block;

typedef struct t_frame {               // Descriptor of frame or tab window
  // These variables must be filled before frame window is created.
  wchar_t        name[SHORTNAME];      // Name used to save/restore position
  int            herebit;              // Must be 0 for plugins
  int            mode;                 // Combination of bits TABLE_xxx
  t_block        *block;               // Pointer to block tree
  t_menu         *menu;                // Menu descriptor (tab window only)
  int            scheme;               // Colour scheme used by window
  // These variables are initialized by frame creation function.
  HWND           hw;                   // Handle of MDI container or NULL
  HWND           htab;                 // Handle of tab control
  WNDPROC        htabwndproc;          // Original WndProc of tab control
  int            capturedtab;          // Tab captured on middle mouse click
  HWND           hstatus;              // Handle of status bar or NULL
  t_block        *active;              // Active table (has focus) or NULL
  t_block        *captured;            // Block that captured mouse or NULL
  int            captureoffset;        // Offset on mouse capture
  int            capturex;             // Mouse screen X coordinate on capture
  int            capturey;             // Mouse screen Y coordinate on capture
  wchar_t        title[TEXTLEN];       // Frame or tab window title
} t_frame;

stdapi (HWND)    Createframewindow(t_frame *pf,wchar_t *icon,wchar_t *title);
stdapi (void)    Updateframe(t_frame *pf,int redrawnow);
stdapi (t_table *) Getactiveframe(t_frame *pf);

stdapi (int)     Updatetabs(t_frame *pf);
stdapi (HWND)    Createtabwindow(t_frame *pf,wchar_t *icon,wchar_t *title);
stdapi (t_table *) Getactivetab(t_frame *pf);
stdapi (int)     Gettabcount(t_frame *pf,int *index);
stdapi (int)     Setactivetab(t_frame *pf,int index);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// FONTS AND GRAPHICS //////////////////////////////

#define FIXEDFONT      0               // Indices of fixed fonts used in tables
#define TERMINAL6      1               // Note: fonts may be changed by user!
#define FIXEDSYS       2
#define COURIERFONT    3
#define LUCIDACONS     4
#define FONT5          5
#define FONT6          6
#define FONT7          7

#define NFIXFONTS      8               // Total number of fixed fonts

#define BLACKWHITE     0               // Colour schemes used by OllyDbg
#define BLUEGOLD       1               // Note: colours may be changed by user!
#define SKYWIND        2
#define NIGHTSTARS     3
#define SCHEME4        4
#define SCHEME5        5
#define SCHEME6        6
#define SCHEME7        7

#define NSCHEMES       8               // Number of predefined colour schemes
#define NDRAW          32              // Number of fg/bg pairs in scheme

#define NOHILITE       0               // Highlighting schemes used by OllyDbg
#define XMASHILITE     1               // Note: colours may be changed by user!
#define JUMPHILITE     2
#define MEMHILITE      3
#define HILITE4        4
#define HILITE5        5
#define HILITE6        6
#define HILITE7        7

#define NHILITE        8               // Number of predefined hilite schemes

#define BLACK          0               // Indexes of colours used by OllyDbg
#define BLUE           1
#define GREEN          2
#define CYAN           3
#define RED            4
#define MAGENTA        5
#define BROWN          6
#define LIGHTGRAY      7
#define DARKGRAY       8
#define LIGHTBLUE      9
#define LIGHTGREEN     10
#define LIGHTCYAN      11
#define LIGHTRED       12
#define LIGHTMAGENTA   13
#define YELLOW         14
#define WHITE          15
#define MINT           16
#define SKYBLUE        17
#define IVORY          18
#define GRAY           19

#define NFIXCOLORS     20              // Number of colors fixed in OllyDbg
#define NCOLORS        (NFIXCOLORS+16) // Number of available colours

// Symbolic names for graphical characters. Any other graphical symbol is
// interpreted as a space. Use only symbols in range [0x01..0x3F], high bits
// are reserved for the future!
#define G_SPACE        0x01            // Space
#define G_SEP          0x02            // Thin separating line
#define G_POINT        0x03            // Point
#define G_BIGPOINT     0x04            // Big point
#define G_JMPDEST      0x05            // Jump destination
#define G_CALLDEST     0x06            // Call destination
#define G_QUESTION     0x07            // Question mark
#define G_JMPUP        0x10            // Jump upstairs
#define G_JMPOUT       0x11            // Jump to same location or outside
#define G_JMPDN        0x12            // Jump downstairs
#define G_SWUP         0x13            // Switch upstairs
#define G_SWBOTH       0x14            // Switch in both directions
#define G_SWDOWN       0x15            // Switch down
#define G_BEGIN        0x18            // Begin of procedure or scope
#define G_BODY         0x19            // Body of procedure or scope
#define G_ENTRY        0x1A            // Loop entry point
#define G_LEAF         0x1B            // Intermediate leaf on a tree
#define G_END          0x1C            // End of procedure or scope
#define G_SINGLE       0x1D            // Single-line scope
#define G_ENDBEG       0x1E            // End and begin of stack scope
#define G_PATHUP       0x21            // Jump path start upstairs
#define G_PATH         0x22            // Jump path through
#define G_PATHDN       0x23            // Jump path start downstairs
#define G_PATHUPDN     0x24            // Two-sided jump path start
#define G_THROUGHUP    0x25            // Jump entry upstairs
#define G_THROUGHDN    0x26            // Jump entry downstairs
#define G_PATHUPEND    0x27            // End of path upstairs
#define G_PATHDNEND    0x28            // End of path downstairs
#define G_PATHBIEND    0x29            // Two-sided end of path
#define G_THRUUPEND    0x2A            // Intermediate end upstairs
#define G_THRUDNEND    0x2B            // Intermediate end downstairs
#define G_ARRLEFT      0x2C            // Left arrow
// Graphical elements used to draw frames in the command help.
#define G_HL           0x30            // Horizontal line
#define G_LT           0x31            // Left top corner
#define G_CT           0x32            // Central top element
#define G_RT           0x33            // Right top corner
#define G_LM           0x34            // Left middle element
#define G_CM           0x35            // Central cross
#define G_RM           0x36            // Right middle element
#define G_LB           0x37            // Left bottom corner
#define G_CB           0x38            // Central bottom element
#define G_RB           0x39            // Right bottom corner
#define G_VL           0x3A            // Vertical line
#define G_LA           0x3B            // Horizontal line with left arrow
#define G_RA           0x3C            // Horizontal line with right arrow
#define G_DA           0x3D            // Vertical line with down arrow

typedef struct t_font {                // Font descriptor
  LOGFONT        logfont;              // System font description
  int            stockindex;           // Index for system stock fonts
  int            hadjtop;              // Height adjustment on top, pixels
  int            hadjbot;              // Height adjustment on bottom, pixels
  wchar_t        name[TEXTLEN];        // Internal font name
  HFONT          hfont;                // Font handle
  int            isstock;              // Don't destroy hfont, taken from stock
  int            isfullunicode;        // Whether UNICODE is fully supported
  int            width;                // Average font width
  int            height;               // Font height
} t_font;

typedef struct t_scheme {              // Descriptor of colour scheme
  wchar_t        name[TEXTLEN];        // Internal scheme name
  COLORREF       textcolor[NDRAW];     // Foreground colours (in DRAW_COLOR)
  COLORREF       bkcolor[NDRAW];       // Background colours (in DRAW_COLOR)
  int            hiliteoperands;       // Used only by highlighting schemes
  int            hilitemodified;       // Used only by highlighting schemes
  HBRUSH         bkbrush;              // Ordinary background brush
  HBRUSH         selbkbrush;           // Selected background brush
  HBRUSH         auxbrush;             // Auxiliary brush
  HPEN           graphpen;             // Pen for normal graphical elements
  HPEN           lopen;                // Pen for grayed graphical elements
  HPEN           hipen;                // Pen for hilited graphical elements
  HPEN           auxpen;               // Pen for auxiliary graphical elements
  HPEN           ulpen;                // Pen to underline text
} t_scheme;

stdapi (int)     Getmonitorrect(int x,int y,RECT *rc);
stdapi (void)    Sunkenframe(HDC dc,RECT *rc,int flags);
stdapi (int)     Findstockobject(ulong gdihandle,wchar_t *name,int nname);


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// MEMORY FUNCTIONS ///////////////////////////////

// Mode bits used in calls to Readmemory(), Readmemoryex() and Writememory().
#define MM_REPORT      0x0000          // Display error message if unreadable
#define MM_SILENT      0x0001          // Don't display error message
#define MM_NORESTORE   0x0002          // Don't remove/set INT3 breakpoints
#define MM_PARTIAL     0x0004          // Allow less data than requested
#define MM_WRITETHRU   0x0008          // Write immediately to memory
#define MM_REMOVEINT3  0x0010          // Writememory(): remove INT3 breaks
#define MM_ADJUSTINT3  0x0020          // Writememory(): adjust INT3 breaks
#define MM_FAILGUARD   0x0040          // Fail if memory is guarded
// Mode bits used in calls to Readmemoryex().
#define MM_BPMASK      BP_ACCESSMASK   // Mask to extract memory breakpoints
#define   MM_BPREAD    BP_READ         // Fail if memory break on read is set
#define   MM_BPWRITE   BP_WRITE        // Fail if memory break on write is set
#define   MM_BPEXEC    BP_EXEC         // Fail if memory break on exec is set

// Special types of memory block.
#define MSP_NONE       0               // Not a special memory block
#define MSP_PEB        1               // Contains Process Environment Block
#define MSP_SHDATA     2               // Contains KUSER_SHARED_DATA
#define MSP_PROCPAR    3               // Contains Process Parameters
#define MSP_ENV        4               // Contains environment

typedef struct t_memory {              // Descriptor of memory block
  ulong          base;                 // Base address of memory block
  ulong          size;                 // Size of memory block
  ulong          type;                 // Service information, TY_xxx+MEM_xxx
  int            special;              // Extension of type, one of MSP_xxx
  ulong          owner;                // Address of owner of the memory
  ulong          initaccess;           // Initial read/write access
  ulong          access;               // Actual status and read/write access
  ulong          threadid;             // Block belongs to this thread or 0
  wchar_t        sectname[SHORTNAME];  // Null-terminated section name
  uchar          *copy;                // Copy used in CPU window or NULL
  uchar          *decode;              // Decoding information or NULL
} t_memory;

stdapi (void)    Flushmemorycache(void);
stdapi (ulong)   Readmemory(void *buf,ulong addr,ulong size,int mode);
stdapi (ulong)   Readmemoryex(void *buf,ulong addr,ulong size,int mode,
                   ulong threadid);
stdapi (ulong)   Writememory(const void *buf,ulong addr,ulong size,int mode);
stdapi (t_memory *) Findmemory(ulong addr);
stdapi (uchar *) Finddecode(ulong addr,ulong *psize);
stdapi (int)     Guardmemory(ulong base,ulong size,int guard);
stdapi (int)     Listmemory(void);
stdapi (HGLOBAL) Copymemoryhex(ulong addr,ulong size);
stdapi (int)     Pastememoryhex(ulong addr,ulong size,
                   int ensurebackup,int removeanalysis);
stdapi (int)     Editmemory(HWND hparent,ulong addr,ulong size,
                   int ensurebackup,int removeanalysis,int x,int y,int font);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// JUMP DATA ///////////////////////////////////

// Types of recognized jumps and calls.
#define JT_TYPE        0x000F          // Mask to extract data type
#define   JT_UNDEF     0x0000          // End of jump table
#define   JT_JUMP      0x0001          // Unconditional jump
#define   JT_COND      0x0002          // Conditional jump
#define   JT_SWITCH    0x0003          // Jump via switch table
#define   JT_RET       0x0004          // RET misused as jump
#define   JT_CALL      0x0005          // Call
#define   JT_SWCALL    0x0006          // Call via switch table
#define   JT_NETJUMP   0x0008          // Unconditional jump in CIL code
#define   JT_NETCOND   0x0009          // Conditional jump in CIL code
#define   JT_NETSW     0x000A          // Switch jump in CIL code
// Used as flag to Addjump, absent in the jump table.
#define JT_NOSORT      0x8000          // Do not sort data implicitly

// Note that these macros work both with t_jmp and t_jmpcall.
#define Isjump(jmp)    (((jmp)->type>=JT_JUMP && (jmp)->type<=JT_RET) ||       \
                       ((jmp)->type>=JT_NETJUMP && (jmp)->type<=JT_NETSW))
#define Iscall(jmp)    ((jmp)->type==JT_CALL || (jmp)->type==JT_SWCALL)

typedef struct t_jmp {                 // Descriptor of recognized jump or call
  ulong          from;                 // Address of jump/call command
  ulong          dest;                 // Adress of jump/call destination
  uchar          type;                 // Jump/call type, one of JT_xxx
} t_jmp;

typedef struct t_exe {                 // Description of executable module
  ulong          base;                 // Module base
  ulong          size;                 // Module size
  int            adjusted;             // Whether base is already adjusted
  wchar_t        path[MAXPATH];        // Full module path
} t_exe;

typedef struct t_jmpdata {             // Jump table
  ulong          modbase;              // Base of module owning jump table
  ulong          modsize;              // Size of module owning jump table
  t_jmp          *jmpdata;             // Jump data, sorted by source
  int            *jmpindex;            // Indices to jmpdata, sorted by dest
  int            maxjmp;               // Total number of elements in arrays
  int            njmp;                 // Number of used elements in arrays
  int            nsorted;              // Number of sorted elements in arrays
  int            dontsort;             // Do not sort data implicitly
  t_exe          *exe;                 // Pointed modules, unsorted
  int            maxexe;               // Allocated number of elements in exe
  int            nexe;                 // Number of used elements in exe
} t_jmpdata;

typedef struct t_jmpcall {             // Descriptor of found jump or call
  ulong          addr;                 // Source or destination address
  union {
    int          type;                 // Jump/call type, one of JT_xxx
    ulong        swcase;               // First switch case
  };
} t_jmpcall;

stdapi (int)     Addjump(t_jmpdata *pdat,ulong from,ulong dest,int type);
stdapi (void)    Sortjumpdata(t_jmpdata *pdat);
stdapi (t_jmp *) Findjumpfrom(ulong from);
stdapi (int)     Findlocaljumpsto(ulong dest,ulong *buf,int nbuf);
stdapi (int)     Findlocaljumpscallsto(ulong dest,t_jmpcall *jmpcall,
                   int njmpcall);
stdapi (int)     Arelocaljumpscallstorange(ulong addr0,ulong addr1);
stdapi (int)     Findglobalcallsto(ulong dest,ulong *buf,int nbuf);
stdapi (int)     Findglobaljumpscallsto(ulong dest,t_jmpcall *jmpcall,
                   int njmpcall);


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// SETS OF RANGES ////////////////////////////////

typedef struct t_range {
  ulong        rmin;                   // Low range limit
  ulong        rmax;                   // High range limit (INCLUDED!)
} t_range;

stdapi (int)     Initset(t_range *set,ulong nmax);
stdapi (int)     Fullrange(t_range *set);
stdapi (int)     Emptyrange(t_range *set);
stdapi (ulong)   Getsetcount(const t_range *set);
stdapi (int)     Getrangecount(const t_range *set);
stdapi (int)     Isinset(const t_range *set,ulong value);
stdapi (int)     Getrangebymember(const t_range *set,ulong value,
                   ulong *rmin,ulong *rmax);
stdapi (int)     Getrangebyindex(const t_range *set,int index,
                   ulong *rmin,ulong *rmax);
stdapi (int)     Addrange(t_range *set,ulong rmin,ulong rmax);
stdapi (int)     Removerange(t_range *set,ulong rmin,ulong rmax);


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// NESTED DATA //////////////////////////////////

// General item types related to nested data.
#define ND_LEVELMASK   0x000000FF      // Mask to extract nesting level
#define ND_OPENTOP     0x00000100      // Range is open on the top
#define ND_OPENBOTTOM  0x00000200      // Range is open on the bottom
#define ND_NESTHILITE  0x00000400      // Highlighted bracket
#define ND_NESTGRAY    0x00000800      // Grayed bracket
// Types specific to loop data t_loopnest:
#define ND_MOREVARS    0x00010000      // List of loop variables overflowed

#define MAXNEST        32              // Limit of displayed nesting levels

typedef struct t_nesthdr {             // Header of nested data range
  ulong          addr0;                // First address occupied by range
  ulong          addr1;                // Last occupied address (included!)
  ulong          type;                 // Level and user-defined type, TY_xxx
  ulong          aprev;                // First address of previous range
} t_nesthdr;

typedef void NDDEST(t_nesthdr *);

typedef struct t_nested {              // Descriptor of nested data
  int            n;                    // Actual number of elements
  int            nmax;                 // Maximal number of elements
  ulong          itemsize;             // Size of single element
  void           *data;                // Ordered nested data
  ulong          version;              // Changes on each modification
  NDDEST         *destfunc;            // Destructor function or NULL
} t_nested;

stdapi (void)    Destroynesteddata(t_nested *nd);
stdapi (int)     Createnesteddata(t_nested *nd,ulong itemsize,int nexp,
                   NDDEST *destfunc);
stdapi (void *)  Addnesteddata(t_nested *nd,void *item);
stdapi (void)    Deletenestedrange(t_nested *nd,ulong addr0,ulong addr1);
stdapi (int)     Getnestingpattern(t_nested *nd,ulong addr,wchar_t *pat,
                   int npat,uchar *mask,int showentry,int *isend);
stdapi (int)     Getnestingdepth(t_nested *nd,ulong addr);
stdapi (void *)  Findnesteddata(t_nested *nd,ulong addr,int level);

stdapi (void *)  Nesteddatatoudd(t_nested *nd,ulong base,ulong *datasize);
stdapi (int)     Uddtonesteddata(t_nested *nd,void *data,ulong base,ulong size);


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// MODULES ////////////////////////////////////

#define SHT_MERGENEXT  0x00000001      // Merge section with the next

#define NCALLMOD       24              // Max number of saved called modules

// .NET stream identifiers. Don't change the order and the values of the
// first three items (NS_STRINGS, NS_GUID and NS_BLOB)!
#define NS_STRINGS     0               // Stream with ASCII strings
#define NS_GUID        1               // Stream with GUIDs
#define NS_BLOB        2               // Data referenced by MetaData
#define NS_US          3               // Stream with UNICODE strings
#define NS_META        4               // Stream with MetaData tables

#define NETSTREAM      5               // Number of default .NET streams

// Indices of .NET MetaData tables.
#define MDT_MODULE     0               // Module table
#define MDT_TYPEREF    1               // TypeRef table
#define MDT_TYPEDEF    2               // TypeDef table
#define MDT_FIELDPTR   3               // FieldPtr table
#define MDT_FIELD      4               // Field table
#define MDT_METHODPTR  5               // MethodPtr table
#define MDT_METHOD     6               // MethodDef table
#define MDT_PARAMPTR   7               // ParamPtr table
#define MDT_PARAM      8               // Param table
#define MDT_INTERFACE  9               // InterfaceImpl table
#define MDT_MEMBERREF  10              // MemberRef table
#define MDT_CONSTANT   11              // Constant table
#define MDT_CUSTATTR   12              // CustomAttribute table
#define MDT_MARSHAL    13              // FieldMarshal table
#define MDT_DECLSEC    14              // DeclSecurity table
#define MDT_CLASSLAY   15              // ClassLayout table
#define MDT_FIELDLAY   16              // FieldLayout table
#define MDT_SIGNATURE  17              // StandAloneSig table
#define MDT_EVENTMAP   18              // EventMap table
#define MDT_EVENTPTR   19              // EventPtr table
#define MDT_EVENT      20              // Event table
#define MDT_PROPMAP    21              // PropertyMap table
#define MDT_PROPPTR    22              // PropertyPtr table
#define MDT_PROPERTY   23              // Property table
#define MDT_METHSEM    24              // MethodSemantics table
#define MDT_METHIMPL   25              // MethodImpl table
#define MDT_MODREF     26              // ModuleRef table
#define MDT_TYPESPEC   27              // TypeSpec table
#define MDT_IMPLMAP    28              // ImplMap table
#define MDT_RVA        29              // FieldRVA table
#define MDT_ENCLOG     30              // ENCLog table
#define MDT_ENCMAP     31              // ENCMap table
#define MDT_ASSEMBLY   32              // Assembly table
#define MDT_ASMPROC    33              // AssemblyProcessor table
#define MDT_ASMOS      34              // AssemblyOS table
#define MDT_ASMREF     35              // AssemblyRef table
#define MDT_REFPROC    36              // AssemblyRefProcessor table
#define MDT_REFOS      37              // AssemblyRefOS table
#define MDT_FILE       38              // File table
#define MDT_EXPORT     39              // ExportedType table
#define MDT_RESOURCE   40              // ManifestResource table
#define MDT_NESTED     41              // NestedClass table
#define MDT_GENPARM    42              // GenericParam table
#define MDT_METHSPEC   43              // MethodSpec table
#define MDT_CONSTR     44              // GenericParamConstraint table
#define MDT_UNUSED     63              // Used only in midx[]

#define MDTCOUNT       64              // Number of .NET MetaData tables

typedef struct t_secthdr {             // Extract from IMAGE_SECTION_HEADER
  wchar_t        sectname[12];         // Null-terminated section name
  ulong          base;                 // Address of section in memory
  ulong          size;                 // Size of section loaded into memory
  ulong          type;                 // Set of SHT_xxx
  ulong          fileoffset;           // Offset of section in file
  ulong          rawsize;              // Size of section in file
  ulong          characteristics;      // Set of IMAGE_SCN_xxx
} t_secthdr;

typedef struct t_premod {              // Preliminary module descriptor
  ulong          base;                 // Base address of the module
  ulong          size;                 // Size of module or 1
  ulong          type;                 // Service information, TY_xxx+MOD_xxx
  ulong          entry;                // Address of <ModuleEntryPoint> or 0
  wchar_t        path[MAXPATH];        // Full name of the module
} t_premod;

typedef struct t_netstream {           // Location of default .NET stream
  ulong          base;                 // Base address in memory
  ulong          size;                 // Stream size, bytes
} t_netstream;

typedef struct t_metadata {            // Descriptor of .NET MetaData table
  ulong          base;                 // Location in memory or NULL if absent
  ulong          rowcount;             // Number of rows or 0 if absent
  ulong          rowsize;              // Size of single row, bytes, or 0
  ushort         nameoffs;             // Offset of name field
  ushort         namesize;             // Size of name or 0 if absent
} t_metadata;

typedef struct t_module {              // Descriptor of executable module
  ulong          base;                 // Base address of module
  ulong          size;                 // Size of memory occupied by module
  ulong          type;                 // Service information, TY_xxx+MOD_xxx
  wchar_t        modname[SHORTNAME];   // Short name of the module
  wchar_t        path[MAXPATH];        // Full name of the module
  wchar_t        version[TEXTLEN];     // Version of executable file
  ulong          fixupbase;            // Base of image in executable file
  ulong          codebase;             // Base address of module code block
  ulong          codesize;             // Size of module code block
  ulong          entry;                // Address of <ModuleEntryPoint> or 0
  ulong          sfxentry;             // Address of SFX-packed entry or 0
  ulong          winmain;              // Address of WinMain or 0
  ulong          database;             // Base address of module data block
  ulong          edatabase;            // Base address of export data table
  ulong          edatasize;            // Size of export data table
  ulong          idatatable;           // Base address of import data table
  ulong          iatbase;              // Base of Import Address Table
  ulong          iatsize;              // Size of IAT
  ulong          relocbase;            // Base address of relocation table
  ulong          relocsize;            // Size of relocation table
  ulong          resbase;              // Base address of resources
  ulong          ressize;              // Size of resources
  ulong          tlsbase;              // Base address of TLS directory table
  ulong          tlssize;              // Size of TLS directory table
  ulong          tlscallback;          // Address of first TLS callback or 0
  ulong          netentry;             // .NET entry (MOD_NETAPP only)
  ulong          clibase;              // .NET CLI header base (MOD_NETAPP)
  ulong          clisize;              // .NET CLI header base (MOD_NETAPP)
  t_netstream    netstr[NETSTREAM];    // Locations of default .NET streams
  t_metadata     metadata[MDTCOUNT];   // Descriptors of .NET MetaData tables
  ulong          sfxbase;              // Base of memory block with SFX
  ulong          sfxsize;              // Size of memory block with SFX
  ulong          rawhdrsize;           // Size of PE header in file
  ulong          memhdrsize;           // Size of PE header in memory
  int            nsect;                // Number of sections in the module
  t_secthdr      *sect;                // Extract from section headers
  int            nfixup;               // Number of 32-bit fixups
  ulong          *fixup;               // Array of 32-bit fixups
  t_jmpdata      jumps;                // Jumps and calls from this module
  t_nested       loopnest;             // Loop brackets
  t_nested       argnest;              // Call argument brackets
  t_simple       predict;              // Predicted ESP, EBP & results (sd_pred)
  t_sorted       strings;              // Resource strings (t_string)
  int            saveudd;              // UDD-relevant data is changed
  int            ncallmod;             // No. of called modules (max. NCALLMOD)
  wchar_t        callmod[NCALLMOD][SHORTNAME]; // List of called modules
} t_module;

// Keep t_aqueue identical with the header of t_module!
typedef struct t_aqueue {              // Descriptor of module to be analysed
  ulong          base;                 // Base address of module
  ulong          size;                 // Size of memory occupied by module
  ulong          type;                 // Service information, TY_xxx+MOD_xxx
} t_aqueue;

stdapi (t_module *) Findmodule(ulong addr);
stdapi (t_module *) Findmodulebyname(wchar_t *shortname);
stdapi (t_module *) Findmainmodule(void);
stdapi (int)     Issystem(ulong addr);
stdapi (ulong *) Findfixup(t_module *pmod,ulong addr);
stdapi (ulong)   Findfileoffset(t_module *pmod,ulong addr);
stdapi (int)     Decoderange(wchar_t *s,ulong addr,ulong size);
stdapi (int)     Getexeversion(wchar_t *path,wchar_t *version);
stdapi (int)     Getexportfrommemory(ulong addr,wchar_t *s);


////////////////////////////////////////////////////////////////////////////////
////////////////////////// LIST OF DEBUGGEE'S WINDOWS //////////////////////////

typedef struct t_window {              // Description of window
  ulong          hwnd;                 // Window's handle
  ulong          dummy;                // Must be 1
  ulong          type;                 // Type of window, TY_xxx+WN_xxx
  ulong          parenthw;             // Handle of parent or 0
  ulong          winproc;              // Address of WinProc or 0
  ulong          threadid;             // ID of the owning thread
  ulong          exstyle;              // Extended style
  ulong          style;                // Style
  ulong          id;                   // Identifier
  ulong          classproc;            // Address of default (class) WinProc
  RECT           windowrect;           // Window position, screen coordinates
  RECT           clientrect;           // Client position, screen coordinates
  int            child;                // Index of next child
  int            sibling;              // Index of next sibling
  int            byparent;             // Index when sorted by parent
  int            level;                // Level in genealogy (0: topmost)
  wchar_t        title[TEXTLEN];       // Window's title or text
  wchar_t        classname[TEXTLEN];   // Class name
  wchar_t        tree[MAXNEST];        // Tree display
} t_window;


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// NAMELIST WINDOWS ///////////////////////////////

// Types of action in WM_USER_NAMES broadcasts (parameter wp).
#define NA_FIND        0               // Check if namelist is already open
#define NA_UPDATE      1               // Update namelist
#define NA_CLOSE       2               // Close namelist
#define NA_CLOSEALL    3               // Close all namelists

typedef struct t_namecast {            // Structure passed on broadcast
  ulong          base;                 // Module base, 0 - list of all names
  t_table        *table;               // Filled when broadcast stops
} t_namecast;

typedef struct t_namelist {            // Element of namelist sorted data
  ulong          addr;                 // Base address of the entry
  ulong          size;                 // Size of the entry, always 1
  ulong          type;                 // Type & addr extension, TY_xxx+NL_xxx
} t_namelist;


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// RESOURCES ///////////////////////////////////

typedef struct t_string {              // Descriptor of resource string
  ulong          id;                   // Identifier associated with the string
  ulong          dummy;                // Always 1
  ulong          addr;                 // Address of string in memory
  ulong          count;                // String size, UNICODE characters!
  int            language;             // Language, one of LANG_xxx
} t_string;

stdapi (int)     Getmodulestring(t_module *pm,ulong id,wchar_t *s);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// UDD FILES ///////////////////////////////////

#define SAVEMAGIC      0xFEDCBA98      // Indicator of savearea validity

// Attention, for the sake of the compatibility between the different OllyDbg
// versions, never, ever change existing elements, only add new!
typedef struct t_savearea {
  ulong          magic;                // Validity marker, must be SAVEMAGIC
  wchar_t        dumpstr[SHORTNAME];   // Last structure decoding in dump
} t_savearea;


////////////////////////////////////////////////////////////////////////////////
//////////////////////////// THREADS AND REGISTERS /////////////////////////////

#define NREG           8               // Number of registers (of any type)
#define NSEG           6               // Number of valid segment registers
#define NHARD          4               // Number of hardware breakpoints

// Event ignoring list.
#define IGNO_INT3      0x00000001      // Ignore INT3 breakpoint
#define IGNO_ACCESS    0x00000002      // Ignore memory access violation
#define IGNO_HW        0x00000004      // Ignore hardware breakpoint

// Register displaying mode.
#define RDM_MODE       0x0000000F      // Mask to extract display mode
#define   RDM_FPU      0x00000000      // Decode FPU registers as floats
#define   RDM_MMX      0x00000001      // Decode FPU registers as MMX
#define   RDM_3DN      0x00000002      // Decode FPU registers as 3DNow!
#define   RDM_DBG      0x00000003      // Decode debug registers instead of FPU
#define RDM_SSEMODE    0x000000F0      // Mask to extract SSE decoding mode
#define   RDM_SSEI32   0x00000000      // Decode SSE as 4x32-bit hex numbers
#define   RDM_SSEF32   0x00000010      // Decode SSE as 4x32-bit floats
#define   RDM_SSEF64   0x00000020      // Decode SSE as 2x64-bit floats

// Status of registers.
#define RV_MODIFIED    0x00000001      // Update CONTEXT before run
#define RV_USERMOD     0x00000002      // Registers modified by user
#define RV_SSEVALID    0x00000004      // Whether SSE registers are valid
#define RV_SSEMOD      0x00000008      // Update SSE registers before run
#define RV_ERRVALID    0x00000010      // Whether last thread error is valid
#define RV_ERRMOD      0x00000020      // Update last thread error before run
#define RV_MEMVALID    0x00000040      // Whether memory fields are valid
#define RV_DBGMOD      0x00000080      // Update debugging registers before run

// CPU flags.
#define FLAG_C         0x00000001      // Carry flag
#define FLAG_P         0x00000004      // Parity flag
#define FLAG_A         0x00000010      // Auxiliary carry flag
#define FLAG_Z         0x00000040      // Zero flag
#define FLAG_S         0x00000080      // Sign flag
#define FLAG_T         0x00000100      // Single-step trap flag
#define FLAG_D         0x00000400      // Direction flag
#define FLAG_O         0x00000800      // Overflow flag

// Attention, number of memory fields is limited by the run trace!
#define NMEMFIELD      2               // Number of memory fields in t_reg

typedef struct t_memfield {            // Descriptor of memory field
  ulong          addr;                 // Address of data in memory
  ulong          size;                 // Data size (0 - no data)
  uchar          data[16];             // Data
} t_memfield;

// Thread registers.
typedef struct t_reg {                 // Excerpt from context
  ulong          status;               // Status of registers, set of RV_xxx
  ulong          threadid;             // ID of thread that owns registers
  ulong          ip;                   // Instruction pointer (EIP)
  ulong          r[NREG];              // EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
  ulong          flags;                // Flags
  ulong          s[NSEG];              // Segment registers ES,CS,SS,DS,FS,GS
  ulong          base[NSEG];           // Segment bases
  ulong          limit[NSEG];          // Segment limits
  uchar          big[NSEG];            // Default size (0-16, 1-32 bit)
  uchar          dummy[2];             // Reserved, used for data alignment
  int            top;                  // Index of top-of-stack
  long double    f[NREG];              // Float registers, f[top] - top of stack
  uchar          tag[NREG];            // Float tags (0x3 - empty register)
  ulong          fst;                  // FPU status word
  ulong          fcw;                  // FPU control word
  ulong          ferrseg;              // Selector of last detected FPU error
  ulong          feroffs;              // Offset of last detected FPU error
  ulong          dr[NREG];             // Debug registers
  ulong          lasterror;            // Last thread error or 0xFFFFFFFF
  uchar          ssereg[NREG][16];     // SSE registers
  ulong          mxcsr;                // SSE control and status register
  t_memfield     mem[NMEMFIELD];       // Known memory fields from run trace
} t_reg;

typedef struct t_thread {              // Information about active threads
  ulong          threadid;             // Thread identifier
  ulong          dummy;                // Always 1
  ulong          type;                 // Service information, TY_xxx+THR_xxx
  int            ordinal;              // Thread's ordinal number (1-based)
  wchar_t        name[SHORTNAME];      // Short name of the thread
  HANDLE         thread;               // Thread handle, for OllyDbg only!
  ulong          tib;                  // Thread Information Block
  ulong          entry;                // Thread entry point
  CONTEXT        context;              // Actual context of the thread
  t_reg          reg;                  // Actual contents of registers
  int            regvalid;             // Whether reg and context are valid
  t_reg          oldreg;               // Previous contents of registers
  int            oldregvalid;          // Whether oldreg is valid
  int            suspendrun;           // Suspended for run (0 or 1)
  int            suspendcount;         // Temporarily suspended (0..inf)
  int            suspenduser;          // Suspended by user (0 or 1)
  int            trapset;              // Single-step trap set by OllyDbg
  int            trapincontext;        // Trap is catched in exception context
  ulong          rtprotocoladdr;       // Address of destination to protocol
  int            ignoreonce;           // Ignore list, IGNO_xxx
  int            drvalid;              // Contents of dr is valid
  ulong          dr[NREG];             // Expected state of DR0..3,7
  int            hwmasked;             // Temporarily masked hardware breaks
  int            hwreported;           // Reported breakpoint expressions
  // Thread-related information gathered by Updatethreaddata().
  HWND           hw;                   // One of windows owned by thread
  ulong          usertime;             // Time in user mode, 100u units or -1
  ulong          systime;              // Time in system mode, 100u units or -1
  // Thread-related information gathered by Listmemory().
  ulong          stacktop;             // Top of thread's stack
  ulong          stackbottom;          // Bottom of thread's stack
} t_thread;

stdapi (t_thread *) Findthread(ulong threadid);
stdapi (t_thread *) Findthreadbyordinal(int ordinal);
stdapi (t_reg *) Threadregisters(ulong threadid);
stdapi (int)     Decodethreadname(wchar_t *s,ulong threadid,int mode);
stdapi (void)    Registermodifiedbyuser(t_thread *pthr);


////////////////////////////////////////////////////////////////////////////////
////////////////////////// ASSEMBLER AND DISASSEMBLER //////////////////////////

#define MAXCMDSIZE     16              // Maximal length of valid 80x86 command
#define MAXSEQSIZE     256             // Maximal length of command sequence
#define INT3           0xCC            // Code of 1-byte INT3 breakpoint
#define NOP            0x90            // Code of 1-byte NOP command
#define NOPERAND       4               // Maximal allowed number of operands
#define NEGLIMIT       (-16384)        // Limit to decode offsets as negative
#define DECLIMIT       65536           // Limit to decode integers as decimal

// Registers.
#define REG_UNDEF      (-1)            // Codes of general purpose registers
#define REG_EAX        0
#define REG_ECX        1
#define REG_EDX        2
#define REG_EBX        3
#define REG_ESP        4
#define REG_EBP        5
#define REG_ESI        6
#define REG_EDI        7

#define REG_BYTE       0x80            // Flag used in switch analysis

#define REG_AL         0               // Symbolic indices of 8-bit registers
#define REG_CL         1
#define REG_DL         2
#define REG_BL         3
#define REG_AH         4
#define REG_CH         5
#define REG_DH         6
#define REG_BH         7

#define SEG_UNDEF      (-1)            // Codes of segment/selector registers
#define SEG_ES         0
#define SEG_CS         1
#define SEG_SS         2
#define SEG_DS         3
#define SEG_FS         4
#define SEG_GS         5

// Pseudoregisters, used in search for assembler commands.
#define REG_R8         NREG            // 8-bit pseudoregister R8
#define REG_R16        NREG            // 16-bit pseudoregister R16
#define REG_R32        NREG            // 32-bit pseudoregister R32
#define REG_ANY        NREG            // Pseudoregister FPUREG, MMXREG etc.
#define SEG_ANY        NREG            // Segment pseudoregister SEG
#define REG_RA         (NREG+1)        // 32-bit semi-defined pseudoregister RA
#define REG_RB         (NREG+2)        // 32-bit semi-defined pseudoregister RB

#define NPSEUDO        (NREG+3)        // Total count of resisters & pseudoregs

#define IS_REAL(r)     ((r)<REG_R32)   // Checks for real register
#define IS_PSEUDO(r)   ((r)>=REG_R32)  // Checks for pseudoregister (undefined)
#define IS_SEMI(r)     ((r)>=REG_RA)   // Checks for semi-defined register

#define D_NONE         0x00000000      // No special features
// General type of command, only one is allowed.
#define D_CMDTYPE      0x0000001F      // Mask to extract type of command
#define   D_CMD        0x00000000      // Ordinary (none of listed below)
#define   D_MOV        0x00000001      // Move to or from integer register
#define   D_MOVC       0x00000002      // Conditional move to integer register
#define   D_SETC       0x00000003      // Conditional set integer register
#define   D_TEST       0x00000004      // Used to test data (CMP, TEST, AND...)
#define   D_STRING     0x00000005      // String command with REPxxx prefix
#define   D_JMP        0x00000006      // Unconditional near jump
#define   D_JMPFAR     0x00000007      // Unconditional far jump
#define   D_JMC        0x00000008      // Conditional jump on flags
#define   D_JMCX       0x00000009      // Conditional jump on (E)CX (and flags)
#define   D_PUSH       0x0000000A      // PUSH exactly 1 (d)word of data
#define   D_POP        0x0000000B      // POP exactly 1 (d)word of data
#define   D_CALL       0x0000000C      // Plain near call
#define   D_CALLFAR    0x0000000D      // Far call
#define   D_INT        0x0000000E      // Interrupt
#define   D_RET        0x0000000F      // Plain near return from call
#define   D_RETFAR     0x00000010      // Far return or IRET
#define   D_FPU        0x00000011      // FPU command
#define   D_MMX        0x00000012      // MMX instruction, incl. SSE extensions
#define   D_3DNOW      0x00000013      // 3DNow! instruction
#define   D_SSE        0x00000014      // SSE, SSE2, SSE3 etc. instruction
#define   D_IO         0x00000015      // Accesses I/O ports
#define   D_SYS        0x00000016      // Legal but useful in system code only
#define   D_PRIVILEGED 0x00000017      // Privileged (non-Ring3) command
#define   D_DATA       0x0000001C      // Data recognized by Analyser
#define   D_PSEUDO     0x0000001D      // Pseudocommand, for search models only
#define   D_PREFIX     0x0000001E      // Standalone prefix
#define   D_BAD        0x0000001F      // Bad or unrecognized command
// Additional parts of the command.
#define D_SIZE01       0x00000020      // Bit 0x01 in last cmd is data size
#define D_POSTBYTE     0x00000040      // Command continues in postbyte
// For string commands, either long or short form can be selected.
#define D_LONGFORM     0x00000080      // Long form of string command
// Decoding of some commands depends on data or address size.
#define D_SIZEMASK     0x00000F00      // Mask for data/address size dependence
#define   D_DATA16     0x00000100      // Requires 16-bit data size
#define   D_DATA32     0x00000200      // Requires 32-bit data size
#define   D_ADDR16     0x00000400      // Requires 16-bit address size
#define   D_ADDR32     0x00000800      // Requires 32-bit address size
// Prefixes that command may, must or must not possess.
#define D_MUSTMASK     0x0000F000      // Mask for fixed set of prefixes
#define   D_NOMUST     0x00000000      // No obligatory prefixes (default)
#define   D_MUST66     0x00001000      // (SSE) Requires 66, no F2 or F3
#define   D_MUSTF2     0x00002000      // (SSE) Requires F2, no 66 or F3
#define   D_MUSTF3     0x00003000      // (SSE) Requires F3, no 66 or F2
#define   D_MUSTNONE   0x00004000      // (MMX,SSE) Requires no 66, F2 or F3
#define   D_NEEDF2     0x00005000      // (SSE) Requires F2, no F3
#define   D_NEEDF3     0x00006000      // (SSE) Requires F3, no F2
#define   D_NOREP      0x00007000      // Must not include F2 or F3
#define   D_MUSTREP    0x00008000      // Must include F3 (REP)
#define   D_MUSTREPE   0x00009000      // Must include F3 (REPE)
#define   D_MUSTREPNE  0x0000A000      // Must include F2 (REPNE)
#define D_LOCKABLE     0x00010000      // Allows for F0 (LOCK, memory only)
#define D_BHINT        0x00020000      // Allows for branch hints (2E, 3E)
// Decoding of some commands with ModRM-SIB depends whether register or memory.
#define D_MEMORY       0x00040000      // Mod field must indicate memory
#define D_REGISTER     0x00080000      // Mod field must indicate register
// Side effects caused by command.
#define D_FLAGMASK     0x00700000      // Mask to extract modified flags
#define   D_NOFLAGS    0x00000000      // Flags S,Z,P,O,C remain unchanged
#define   D_ALLFLAGS   0x00100000      // Modifies flags S,Z,P,O,C
#define   D_FLAGZ      0x00200000      // Modifies flag Z only
#define   D_FLAGC      0x00300000      // Modifies flag C only
#define   D_FLAGSCO    0x00400000      // Modifies flag C and O only
#define   D_FLAGD      0x00500000      // Modifies flag D only
#define   D_FLAGSZPC   0x00600000      // Modifies flags Z, P and C only (FPU)
#define   D_NOCFLAG    0x00700000      // S,Z,P,O modified, C unaffected
#define D_FPUMASK      0x01800000      // Mask for effects on FPU stack
#define   D_FPUSAME    0x00000000      // Doesn't rotate FPU stack (default)
#define   D_FPUPOP     0x00800000      // Pops FPU stack
#define   D_FPUPOP2    0x01000000      // Pops FPU stack twice
#define   D_FPUPUSH    0x01800000      // Pushes FPU stack
#define D_CHGESP       0x02000000      // Command indirectly modifies ESP
// Command features.
#define D_HLADIR       0x04000000      // Nonstandard order of operands in HLA
#define D_WILDCARD     0x08000000      // Mnemonics contains W/D wildcard ('*')
#define D_COND         0x10000000      // Conditional (action depends on flags)
#define D_USESCARRY    0x20000000      // Uses Carry flag
#define D_USEMASK      0xC0000000      // Mask to detect unusual commands
#define   D_RARE       0x40000000      // Rare or obsolete in Win32 apps
#define   D_SUSPICIOUS 0x80000000      // Suspicious command
#define   D_UNDOC      0xC0000000      // Undocumented command

// Extension of D_xxx.
#define DX_ZEROMASK    0x00000003      // How to decode FLAGS.Z flag
#define   DX_JE        0x00000001      // JE, JNE instead of JZ, JNZ
#define   DX_JZ        0x00000002      // JZ, JNZ instead of JE, JNE
#define DX_CARRYMASK   0x0000000C      // How to decode FLAGS.C flag
#define   DX_JB        0x00000004      // JAE, JB instead of JC, JNC
#define   DX_JC        0x00000008      // JC, JNC instead of JAE, JB
#define DX_WONKYTRAP   0x00000100      // Don't single-step this command

// Type of operand, only one is allowed.
#define B_ARGMASK      0x000000FF      // Mask to extract type of argument
#define   B_NONE       0x00000000      // Operand absent
#define   B_AL         0x00000001      // Register AL
#define   B_AH         0x00000002      // Register AH
#define   B_AX         0x00000003      // Register AX
#define   B_CL         0x00000004      // Register CL
#define   B_CX         0x00000005      // Register CX
#define   B_DX         0x00000006      // Register DX
#define   B_DXPORT     0x00000007      // Register DX as I/O port address
#define   B_EAX        0x00000008      // Register EAX
#define   B_EBX        0x00000009      // Register EBX
#define   B_ECX        0x0000000A      // Register ECX
#define   B_EDX        0x0000000B      // Register EDX
#define   B_ACC        0x0000000C      // Accumulator (AL/AX/EAX)
#define   B_STRCNT     0x0000000D      // Register CX or ECX as REPxx counter
#define   B_DXEDX      0x0000000E      // Register DX or EDX in DIV/MUL
#define   B_BPEBP      0x0000000F      // Register BP or EBP in ENTER/LEAVE
#define   B_REG        0x00000010      // 8/16/32-bit register in Reg
#define   B_REG16      0x00000011      // 16-bit register in Reg
#define   B_REG32      0x00000012      // 32-bit register in Reg
#define   B_REGCMD     0x00000013      // 16/32-bit register in last cmd byte
#define   B_REGCMD8    0x00000014      // 8-bit register in last cmd byte
#define   B_ANYREG     0x00000015      // Reg field is unused, any allowed
#define   B_INT        0x00000016      // 8/16/32-bit register/memory in ModRM
#define   B_INT8       0x00000017      // 8-bit register/memory in ModRM
#define   B_INT16      0x00000018      // 16-bit register/memory in ModRM
#define   B_INT32      0x00000019      // 32-bit register/memory in ModRM
#define   B_INT1632    0x0000001A      // 16/32-bit register/memory in ModRM
#define   B_INT64      0x0000001B      // 64-bit integer in ModRM, memory only
#define   B_INT128     0x0000001C      // 128-bit integer in ModRM, memory only
#define   B_IMMINT     0x0000001D      // 8/16/32-bit int at immediate addr
#define   B_INTPAIR    0x0000001E      // Two signed 16/32 in ModRM, memory only
#define   B_SEGOFFS    0x0000001F      // 16:16/16:32 absolute address in memory
#define   B_STRDEST    0x00000020      // 8/16/32-bit string dest, [ES:(E)DI]
#define   B_STRDEST8   0x00000021      // 8-bit string destination, [ES:(E)DI]
#define   B_STRSRC     0x00000022      // 8/16/32-bit string source, [(E)SI]
#define   B_STRSRC8    0x00000023      // 8-bit string source, [(E)SI]
#define   B_XLATMEM    0x00000024      // 8-bit memory in XLAT, [(E)BX+AL]
#define   B_EAXMEM     0x00000025      // Reference to memory addressed by [EAX]
#define   B_LONGDATA   0x00000026      // Long data in ModRM, mem only
#define   B_ANYMEM     0x00000027      // Reference to memory, data unimportant
#define   B_STKTOP     0x00000028      // 16/32-bit int top of stack
#define   B_STKTOPFAR  0x00000029      // Top of stack (16:16/16:32 far addr)
#define   B_STKTOPEFL  0x0000002A      // 16/32-bit flags on top of stack
#define   B_STKTOPA    0x0000002B      // 16/32-bit top of stack all registers
#define   B_PUSH       0x0000002C      // 16/32-bit int push to stack
#define   B_PUSHRET    0x0000002D      // 16/32-bit push of return address
#define   B_PUSHRETF   0x0000002E      // 16:16/16:32-bit push of far retaddr
#define   B_PUSHA      0x0000002F      // 16/32-bit push all registers
#define   B_EBPMEM     0x00000030      // 16/32-bit int at [EBP]
#define   B_SEG        0x00000031      // Segment register in Reg
#define   B_SEGNOCS    0x00000032      // Segment register in Reg, but not CS
#define   B_SEGCS      0x00000033      // Segment register CS
#define   B_SEGDS      0x00000034      // Segment register DS
#define   B_SEGES      0x00000035      // Segment register ES
#define   B_SEGFS      0x00000036      // Segment register FS
#define   B_SEGGS      0x00000037      // Segment register GS
#define   B_SEGSS      0x00000038      // Segment register SS
#define   B_ST         0x00000039      // 80-bit FPU register in last cmd byte
#define   B_ST0        0x0000003A      // 80-bit FPU register ST0
#define   B_ST1        0x0000003B      // 80-bit FPU register ST1
#define   B_FLOAT32    0x0000003C      // 32-bit float in ModRM, memory only
#define   B_FLOAT64    0x0000003D      // 64-bit float in ModRM, memory only
#define   B_FLOAT80    0x0000003E      // 80-bit float in ModRM, memory only
#define   B_BCD        0x0000003F      // 80-bit BCD in ModRM, memory only
#define   B_MREG8x8    0x00000040      // MMX register as 8 8-bit integers
#define   B_MMX8x8     0x00000041      // MMX reg/memory as 8 8-bit integers
#define   B_MMX8x8DI   0x00000042      // MMX 8 8-bit integers at [DS:(E)DI]
#define   B_MREG16x4   0x00000043      // MMX register as 4 16-bit integers
#define   B_MMX16x4    0x00000044      // MMX reg/memory as 4 16-bit integers
#define   B_MREG32x2   0x00000045      // MMX register as 2 32-bit integers
#define   B_MMX32x2    0x00000046      // MMX reg/memory as 2 32-bit integers
#define   B_MREG64     0x00000047      // MMX register as 1 64-bit integer
#define   B_MMX64      0x00000048      // MMX reg/memory as 1 64-bit integer
#define   B_3DREG      0x00000049      // 3DNow! register as 2 32-bit floats
#define   B_3DNOW      0x0000004A      // 3DNow! reg/memory as 2 32-bit floats
#define   B_XMM0I32x4  0x0000004B      // XMM0 as 4 32-bit integers
#define   B_XMM0I64x2  0x0000004C      // XMM0 as 2 64-bit integers
#define   B_XMM0I8x16  0x0000004D      // XMM0 as 16 8-bit integers
#define   B_SREGF32x4  0x0000004E      // SSE register as 4 32-bit floats
#define   B_SREGF32L   0x0000004F      // Low 32-bit float in SSE register
#define   B_SREGF32x2L 0x00000050      // Low 2 32-bit floats in SSE register
#define   B_SSEF32x4   0x00000051      // SSE reg/memory as 4 32-bit floats
#define   B_SSEF32L    0x00000052      // Low 32-bit float in SSE reg/memory
#define   B_SSEF32x2L  0x00000053      // Low 2 32-bit floats in SSE reg/memory
#define   B_SREGF64x2  0x00000054      // SSE register as 2 64-bit floats
#define   B_SREGF64L   0x00000055      // Low 64-bit float in SSE register
#define   B_SSEF64x2   0x00000056      // SSE reg/memory as 2 64-bit floats
#define   B_SSEF64L    0x00000057      // Low 64-bit float in SSE reg/memory
#define   B_SREGI8x16  0x00000058      // SSE register as 16 8-bit sigints
#define   B_SSEI8x16   0x00000059      // SSE reg/memory as 16 8-bit sigints
#define   B_SSEI8x16DI 0x0000005A      // SSE 16 8-bit sigints at [DS:(E)DI]
#define   B_SSEI8x8L   0x0000005B      // Low 8 8-bit ints in SSE reg/memory
#define   B_SSEI8x4L   0x0000005C      // Low 4 8-bit ints in SSE reg/memory
#define   B_SSEI8x2L   0x0000005D      // Low 2 8-bit ints in SSE reg/memory
#define   B_SREGI16x8  0x0000005E      // SSE register as 8 16-bit sigints
#define   B_SSEI16x8   0x0000005F      // SSE reg/memory as 8 16-bit sigints
#define   B_SSEI16x4L  0x00000060      // Low 4 16-bit ints in SSE reg/memory
#define   B_SSEI16x2L  0x00000061      // Low 2 16-bit ints in SSE reg/memory
#define   B_SREGI32x4  0x00000062      // SSE register as 4 32-bit sigints
#define   B_SREGI32L   0x00000063      // Low 32-bit sigint in SSE register
#define   B_SREGI32x2L 0x00000064      // Low 2 32-bit sigints in SSE register
#define   B_SSEI32x4   0x00000065      // SSE reg/memory as 4 32-bit sigints
#define   B_SSEI32x2L  0x00000066      // Low 2 32-bit sigints in SSE reg/memory
#define   B_SREGI64x2  0x00000067      // SSE register as 2 64-bit sigints
#define   B_SSEI64x2   0x00000068      // SSE reg/memory as 2 64-bit sigints
#define   B_SREGI64L   0x00000069      // Low 64-bit sigint in SSE register
#define   B_EFL        0x0000006A      // Flags register EFL
#define   B_FLAGS8     0x0000006B      // Flags (low byte)
#define   B_OFFSET     0x0000006C      // 16/32 const offset from next command
#define   B_BYTEOFFS   0x0000006D      // 8-bit sxt const offset from next cmd
#define   B_FARCONST   0x0000006E      // 16:16/16:32 absolute address constant
#define   B_DESCR      0x0000006F      // 16:32 descriptor in ModRM
#define   B_1          0x00000070      // Immediate constant 1
#define   B_CONST8     0x00000071      // Immediate 8-bit constant
#define   B_CONST8_2   0x00000072      // Immediate 8-bit const, second in cmd
#define   B_CONST16    0x00000073      // Immediate 16-bit constant
#define   B_CONST      0x00000074      // Immediate 8/16/32-bit constant
#define   B_CONSTL     0x00000075      // Immediate 16/32-bit constant
#define   B_SXTCONST   0x00000076      // Immediate 8-bit sign-extended to size
#define   B_CR         0x00000077      // Control register in Reg
#define   B_CR0        0x00000078      // Control register CR0
#define   B_DR         0x00000079      // Debug register in Reg
// Type modifiers, used for interpretation of contents, only one is allowed.
#define B_MODMASK      0x000F0000      // Mask to extract type modifier
#define   B_NONSPEC    0x00000000      // Non-specific operand
#define   B_UNSIGNED   0x00010000      // Decode as unsigned decimal
#define   B_SIGNED     0x00020000      // Decode as signed decimal
#define   B_BINARY     0x00030000      // Decode as binary (full hex) data
#define   B_BITCNT     0x00040000      // Bit count
#define   B_SHIFTCNT   0x00050000      // Shift count
#define   B_COUNT      0x00060000      // General-purpose count
#define   B_NOADDR     0x00070000      // Not an address
#define   B_JMPCALL    0x00080000      // Near jump/call/return destination
#define   B_JMPCALLFAR 0x00090000      // Far jump/call/return destination
#define   B_STACKINC   0x000A0000      // Unsigned stack increment/decrement
#define   B_PORT       0x000B0000      // I/O port
// Validity markers.
#define B_MEMORY       0x00100000      // Memory only, reg version different
#define B_REGISTER     0x00200000      // Register only, mem version different
#define B_MEMONLY      0x00400000      // Warn if operand in register
#define B_REGONLY      0x00800000      // Warn if operand in memory
#define B_32BITONLY    0x01000000      // Warn if 16-bit operand
#define B_NOESP        0x02000000      // ESP is not allowed
// Miscellaneous options.
#define B_SHOWSIZE     0x08000000      // Always show argument size in disasm
#define B_CHG          0x10000000      // Changed, old contents is not used
#define B_UPD          0x20000000      // Modified using old contents
#define B_PSEUDO       0x40000000      // Pseoudooperand, not in assembler cmd
#define B_NOSEG        0x80000000      // Don't add offset of selector

// Analysis data. Note that DEC_PBODY==DEC_PROC|DEC_PEND; this allows for
// automatical merging of overlapping procedures. Also note that DEC_NET is
// followed, if necessary, by a sequence of DEC_NEXTDATA and not DEC_NEXTCODE!
#define DEC_TYPEMASK   0x1F            // Type of analyzed byte
#define   DEC_UNKNOWN  0x00            // Not analyzed, treat as command
#define   DEC_NEXTCODE 0x01            // Next byte of command
#define   DEC_NEXTDATA 0x02            // Next byte of data
#define   DEC_FILLDATA 0x03            // Not recognized, treat as byte data
#define   DEC_INT      0x04            // First byte of integer
#define   DEC_SWITCH   0x05            // First byte of switch item or count
#define   DEC_DATA     0x06            // First byte of integer data
#define   DEC_DB       0x07            // First byte of byte string
#define   DEC_DUMP     0x08            // First byte of byte string with dump
#define   DEC_ASCII    0x09            // First byte of ASCII string
#define   DEC_ASCCNT   0x0A            // Next chunk of ASCII string
#define   DEC_UNICODE  0x0B            // First byte of UNICODE string
#define   DEC_UNICNT   0x0C            // Next chunk of UNICODE string
#define   DEC_FLOAT    0x0D            // First byte of floating number
#define   DEC_GUID     0x10            // First byte of GUID
#define   DEC_NETCMD   0x18            // First byte of .NET (CIL) command
#define   DEC_JMPNET   0x19            // First byte of .NET at jump destination
#define   DEC_CALLNET  0x1A            // First byte of .NET at call destination
#define   DEC_COMMAND  0x1C            // First byte of ordinary command
#define   DEC_JMPDEST  0x1D            // First byte of cmd at jump destination
#define   DEC_CALLDEST 0x1E            // First byte of cmd at call destination
#define   DEC_FILLING  0x1F            // Command used to fill gaps
#define DEC_PROCMASK   0x60            // Procedure analysis
#define   DEC_NOPROC   0x00            // Outside the procedure
#define   DEC_PROC     0x20            // Start of procedure
#define   DEC_PEND     0x40            // End of procedure
#define   DEC_PBODY    0x60            // Body of procedure
#define DEC_TRACED     0x80            // Hit when traced

// Full type of predicted data.
#define PST_GENMASK    0xFFFFFC00      // Mask for ESP generation
#define   PST_GENINC   0x00000400      // Increment of ESP generation
#define PST_UNCERT     0x00000200      // Uncertain, probably modified by call
#define PST_NONSTACK   0x00000100      // Not a stack, internal use only
#define PST_REL        0x00000080      // Fixup/reladdr counter of constant
#define PST_BASE       0x0000007F      // Mask for basical description
#define   PST_SPEC     0x00000040      // Special contents, type in PST_GENMASK
#define   PST_VALID    0x00000020      // Contents valid
#define   PST_ADDR     0x00000010      // Contents is in memory
#define   PST_ORIG     0x00000008      // Based on reg contents at entry point
#define   PST_OMASK    0x00000007      // Mask to extract original register

// Types of special contents when PST_SPEC is set.
#define PSS_SPECMASK   PST_GENMASK     // Mask for type of special contents
#define   PSS_SEHPTR   0x00000400      // Pointer to SEH chain

#define NSTACK         12              // Number of predicted stack entries
#define NSTKMOD        24              // Max no. of predicted stack mod addr
#define NMEM           2               // Number of predicted memory locations

typedef struct t_modrm {               // ModRM decoding
  ulong          size;                 // Total size with SIB and disp, bytes
  struct t_modrm *psib;                // Pointer to SIB table or NULL
  ulong          dispsize;             // Size of displacement or 0 if none
  ulong          features;             // Operand features, set of OP_xxx
  int            reg;                  // Register index or REG_UNDEF
  int            defseg;               // Default selector (SEG_xxx)
  uchar          scale[NREG];          // Scales of registers in memory address
  ulong          aregs;                // List of registers used in address
  int            basereg;              // Register used as base or REG_UNDEF
  wchar_t        ardec[SHORTNAME];     // Register part of address, INTEL fmt
  wchar_t        aratt[SHORTNAME];     // Register part of address, AT&T fmt
} t_modrm;

typedef struct t_predict {             // Prediction of execution
  ulong          addr;                 // Predicted EIP or NULL if uncertain
  ulong          one;                  // Must be 1
  ulong          type;                 // Type, TY_xxx/PR_xxx
  ushort         flagsmeaning;         // Set of DX_ZEROMASK|DX_CARRYMASK
  ulong          rstate[NREG];         // State of register, set of PST_xxx
  ulong          rconst[NREG];         // Constant related to register
  ulong          jmpstate;             // State of EIP after jump or return
  ulong          jmpconst;             // Constant related to jump or return
  ulong          espatpushbp;          // Offset of ESP at PUSH EBP
  int            nstack;               // Number of valid stack entries
  struct {
    long         soffset;              // Offset of data on stack (signed!)
    ulong        sstate;               // State of stack data, set of PST_xxx
    ulong        sconst;               // Constant related to stack data
  } stack[NSTACK];
  int            nstkmod;              // Number of valid stkmod addresses
  ulong          stkmod[NSTKMOD];      // Addresses of stack modifications
  int            nmem;                 // Number of valid memory entries
  struct {
    ulong        maddr;                // Address of doubleword variable
    ulong        mstate;               // State of memory, set of PST_xxx
    ulong        mconst;               // Constant related to memory data
  } mem[NMEM];
  ulong          resstate;             // State of result of command execution
  ulong          resconst;             // Constant related to result
} t_predict;

typedef struct t_callpredict {         // Simplified prediction
  ulong          addr;                 // Predicted EIP or NULL if uncertain
  ulong          one;                  // Must be 1
  ulong          type;                 // Type of prediction, TY_xxx/PR_xxx
  ulong          eaxstate;             // State of EAX, set of PST_xxx
  ulong          eaxconst;             // Constant related to EAX
  int            nstkmod;              // Number of valid stkmod addresses
  ulong          stkmod[NSTKMOD];      // Addresses of stack modifications
  ulong          resstate;             // State of result of command execution
  ulong          resconst;             // Constant related to result
} t_callpredict;

// Location of operand, only one bit is allowed.
#define OP_SOMEREG     0x000000FF      // Mask for any kind of register
#define   OP_REGISTER  0x00000001      // Operand is a general-purpose register
#define   OP_SEGREG    0x00000002      // Operand is a segment register
#define   OP_FPUREG    0x00000004      // Operand is a FPU register
#define   OP_MMXREG    0x00000008      // Operand is a MMX register
#define   OP_3DNOWREG  0x00000010      // Operand is a 3DNow! register
#define   OP_SSEREG    0x00000020      // Operand is a SSE register
#define   OP_CREG      0x00000040      // Operand is a control register
#define   OP_DREG      0x00000080      // Operand is a debug register
#define OP_MEMORY      0x00000100      // Operand is in memory
#define OP_CONST       0x00000200      // Operand is an immediate constant
#define OP_PORT        0x00000400      // Operand is an I/O port
// Additional operand properties.
#define OP_INVALID     0x00001000      // Invalid operand, like reg in mem-only
#define OP_PSEUDO      0x00002000      // Pseudooperand (not in mnenonics)
#define OP_MOD         0x00004000      // Command may change/update operand
#define OP_MODREG      0x00008000      // Memory, but modifies reg (POP,MOVSD)
#define OP_REL         0x00010000      // Relative or fixuped const or address
#define OP_IMPORT      0x00020000      // Value imported from different module
#define OP_SELECTOR    0x00040000      // Includes immediate selector
// Additional properties of memory address.
#define OP_INDEXED     0x00080000      // Memory address contains registers
#define OP_OPCONST     0x00100000      // Memory address contains constant
#define OP_ADDR16      0x00200000      // 16-bit memory address
#define OP_ADDR32      0x00400000      // Explicit 32-bit memory address
// Value of operand.
#define OP_OFFSOK      0x00800000      // Offset to selector valid
#define OP_ADDROK      0x01000000      // Address valid
#define OP_VALUEOK     0x02000000      // Value (max. 16 bytes) valid
#define OP_PREDADDR    0x04000000      // Address predicted, not actual
#define OP_PREDVAL     0x08000000      // Value predicted, not actual
#define OP_RTLOGMEM    0x10000000      // Memory contents got from run trace
#define   OP_ACTVALID  0x20000000      // Actual value is valid
// Pseudooperands, used in assembler search models only.
#define OP_ANYMEM      0x40000000      // Any memory location
#define OP_ANY         0x80000000      // Any operand

typedef struct t_operand {             // Description of disassembled operand
  // Description of operand.
  ulong          features;             // Operand features, set of OP_xxx
  ulong          arg;                  // Operand type, set of B_xxx
  int            optype;               // DEC_INT, DEC_FLOAT or DEC_UNKNOWN
  int            opsize;               // Total size of data, bytes
  int            granularity;          // Size of element (opsize exc. MMX/SSE)
  int            reg;                  // REG_xxx (also ESP in POP) or REG_UNDEF
  ulong          uses;                 // List of used regs (not in address!)
  ulong          modifies;             // List of modified regs (not in addr!)
  // Description of memory address.
  int            seg;                  // Selector (SEG_xxx)
  uchar          scale[NREG];          // Scales of registers in memory address
  ulong          aregs;                // List of registers used in address
  ulong          opconst;              // Constant or const part of address
  // Value of operand.
  ulong          offset;               // Offset to selector (usually addr)
  ulong          selector;             // Immediate selector in far jump/call
  ulong          addr;                 // Address of operand in memory
  union {
    ulong        u;                    // Value of operand (integer form)
    signed long  s;                    // Value of operand (signed form)
    uchar        value[16]; };         // Value of operand (general form)
  uchar          actual[16];           // Actual memory (if OP_ACTVALID)
  // Textual decoding.
  wchar_t        text[TEXTLEN];        // Operand, decoded to text
  wchar_t        comment[TEXTLEN];     // Commented address and contents
} t_operand;

// Prefix list.
#define PF_SEGMASK     0x0000003F      // Mask for segment override prefixes
#define   PF_ES        0x00000001      // 0x26, ES segment override
#define   PF_CS        0x00000002      // 0x2E, CS segment override
#define   PF_SS        0x00000004      // 0x36, SS segment override
#define   PF_DS        0x00000008      // 0x3E, DS segment override
#define   PF_FS        0x00000010      // 0x64, FS segment override
#define   PF_GS        0x00000020      // 0x65, GS segment override
#define PF_DSIZE       0x00000040      // 0x66, data size override
#define PF_ASIZE       0x00000080      // 0x67, address size override
#define PF_LOCK        0x00000100      // 0xF0, bus lock
#define PF_REPMASK     0x00000600      // Mask for repeat prefixes
#define   PF_REPNE     0x00000200      // 0xF2, REPNE prefix
#define   PF_REP       0x00000400      // 0xF3, REP/REPE prefix
#define PF_BYTE        0x00000800      // Size bit in command, used in cmdexec
#define PF_MUSTMASK    D_MUSTMASK      // Necessary prefixes, used in t_asmmod
#define PF_66          PF_DSIZE        // Alternative names for SSE prefixes
#define PF_F2          PF_REPNE
#define PF_F3          PF_REP
#define PF_HINT        (PF_CS|PF_DS)   // Alternative names for branch hints
#define   PF_NOTTAKEN  PF_CS
#define   PF_TAKEN     PF_DS

// Disassembling errors.
#define DAE_NOERR      0x00000000      // No error
#define DAE_BADCMD     0x00000001      // Unrecognized command
#define DAE_CROSS      0x00000002      // Command crosses end of memory block
#define DAE_MEMORY     0x00000004      // Register where only memory allowed
#define DAE_REGISTER   0x00000008      // Memory where only register allowed
#define DAE_LOCK       0x00000010      // LOCK prefix is not allowed
#define DAE_BADSEG     0x00000020      // Invalid segment register
#define DAE_SAMEPREF   0x00000040      // Two prefixes from the same group
#define DAE_MANYPREF   0x00000080      // More than 4 prefixes
#define DAE_BADCR      0x00000100      // Invalid CR register
#define DAE_INTERN     0x00000200      // Internal error

// Disassembling warnings.
#define DAW_DATASIZE   0x00000001      // Superfluous data size prefix
#define DAW_ADDRSIZE   0x00000002      // Superfluous address size prefix
#define DAW_SEGPREFIX  0x00000004      // Superfluous segment override prefix
#define DAW_REPPREFIX  0x00000008      // Superfluous REPxx prefix
#define DAW_DEFSEG     0x00000010      // Segment prefix coincides with default
#define DAW_JMP16      0x00000020      // 16-bit jump, call or return
#define DAW_FARADDR    0x00000040      // Far jump or call
#define DAW_SEGMOD     0x00000080      // Modifies segment register
#define DAW_PRIV       0x00000100      // Privileged command
#define DAW_IO         0x00000200      // I/O command
#define DAW_SHIFT      0x00000400      // Shift out of range 1..31
#define DAW_LOCK       0x00000800      // Command with valid LOCK prefix
#define DAW_STACK      0x00001000      // Unaligned stack operation
#define DAW_NOESP      0x00002000      // Suspicious use of stack pointer
#define DAW_RARE       0x00004000      // Rare, seldom used command
#define DAW_NONCLASS   0x00008000      // Non-standard or non-documented code
#define DAW_INTERRUPT  0x00010000      // Interrupt command

// Conditions of conditional commands.
#define DAF_NOCOND     0x00000000      // Unconditional command
#define DAF_TRUE       0x00000001      // Condition is true
#define DAF_FALSE      0x00000002      // Condition is false
#define DAF_ANYCOND    0x00000003      // Condition is not predictable

typedef struct t_disasm {              // Disassembled command
  // In the case that DA_HILITE flag is set, fill these members before calling
  // Disasm(). Parameter hilitereg has priority over hiliteindex.
  ulong          hilitereg;            // One of OP_SOMEREG if reg highlighting
  int            hiregindex;           // Index of register to highlight
  int            hiliteindex;          // Index of highlighting scheme (0: none)
  // Starting from this point, no need to initialize the members of t_disasm.
  ulong          ip;                   // Address of first command byte
  ulong          size;                 // Full length of command, bytes
  ulong          cmdtype;              // Type of command, D_xxx
  ulong          exttype;              // More features, set of DX_xxx
  ulong          prefixes;             // List of prefixes, set of PF_xxx
  ulong          nprefix;              // Number of prefixes, including SSE2
  ulong          memfixup;             // Offset of first 4-byte fixup or -1
  ulong          immfixup;             // Offset of second 4-byte fixup or -1
  int            errors;               // Set of DAE_xxx
  int            warnings;             // Set of DAW_xxx
  // Note that used registers are those which contents is necessary to create
  // result. Modified registers are those which value is changed. For example,
  // command MOV EAX,[EBX+ECX] uses EBX and ECX and modifies EAX. Command
  // ADD ESI,EDI uses ESI and EDI and modifies ESI.
  ulong          uses;                 // List of used registers
  ulong          modifies;             // List of modified registers
  // Useful shortcuts.
  int            condition;            // Condition, one of DAF_xxx
  ulong          jmpaddr;              // Jump/call destination or 0
  ulong          memconst;             // Constant in memory address or 0
  ulong          stackinc;             // Data size in ENTER/RETN/RETF
  // Operands.
  t_operand      op[NOPERAND];         // Operands
  // Textual decoding.
  wchar_t        dump[TEXTLEN];        // Hex dump of the command
  wchar_t        result[TEXTLEN];      // Fully decoded command as text
  uchar          mask[TEXTLEN];        // Mask to highlight result
  int            maskvalid;            // Mask corresponds to result
  wchar_t        comment[TEXTLEN];     // Comment that applies to whole command
} t_disasm;

typedef struct t_opinfo {              // Operand in t_cmdinfo
  ulong          features;             // Operand features, set of OP_xxx
  ulong          arg;                  // Operand type, set of B_xxx
  int            opsize;               // Total size of data, bytes
  int            reg;                  // REG_xxx (also ESP in POP) or REG_UNDEF
  int            seg;                  // Selector (SEG_xxx)
  uchar          scale[NREG];          // Scales of registers in memory address
  ulong          opconst;              // Constant or const part of address
} t_opinfo;

typedef struct t_cmdinfo {             // Information on command
  ulong          ip;                   // Address of first command byte
  ulong          size;                 // Full length of command, bytes
  ulong          cmdtype;              // Type of command, D_xxx
  ulong          prefixes;             // List of prefixes, set of PF_xxx
  ulong          nprefix;              // Number of prefixes, including SSE2
  ulong          memfixup;             // Offset of first 4-byte fixup or -1
  ulong          immfixup;             // Offset of second 4-byte fixup or -1
  int            errors;               // Set of DAE_xxx
  ulong          jmpaddr;              // Jump/call destination or 0
  ulong          stackinc;             // Data size in ENTER/RETN/RETF
  t_opinfo       op[NOPERAND];         // Operands
} t_cmdinfo;

// ATTENTION, when making any changes to this structure, apply them to the
// file Cmdemul.asm, too!
typedef struct t_emu {                 // Parameters passed to emulation routine
  ulong          operand[NOPERAND];    // I/O: Operands
  ulong          opsize;               // IN:  Size of operands
  ulong          memaddr;              // OUT: Save address, or 0 if none
  ulong          memsize;              // OUT: Save size (1, 2 or 4 bytes)
  ulong          memdata;              // OUT: Data to save
} t_emu;

typedef void TRACEFUNC(ulong *,ulong *,t_predict *,t_disasm *);
typedef void __cdecl EMUFUNC(t_emu *,t_reg *);

typedef struct t_bincmd {              // Description of 80x86 command
  wchar_t        *name;                // Symbolic name for this command
  ulong          cmdtype;              // Command's features, set of D_xxx
  ulong          exttype;              // More features, set of DX_xxx
  ulong          length;               // Length of main code (before ModRM/SIB)
  ulong          mask;                 // Mask for first 4 bytes of the command
  ulong          code;                 // Compare masked bytes with this
  ulong          postbyte;             // Postbyte
  ulong          arg[NOPERAND];        // Types of arguments, set of B_xxx
  TRACEFUNC      *trace;               // Result prediction function
  EMUFUNC        *emu;                 // Command emulation function
} t_bincmd;

#define AMF_SAMEORDER  0x01            // Same order of index registers in addr
#define AMF_ANYSEG     0x02            // Command has undefined segment prefix
#define AMF_POSTBYTE   0x04            // Includes postbyte
#define AMF_IMPRECISE  0x08            // Command is imprecise (search only)
#define AMF_ANYSIZE    0x10            // Any operand size is acceptable
#define AMF_NOSMALL    0x20            // 16-bit address is not allowed
#define AMF_UNDOC      0x40            // Undocumented command
#define AMF_NEWCMD     0x80            // Marks new command in multiline

#define AMP_REGISTER   0x01            // Operand is a register
#define AMP_MEMORY     0x02            // Operand is a memory location
#define AMP_CONST      0x04            // Operand is a constant
#define AMP_IMPRECISE  0x08            // Constant is imprecise
#define AMP_ANYMEM     0x10            // Any memory operand is acceptable
#define AMP_ANYOP      0x20            // Any operand is acceptable

typedef struct t_modop {               // Operand in assembler model
  uchar          features;             // Operand features, set of AMP_xxx
  uchar          reg;                  // (Pseudo)register operand
  uchar          scale[NPSEUDO];       // Scales of (pseudo)registers in address
  ulong          opconst;              // Constant or const part of address
} t_modop;

// Assembler command model.
typedef struct t_asmmod {              // Description of assembled command
  uchar          code[MAXCMDSIZE];     // Binary code
  uchar          mask[MAXCMDSIZE];     // Mask for binary code (0: bit ignored)
  ulong          prefixes;             // List of prefixes, set of PF_xxx
  uchar          ncode;                // Length of code w/o prefixes, bytes
  uchar          features;             // Code features, set of AMF_xxx
  uchar          postbyte;             // Postbyte (if AMF_POSTBYTE set)
  uchar          noperand;             // Number of operands (no pseudooperands)
  t_modop        op[NOPERAND];         // Description of operands
} t_asmmod;

typedef struct t_asmlist {             // Descriptor of the sequence of models
  t_asmmod       *pasm;                // Pointer to the start of the sequence
  int            length;               // Length of the sequence, models
  wchar_t        comment[TEXTLEN];     // Comment to the sequence
} t_asmlist;

#define DA_TEXT        0x00000001      // Decode command to text and comment
#define   DA_HILITE    0x00000002      // Use syntax highlighting (set t_disasm)
#define DA_OPCOMM      0x00000004      // Comment operands
#define DA_DUMP        0x00000008      // Dump command to hexadecimal text
#define DA_MEMORY      0x00000010      // OK to read memory and use labels
#define   DA_NOIMPORT  0x00000020      // When reading memory, hold the imports
#define   DA_RTLOGMEM  0x00000040      // Use memory saved by run trace
#define   DA_NOSTACKP  0x00000080      // Hide "Stack" prefix in comments
#define DA_STEPINTO    0x00000100      // Enter CALL when predicting registers
#define DA_SHOWARG     0x00000200      // Use predict if address ESP/EBP-based
#define DA_NOPSEUDO    0x00000400      // Skip pseudooperands
#define DA_FORHELP     0x00000800      // Decode operands for command help

#define USEDECODE      ((uchar *)1)    // Request to get decoding automatically

stdapi (int)     Byteregtodwordreg(int bytereg);
stdapi (int)     Printfloat4(wchar_t *s,float f);
stdapi (int)     Printfloat8(wchar_t *s,double d);
stdapi (int)     Printfloat10(wchar_t *s,long double ext);
stdapi (int)     Printmmx(wchar_t *s,uchar *data);
stdapi (int)     Commentcharacter(wchar_t *s,int c,int mode);
stdapi (int)     Nameoffloat(wchar_t *s,uchar *data,ulong size);
stdapi (ulong)   Disasm(uchar *cmd,ulong cmdsize,ulong ip,uchar *dec,
                   t_disasm *da,int mode,t_reg *reg,
                   t_predict *predict);
stdapi (ulong)   Cmdinfo(uchar *cmd,ulong cmdsize,ulong cmdip,
                   t_cmdinfo *ci,int cmdmode,t_reg *cmdreg);
stdapi (ulong)   Disassembleforward(uchar *copy,ulong base,ulong size,
                   ulong ip,ulong n,uchar *decode);
stdapi (ulong)   Disassembleback(uchar *copy,ulong base,ulong size,
                   ulong ip,ulong n,uchar *decode);
stdapi (int)     Checkcondition(int code,ulong flags);
stdapi (ulong)   Setcondition(int code,ulong flags);

#define AM_ALLOWBAD    0x00000001      // Allow bad or undocumented commands
#define AM_IMPRECISE   0x00000002      // Generate imprecise (search) forms
#define   AM_MULTI     0x00000004      // Multiple commands are allowed

#define AM_SEARCH      AM_IMPRECISE

stdapi (int)     Assembleallforms(wchar_t *src,ulong ip,t_asmmod *model,
                   int maxmodel,int mode,wchar_t *errtxt);
stdapi (ulong)   Assemble(wchar_t *src,ulong ip,uchar *buf,ulong nbuf,int mode,
                   wchar_t *errtxt);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////// .NET DISASSEMBLER ///////////////////////////////

// CIL command types.
#define N_CMDTYPE      0x0000001F      // Mask to extract type of command
#define   N_CMD        0x00000000      // Ordinary (none of listed below)
#define   N_JMP        0x00000001      // Unconditional jump
#define   N_JMC        0x00000002      // Conditional jump
#define   N_CALL       0x00000003      // Call
#define   N_RET        0x00000004      // Return (also from exception)
#define   N_SWITCH     0x00000005      // Switch, followed by N cases
#define   N_PREFIX     0x00000006      // Prefix, not a standalone command
#define   N_DATA       0x0000001E      // Command is decoded as data
#define   N_BAD        0x0000001F      // Bad command
#define N_POPMASK      0x00000F00      // Mask to extract number of pops
#define   N_POP0       0x00000000      // Pops no arguments (default)
#define   N_POP1       0x00000100      // Pops 1 argument from stack
#define   N_POP2       0x00000200      // Pops 2 arguments from stack
#define   N_POP3       0x00000300      // Pops 3 arguments from stack
#define   N_POPX       0x00000F00      // Pops variable arguments from stack
#define N_PUSHMASK     0x0000F000
#define   N_PUSH0      0x00000000      // Pushes no data (default)
#define   N_PUSH1      0x00001000      // Pushes 1 argument into stack
#define   N_PUSH2      0x00002000      // Pushes 2 arguments into stack
#define   N_PUSHX      0x0000F000      // Pushes 0 or 1 argument into stack

// CIL explicit operand types.
#define A_ARGMASK      0x000000FF      // Mask to extract type of argument
#define   A_NONE       0x00000000      // No operand
#define   A_OFFSET     0x00000001      // 32-bit offset from next command
#define   A_BYTEOFFS   0x00000002      // 8-bit offset from next command
#define   A_METHOD     0x00000003      // 32-bit method descriptor
#define   A_SIGNATURE  0x00000004      // 32-bit signature of call types
#define   A_TYPE       0x00000005      // 32-bit type descriptor
#define   A_FIELD      0x00000006      // 32-bit field descriptor
#define   A_STRING     0x00000007      // 32-bit string descriptor
#define   A_TOKEN      0x00000008      // 32-bit token descriptor
#define   A_INDEX1     0x00000009      // 8-bit immediate index constant
#define   A_INDEX2     0x0000000A      // 16-bit immediate index constant
#define   A_SWCOUNT    0x0000000B      // 32-bit immediate switch count
#define   A_INT1S      0x0000000C      // 8-bit immediate signed integer const
#define   A_INT4       0x0000000D      // 32-bit immediate integer constant
#define   A_INT8       0x0000000E      // 64-bit immediate integer constant
#define   A_FLOAT4     0x0000000F      // 32-bit immediate float constant
#define   A_FLOAT8     0x00000010      // 64-bit immediate float constant
#define   A_NOLIST     0x00000011      // 8-bit list following no. prefix
#define   A_ALIGN      0x00000012      // 8-bit alignment following unaligned.

typedef struct t_netasm {              // Disassembled .NET CIL command
  ulong          ip;                   // Address of first command byte
  ulong          size;                 // Full length of command, bytes
  ulong          cmdtype;              // Type of command, N_xxx
  ulong          cmdsize;              // Size of command, bytes
  ulong          opsize;               // Size of operand, bytes, or 0 if none
  ulong          nswitch;              // Size of following switch table, dwords
  ulong          jmpaddr;              // Single jump/call destination or 0
  ulong          descriptor;           // Descriptor (xx)xxxxxx or 0
  ulong          dataaddr;             // Address of pointed object/data or 0
  int            errors;               // Set of DAE_xxx
  // Description of operand.
  ulong          optype;               // Operand type, set of A_xxx
  wchar_t        optext[TEXTLEN];      // Operand, decoded to text
  // Textual decoding.
  wchar_t        dump[TEXTLEN];        // Hex dump of the command
  wchar_t        result[TEXTLEN];      // Fully decoded command as text
  wchar_t        comment[TEXTLEN];     // Comment that applies to whole command
} t_netasm;

stdapi (ulong)   Ndisasm(uchar *cmd,ulong size,ulong ip,t_netasm *da,
                   int mode,t_module *pmod);


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// ANALYSIS ///////////////////////////////////

#define MAXARG         256             // Maximal sane number of arguments

#define NGUESS         7               // Max number of args in type analysis

#define AA_MANUAL      0               // No automatical analysis
#define AA_MAINONLY    1               // Automatically analyse main module
#define AA_NONSYS      2               // Automatically analyse non-sys modules
#define AA_ALL         3               // Automatically analyse all modules

#define AO_ISFORMATA   0x01            // Argument is probable ASCII format
#define AO_SIGFORMATA  0x02            // Non-trivial ASCII format
#define AO_ISFORMATW   0x04            // Argument is probable UNICODE format
#define AO_SIGFORMATW  0x08            // Non-trivial UNICODE format
#define AO_NOTFORMAT   0x10            // Argument is not a format
#define AO_ISCOUNT     0x20            // Argument is count of remaining args
#define AO_NOTCOUNT    0x40            // Argument is not a count

typedef struct t_procdata {            // Description of procedure
  ulong          addr;                 // Address of entry point
  ulong          size;                 // Size of simple procedure or 1
  ulong          type;                 // Type of procedure, TY_xxx/PD_xxx
  ulong          retsize;              // Size of return (if PD_RETSIZE)
  ulong          localsize;            // Size of reserved locals, 0 - unknown
  ulong          savedebp;             // Offset of cmd after PUSH EBP, 0 - none
  ulong          features;             // Type of known code, RAW_xxx
  char           generic[12];          // Generic name (without _INTERN_)
  int            narg;                 // No. of stack DWORDs (PD_NARG/VARARG)
  int            nguess;               // Number of guessed args (if PD_NGUESS)
  int            npush;                // Number of pushed args (if PD_NPUSH)
  int            usedarg;              // Min. number of accessed arguments
  uchar          preserved;            // Preserved registers
  uchar          argopt[NGUESS];       // Guessed argument options, AO_xxx
} t_procdata;

typedef struct t_argnest {             // Header of call arguments bracket
  ulong          addr0;                // First address occupied by range
  ulong          addr1;                // Last occupied address (included!)
  ulong          type;                 // Level and user-defined type, TY_xxx
  ulong          aprev;                // First address of previous range
} t_argnest;

#define NLOOPVAR       4               // Max number of loop variables

typedef struct t_loopnest {            // Header of loop bracket
  ulong          addr0;                // First address occupied by range
  ulong          addr1;                // Last occupied address (included!)
  ulong          type;                 // Level and user-defined type, TY_xxx
  ulong          aprev;                // First address of previous range
  ulong          eoffs;                // Offset of entry point from addr0
  struct {                             // Loop registers and variables
    uchar        type;                 // Combination of PRED_xxx
    long         espoffset;            // For locals, offset to original ESP
    long         increment;            // Increment after loop
  } loopvar[NLOOPVAR];
} t_loopnest;

stdapi (ulong)   Getpackednetint(uchar *code,ulong size,ulong *value);
stdapi (void)    Removeanalysis(ulong base,ulong size,int keephittrace);
stdapi (int)     Maybecommand(ulong addr,int requireanalysis);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// STACK WALK //////////////////////////////////

#define SF_FMUNREL     0x00000001      // Predicted frame is unreliable
#define SF_BPUNREL     0x00000002      // Predicted EBP is unreliable
#define SF_VIRTUAL     0x00000004      // DBGHELP: EBP is undefined

typedef struct t_sframe {              // Stack frame descriptor
  // Input parameters, fill before call to Findretaddrdata().
  ulong          eip;                  // Address of command that owns frame
  ulong          esp;                  // ESP at EIP
  ulong          ebp;                  // EBP at EIP, or 0 if unknown
  // Parameters used by DBGHELP.DLL, initialize only before the first call.
  int            firstcall;            // First call to Findretaddrdata()
  HANDLE         thread;               // Thread handle
  CONTEXT        context;              // Copy of CONTEXT, fill on first call
  int            contextvalid;         // Whether context contains valid data
  // Output parameters.
  ulong          status;               // Set of SF_xxx
  ulong          oldeip;               // Address of CALL or 0 if unknown
  ulong          oldesp;               // ESP at CALL or 0 if unknown
  ulong          oldebp;               // EBP at CALL or 0 if unknown
  ulong          retpos;               // Address of return in stack
  ulong          procaddr;             // Entry of current function or 0
  // Parameters used by DBGHELP.DLL, don't initialize!
  #ifdef STACKFRAME64                  // Requires <dbghelp.h>
    STACKFRAME64 sf;                   // Stack frame for StackWalk64()
  #else
    uchar        dummy[264];           // Replaces STACKFRAME64
  #endif
} t_sframe;

stdapi (ulong)   Isretaddr(ulong retaddr,ulong *procaddr);
stdapi (int)     Findretaddrdata(t_sframe *pf,ulong base,ulong size);


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// KNOWN FUNCTIONS ////////////////////////////////

#define NARG           24              // Max number of arguments in a function

#define ADEC_VALID     0x00000001      // Value valid
#define ADEC_PREDICTED 0x00000002      // Value predicted
#define ADEC_CHGNAME   0x00000004      // Allow name change of substituted arg
#define ADEC_MARK      0x00000008      // (out) Important parameter

// Type of argument in the description of function or structure. Note that
// ARG_STRUCT is allowed only in conjunction with ARG_POINTER.
#define ARG_POINTER    0x01            // Argument is a pointer
#define ARG_BASE       0x06            // Mask to extract base type of argument
#define   ARG_TYPE     0x00            // Argument is a type
#define   ARG_STRUCT   0x02            // Argument is a structure
#define   ARG_DIRECT   0x04            // Argument is a direct string
#define ARG_OUT        0x08            // Pointer to data undefined at call
#define ARG_MARK       0x10            // Important parameter
#define ARG_ELLIPSYS   0x20            // Followed by ellipsys
#define ARG_VALID      0x40            // Must always be set to avoid argx=0

#define ARG_TYPEMASK   (ARG_POINTER|ARG_BASE)    // Mask to extract full type

#define ARG_PTYPE      (ARG_POINTER|ARG_TYPE)    // Pointer to type
#define ARG_PSTRUCT    (ARG_POINTER|ARG_STRUCT)  // Pointer to structure

// Bits used to define type of function.
#define FN_C           0x00000001      // Does not remove arguments from stack
#define FN_PASCAL      0x00000002      // Removes arguments from stack on return
#define FN_NORETURN    0x00000004      // Does not return, like ExitProcess()
#define FN_VARARG      0x00000008      // Variable number of arguments
#define FN_EAX         0x00000100      // EAX on return is same as on entry
#define FN_ECX         0x00000200      // ECX on return is same as on entry
#define FN_EDX         0x00000400      // EDX on return is same as on entry
#define FN_EBX         0x00000800      // EBX on return is same as on entry
#define FN_ESP         0x00001000      // ESP on return is same as on entry
#define FN_EBP         0x00002000      // EBP on return is same as on entry
#define FN_ESI         0x00004000      // ESI on return is same as on entry
#define FN_EDI         0x00008000      // EDI on return is same as on entry
#define FN_USES_EAX    0x00010000      // EAX is used as register parameter
#define FN_USES_ECX    0x00020000      // ECX is used as register parameter
#define FN_USES_EDX    0x00040000      // EDX is used as register parameter
#define FN_USES_EBX    0x00080000      // EBX is used as register parameter
#define FN_USES_ESP    0x00100000      // ESP is used as register parameter
#define FN_USES_EBP    0x00200000      // EBP is used as register parameter
#define FN_USES_ESI    0x00400000      // ESI is used as register parameter
#define FN_USES_EDI    0x00800000      // EDI on return is same as on entry

#define FN_FUNCTION    0
#define FN_STDFUNC     (FN_PASCAL|FN_EBX|FN_EBP|FN_ESI|FN_EDI)
#define FN_STDC        (FN_C|FN_EBX|FN_EBP|FN_ESI|FN_EDI)

typedef struct t_argdec {              // Descriptor of function argument
  ulong          mode;                 // Value descriptor, set of ADEC_xxx
  ulong          value;                // Value on the stack
  ulong          pushaddr;             // Address of command that pushed data
  wchar_t        prtype[SHORTNAME];    // Type of argument with ARG_xxx prefix
  wchar_t        name[TEXTLEN];        // Decoded name of argument
  wchar_t        text[TEXTLEN];        // Decoded value (if valid or predicted)
} t_argdec;

typedef struct t_strdec {              // Decoded structure item
  ulong          size;                 // Item size, bytes
  ulong          addr;                 // Address of the first byte
  ulong          value;                // Item value (only if size<=4!)
  uchar          valuevalid;           // Whether value is valid
  uchar          dec;                  // One of DEC_TYPEMASK subfields
  uchar          decsize;              // Size of decoding element
  uchar          reserved;             // Reserved for the future
  wchar_t        prtype[SHORTNAME];    // Type of item with ARG_xxx prefix
  wchar_t        name[TEXTLEN];        // Name of item
  wchar_t        text[TEXTLEN];        // Decoded value
} t_strdec;

typedef struct t_rawdata {             // Header of raw data block
  ulong          size;                 // Data size, bytes
  ulong          hasmask;              // Data is followed by mask
  ulong          features;             // Data features
} t_rawdata;                           // Data & mask immediately follow header

typedef struct t_argloc {              // Information about stack args & locals
  ulong          fntype;               // Calling convention, set of FN_xxx
  int            retfeatures;          // Return features, set of ARG_xxx
  int            retsize;              // Size of returned value
  wchar_t        rettype[SHORTNAME];   // Type of the returned value
  int            argvalid;             // Whether arg[] below is valid
  struct {                             // List of arguments
    int          features;             // Argument features, set of ARG_xxx
    int          size;                 // Size of argument on the stack
    wchar_t      name[TEXTLEN];        // Name of the argument
    wchar_t      type[SHORTNAME];      // Type of the argument
  } arg[NARG];
} t_argloc;

stdapi (int)     Getconstantbyname(wchar_t *name,ulong *value);
stdapi (int)     Getconstantbyvalue(wchar_t *groupname,
                   ulong value,wchar_t *name);
stdapi (int)     Decodetype(ulong data,wchar_t *type,wchar_t *text,int ntext);
stdapi (int)     Fillcombowithgroup(HWND hw,wchar_t *groupname,
                   int sortbyname,ulong select);
stdapi (int)     Fillcombowithstruct(HWND hw,wchar_t *prefix,wchar_t *select);
stdapi (t_rawdata *) Getrawdata(wchar_t *name);
stdapi (int)     Substitutehkeyprefix(wchar_t *key);
stdapi (int)     Decodeknownbyname(wchar_t *name,t_procdata *pd,
                   t_argdec adec[NARG],wchar_t *rettype,int nexp);
stdapi (int)     Decodeknownbyaddr(ulong addr,t_procdata *pd,
                   t_argdec adec[NARG],wchar_t *rettype,wchar_t *name,
                   int nexp,int follow);
stdapi (int)     Isnoreturn(ulong addr);
stdapi (int)     Decodeargument(t_module *pmod,wchar_t *prtype,void *data,
                   int ndata,wchar_t *text,int ntext,int *nontriv);
stdapi (int)     Getstructureitemcount(wchar_t *name,ulong *size);
stdapi (int)     Findstructureitembyoffset(wchar_t *name,ulong offset);
stdapi (int)     Decodestructure(wchar_t *name,ulong addr,int item0,
                   t_strdec *str,int nstr);
stdapi (ulong)   Getstructureitemvalue(uchar *code,ulong ncode,
                   wchar_t *name,wchar_t *itemname,void *value,ulong nvalue);


////////////////////////////////////////////////////////////////////////////////
////////////////////// EXPRESSIONS, WATCHES AND INSPECTORS /////////////////////

#define NEXPR          16              // Max. no. of expressions in EMOD_MULTI

// Mode of expression evaluation.
#define EMOD_CHKEXTRA  0x00000001      // Report extra characters on line
#define EMOD_NOVALUE   0x00000002      // Don't convert data to text
#define EMOD_NOMEMORY  0x00000004      // Don't read debuggee's memory
#define EMOD_MULTI     0x00000008      // Allow multiple expressions

#define EXPR_TYPEMASK  0x0F            // Mask to extract type of expression
#define   EXPR_INVALID 0x00            // Invalid or undefined expression
#define   EXPR_BYTE    0x01            // 8-bit integer byte
#define   EXPR_WORD    0x02            // 16-bit integer word
#define   EXPR_DWORD   0x03            // 32-bit integer doubleword
#define   EXPR_FLOAT4  0x04            // 32-bit floating-point number
#define   EXPR_FLOAT8  0x05            // 64-bit floating-point number
#define   EXPR_FLOAT10 0x06            // 80-bit floating-point number
#define   EXPR_SEG     0x07            // Segment
#define   EXPR_ASCII   0x08            // Pointer to ASCII string
#define   EXPR_UNICODE 0x09            // Pointer to UNICODE string
#define   EXPR_TEXT    0x0A            // Immediate UNICODE string
#define EXPR_REG       0x10            // Origin is register
#define EXPR_SIGNED    0x20            // Signed integer

#define EXPR_SIGDWORD  (EXPR_DWORD|EXPR_SIGNED)

typedef struct t_result {              // Result of expression's evaluation
  int            lvaltype;             // Type of expression, EXPR_xxx
  ulong          lvaladdr;             // Address of lvalue or NULL
  int            datatype;             // Type of data, EXPR_xxx
  int            repcount;             // Repeat count (0..32, 0 means default)
  union {
    uchar        data[10];             // Value as set of bytes
    ulong        u;                    // Value as address or unsigned integer
    long         l;                    // Value as signed integer
    long double  f; };                 // Value as 80-bit float
  wchar_t        value[TEXTLEN];       // Value decoded to string
} t_result;

typedef struct t_watch {               // Watch descriptor
  ulong          addr;                 // 0-based watch index
  ulong          size;                 // Reserved, always 1
  ulong          type;                 // Service information, TY_xxx
  wchar_t        expr[TEXTLEN];        // Watch expression
} t_watch;

stdapi (int)     Cexpression(wchar_t *expression,uchar *cexpr,int nexpr,
                   int *explen,wchar_t *err,ulong mode);
stdapi (int)     Exprcount(uchar *cexpr);
stdapi (int)     Eexpression(t_result *result,wchar_t *expl,uchar *cexpr,
                   int index,uchar *data,ulong base,ulong size,ulong threadid,
                   ulong a,ulong b,ulong mode);
stdapi (int)     Expression(t_result *result,wchar_t *expression,uchar *data,
                   ulong base,ulong size,ulong threadid,ulong a,ulong b,
                   ulong mode);
stdapi (int)     Fastexpression(t_result *result,ulong addr,int type,
                   ulong threadid);


////////////////////////////////////////////////////////////////////////////////
///////////////////////////// DIALOGS AND OPTIONS //////////////////////////////

// Mode bits in calls to dialog functions.
#define DIA_SIZEMASK   0x0000001F      // Mask to extract default data size
#define   DIA_BYTE     0x00000001      // Byte data size
#define   DIA_WORD     0x00000002      // Word data size
#define   DIA_DWORD    0x00000004      // Doubleword data size (default)
#define   DIA_QWORD    0x00000008      // Quadword data size
#define   DIA_TBYTE    0x0000000A      // 10-byte data size
#define   DIA_DQWORD   0x00000010      // 16-byte data size
#define DIA_HEXONLY    0x00000020      // Hexadecimal format only
#define DIA_EXTENDED   0x00000040      // Extended format
#define DIA_DATAVALID  0x00000080      // Input data valid (edit mode)
#define DIA_DEFMASK    0x00000F00      // Mask to extract default data type
#define   DIA_DEFHEX   0x00000100      // On startup, cursor in hex control
#define   DIA_DEFSIG   0x00000200      // On startup, cursor in signed control
#define   DIA_DEFUNSIG 0x00000300      // On startup, cursor in unsigned control
#define   DIA_DEFASC   0x00000400      // On startup, cursor in ASCII control
#define   DIA_DEFUNI   0x00000500      // On startup, cursor in UNICODE control
#define   DIA_DEFCODE  0x00000600      // Default is code breakpoint
#define   DIA_DEFFLOAT 0x00000700      // Default selection is float
#define DIA_ISSEARCH   0x00001000      // Is a search dialog
#define DIA_ASKCASE    0x00002000      // Ask if case-insensitive
#define DIA_SEARCHDIR  0x00004000      // Includes direction search buttons
#define DIA_HISTORY    0x00008000      // Supports history
#define DIA_SELMASK    0x000F0000      // Mask to extract selection offset
#define   DIA_SEL0     0x00000000      // Select least significant item
#define   DIA_SEL4     0x00040000      // Select item with offset 4
#define   DIA_SEL8     0x00080000      // Select item with offset 8
#define   DIA_SEL12    0x000C0000      // Select item with offset 12
#define   DIA_SEL14    0x000E0000      // Select item with offset 14
#define DIA_JMPMODE    0x00300000      // Mask for jump/call/switch display
#define   DIA_JMPFROM  0x00000000      // Jumps/calls from specified location
#define   DIA_JMPTO    0x00100000      // Jumps/calls to specified location
#define   DIA_SWITCH   0x00200000      // Switches
#define DIA_JMPGLOB    0x00400000      // Show global jumps and calls
#define DIA_JMPLOC     0x00000000      // Show local jumps and calls
#define DIA_UTF8       0x00800000      // Support for UTF8
#define DIA_ABSXYPOS   0x10000000      // Use X-Y dialog coordinates as is
#define DIA_RESTOREPOS 0x20000000      // Restore X-Y dialog coordinates

// Types of controls that can be used in dialogs.
#define CA_END         0               // End of control list with dialog size
#define CA_COMMENT     1               // Dummy entry in control list
#define CA_TEXT        2               // Simple left-aligned text
#define CA_TEXTC       4               // Simple centered text
#define CA_TEXTR       5               // Simple right-aligned text
#define CA_WARN        6               // Multiline text, highlighted if differ
#define CA_WTEXT       7               // Text with white bg in sunken frame
#define CA_TITLE       8               // Fat centered text
#define CA_FRAME       9               // Etched frame
#define CA_SUNK        10              // Sunken frame
#define CA_GROUP       11              // Group box (named frame)
#define CA_EDIT        12              // Standard edit control
#define CA_NOEDIT      13              // Read-only edit control
#define CA_EDITHEX     14              // Standard edit control, hex uppercase
#define CA_MULTI       15              // Multiline edit control (DATALEN)
#define CA_NOMULTI     16              // Multiline read-only edit (DATALEN)
#define CA_BTN         17              // Standard pushbutton
#define CA_DEFBTN      18              // Standard default pushbutton
#define CA_COMBO       19              // Combo box control, specified font
#define CA_COMBOFIX    20              // Combo box control, fixed width font
#define CA_CEDIT       21              // Combo edit control, specified font
#define CA_CEDITFIX    22              // Combo edit control, fixed width font
#define CA_CESAV0      32              // Combo edit 0 with autosave & UNICODE
#define CA_CESAV1      33              // Combo edit 1 with autosave & UNICODE
#define CA_CESAV2      34              // Combo edit 2 with autosave & UNICODE
#define CA_CESAV3      35              // Combo edit 3 with autosave & UNICODE
#define CA_CESAV4      36              // Combo edit 4 with autosave & UNICODE
#define CA_CESAV5      37              // Combo edit 5 with autosave & UNICODE
#define CA_CESAV6      38              // Combo edit 6 with autosave & UNICODE
#define CA_CESAV7      39              // Combo edit 7 with autosave & UNICODE
#define CA_LIST        48              // Simple list box
#define CA_LISTFIX     49              // Simple list box, fixed font
#define CA_CHECK       62              // Auto check box, left-aligned
#define CA_CHECKR      63              // Auto check box, right-aligned
#define CA_BIT0        64              // Auto check box, bit 0
#define CA_BIT1        65              // Auto check box, bit 1
#define CA_BIT2        66              // Auto check box, bit 2
#define CA_BIT3        67              // Auto check box, bit 3
#define CA_BIT4        68              // Auto check box, bit 4
#define CA_BIT5        69              // Auto check box, bit 5
#define CA_BIT6        70              // Auto check box, bit 6
#define CA_BIT7        71              // Auto check box, bit 7
#define CA_BIT8        72              // Auto check box, bit 8
#define CA_BIT9        73              // Auto check box, bit 9
#define CA_BIT10       74              // Auto check box, bit 10
#define CA_BIT11       75              // Auto check box, bit 11
#define CA_BIT12       76              // Auto check box, bit 12
#define CA_BIT13       77              // Auto check box, bit 13
#define CA_BIT14       78              // Auto check box, bit 14
#define CA_BIT15       79              // Auto check box, bit 15
#define CA_BIT16       80              // Auto check box, bit 16
#define CA_BIT17       81              // Auto check box, bit 17
#define CA_BIT18       82              // Auto check box, bit 18
#define CA_BIT19       83              // Auto check box, bit 19
#define CA_BIT20       84              // Auto check box, bit 20
#define CA_BIT21       85              // Auto check box, bit 21
#define CA_BIT22       86              // Auto check box, bit 22
#define CA_BIT23       87              // Auto check box, bit 23
#define CA_BIT24       88              // Auto check box, bit 24
#define CA_BIT25       89              // Auto check box, bit 25
#define CA_BIT26       90              // Auto check box, bit 26
#define CA_BIT27       91              // Auto check box, bit 27
#define CA_BIT28       92              // Auto check box, bit 28
#define CA_BIT29       93              // Auto check box, bit 29
#define CA_BIT30       94              // Auto check box, bit 30
#define CA_BIT31       95              // Auto check box, bit 31
#define CA_RADIO0      96              // Radio button, value 0
#define CA_RADIO1      97              // Radio button, value 1
#define CA_RADIO2      98              // Radio button, value 2
#define CA_RADIO3      99              // Radio button, value 3
#define CA_RADIO4      100             // Radio button, value 4
#define CA_RADIO5      101             // Radio button, value 5
#define CA_RADIO6      102             // Radio button, value 6
#define CA_RADIO7      103             // Radio button, value 7
#define CA_RADIO8      104             // Radio button, value 8
#define CA_RADIO9      105             // Radio button, value 9
#define CA_RADIO10     106             // Radio button, value 10
#define CA_RADIO11     107             // Radio button, value 11
#define CA_RADIO12     108             // Radio button, value 12
#define CA_RADIO13     109             // Radio button, value 13
#define CA_RADIO14     110             // Radio button, value 14
#define CA_RADIO15     111             // Radio button, value 15
#define CA_CUSTOM      124             // Custom control
#define CA_CUSTSF      125             // Custom control with sunken frame
// Controls with special functions that work only in Options dialog.
#define CA_FILE        129             // Edit file (autosave, MAXPATH chars)
#define CA_BROWSE      130             // Browse file name pushbutton
#define CA_BRDIR       131             // Browse directory pushbutton
#define CA_LANGS       132             // Combobox with list of languages
#define CA_FONTS       133             // Combobox with list of fonts
#define CA_FHTOP       134             // Combobox that adjusts top font height
#define CA_FHBOT       135             // Combobox that adjusts bottom font hgt
#define CA_SCHEMES     136             // Combobox with list of schemes
#define CA_HILITE      137             // Combobox with list of hilites
#define CA_HILITE1     138             // Combobox with nontrivial hilites

// Modes of font usage in dialog windows, if applies.
#define DFM_SYSTEM     0               // Use system font
#define DFM_PARENT     1               // Use font of parent window
#define DFM_FIXED      2               // Use dlgfontindex
#define DFM_FIXALL     3               // Use dlgfontindex for all controls

#define HEXLEN         1024            // Max length of hex edit string, bytes

#define NSEARCHCMD     128             // Max number of assembler search models

typedef struct t_control {             // Descriptor of dialog control
  ulong          type;                 // Type of control, CA_xxx
  int            id;                   // Control's ID or -1 if unimportant
  int            x;                    // X coordinate, chars/4
  int            y;                    // Y coordinate, chars/8
  int            dx;                   // X size, chars/4
  int            dy;                   // Y size, chars/8
  int            *var;                 // Pointer to control variable or NULL
  wchar_t        *text;                // Name or contents of the control
  wchar_t        *help;                // Tooltip or NULL
  int            oldvar;               // Copy of control variable, internal
} t_control;

typedef struct t_dialog {              // Descriptor of OllyDbg dialog
  t_control      *controls;            // List of controls to place in dialog
  wchar_t        *title;               // Pointer to the dialog's title
  int            focus;                // ID of control with focus
  int            item;                 // Index of processing item
  ulong          u;                    // Doubleword data
  uchar          data[16];             // Data in other formats
  ulong          addr0;                // Address
  ulong          addr1;                // Address
  int            letter;               // First character entered in dialog
  int            x;                    // X reference screen coordinate
  int            y;                    // Y reference screen coordinate
  int            fi;                   // Index of font to use in dialog
  int            mode;                 // Dialog operation mode, set of DIA_xxx
  int            cesav[8];             // NM_xxx of CA_CESAVn
  HFONT          fixfont;              // Fixed font used in dialog
  int            isfullunicode;        // Whether fixfont UNICODE
  int            fixdx;                // Width of dialog fixed font
  int            fixdy;                // Height of dialog fixed font
  HWND           htooltip;             // Handle of tooltip window
  HWND           hwwarn;               // Handle of WARN control, if any
  int            initdone;             // WM_INITDIALOG finished
} t_dialog;

// ATTENTION, size of structure t_hexstr must not exceed DATALEN!
typedef struct t_hexstr {              // Data for hex/text search
  ulong          n;                    // Data length, bytes
  ulong          nmax;                 // Maximal data length, bytes
  uchar          data[HEXLEN];         // Data
  uchar          mask[HEXLEN];         // Mask, 0 bits are masked
} t_hexstr;

typedef int  BROWSECODEFUNC(int,void *,ulong *,wchar_t *);

stdapi (t_control *) Findcontrol(HWND hw);
stdapi (int)     Defaultactions(HWND hparent,t_control *pctr,
                   WPARAM wp,LPARAM lp);
stdapi (void)    Addstringtocombolist(HWND hc,wchar_t *s);
stdapi (int)     Preparedialog(HWND hw,t_dialog *pdlg);
stdapi (int)     Endotdialog(HWND hw,int result);
stdapi (int)     Getregister(HWND hparent,int reg,ulong *data,int letter,
                   int x,int y,int fi,int mode);
stdapi (int)     Getinteger(HWND hparent,wchar_t *title,ulong *data,int letter,
                   int x,int y,int fi,int mode);
stdapi (int)     Getdword(HWND hparent,wchar_t *title,ulong *data,int letter,
                   int x,int y,int fi,int mode);
stdapi (int)     Getlasterrorcode(HWND hparent,wchar_t *title,ulong *data,
                   int letter,int x,int y,int fi);
stdapi (int)     Getaddressrange(HWND hparent,wchar_t *title,
                   ulong *rmin,ulong *rmax,int x,int y,int fi,int mode);
stdapi (int)     Getexceptionrange(HWND hparent,wchar_t *title,
                   ulong *rmin,ulong *rmax,int x,int y,int fi);
stdapi (int)     Getstructuretype(HWND hparent,wchar_t *title,wchar_t *text,
                   wchar_t *strname,int x,int y,int fi);
stdapi (int)     Getfpureg(HWND hparent,int reg,void *data,int letter,
                   int x,int y,int fi);
stdapi (int)     Get3dnow(HWND hparent,wchar_t *title,void *data,int letter,
                   int x,int y,int fi,int mode);
stdapi (int)     Getfloat(HWND hparent,wchar_t *title,void *data,int letter,
                   int x,int y,int fi,int mode);
stdapi (int)     Getmmx(HWND hparent,wchar_t *title,void *data,int letter,
                   int x,int y,int fi);
stdapi (int)     Getsse(HWND hparent,wchar_t *title,void *data,int letter,
                   int x,int y,int fi,int mode);
stdapi (int)     Getstring(HWND hparent,wchar_t *title,wchar_t *s,int length,
                   int savetype,int letter,int x,int y,int fi,int mode);
stdapi (int)     Getdwordexpression(HWND hparent,wchar_t *title,ulong *u,
                   ulong threadid,int savetype,int x,int y,int fi,int mode);
stdapi (int)     Getgotoexpression(HWND hparent,wchar_t *title,ulong *u,
                   ulong threadid,int savetype,int x,int y,int fi,int mode);
stdapi (int)     Asmindump(HWND hparent,wchar_t *title,struct t_dump *pd,
                   int letter,int x,int y,int fi,int mode);
stdapi (int)     Getasmsearchmodel(HWND hparent,wchar_t *title,t_asmmod *model,
                   int nmodel,int x,int y,int fi,int mode);
stdapi (int)     Getseqsearchmodel(HWND hparent,wchar_t *title,t_asmmod *model,
                   int nmodel,int x,int y,int fi,int mode);
stdapi (int)     Binaryedit(HWND hparent,wchar_t *title,t_hexstr *hstr,
                   int letter,int x,int y,int fi,int mode);
stdapi (int)     Getpredefinedtypebyindex(int fnindex,wchar_t *type);
stdapi (int)     Getindexbypredefinedtype(wchar_t *type);
stdapi (int)     Condbreakpoint(HWND hparent,ulong *addr,int naddr,
                   wchar_t *title,int x,int y,int fi);
stdapi (int)     Condlogbreakpoint(HWND hparent,ulong *addr,int naddr,
                   int fnindex,wchar_t *title,int x,int y,int fi);
stdapi (int)     Membreakpoint(HWND hparent,ulong addr,ulong size,
                   int x,int y,int fi,int mode);
stdapi (int)     Memlogbreakpoint(HWND hparent,ulong addr,ulong size,
                   int x,int y,int fi,int mode);
stdapi (int)     Hardbreakpoint(HWND hparent,ulong addr,
                   int x,int y,int fi,int mode);
stdapi (int)     Hardlogbreakpoint(HWND hparent,ulong addr,int fnindex,
                   int x,int y,int fi,int mode);
stdapi (void)    Setrtcond(HWND hparent,int x,int y,int fi);
stdapi (void)    Setrtprot(HWND hparent,int x,int y,int fi);
stdapi (ulong)   Browsecodelocations(HWND hparent,wchar_t *title,
                   BROWSECODEFUNC *bccallback,void *data);
stdapi (int)     Fillcombowithcodepages(HWND hw,int select);


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// PLUGIN OPTIONS ////////////////////////////////

#define OPT_TITLE      9001            // Pane title
#define OPT_1          9011            // First automatical control
#define OPT_2          9012            // Second automatical control
#define OPT_3          9013            // Third automatical control
#define OPT_4          9014            // Fourth automatical control
#define OPT_5          9015            // Fifth automatical control
#define OPT_6          9016            // Sixth automatical control
#define OPT_7          9017            // Seventh automatical control
#define OPT_8          9018            // Eighth automatical control
#define OPT_9          9019            // Ninth automatical control
#define OPT_10         9020            // Tenth automatical control
#define OPT_11         9021            // Eleventh automatical control
#define OPT_12         9022            // Twelfth automatical control
#define OPT_13         9023            // Thirteen automatical control
#define OPT_14         9024            // Fourteen automatical control
#define OPT_15         9025            // Fifteen automatical control
#define OPT_16         9026            // Sixteen automatical control
#define OPT_17         9027            // Seventeen automatical control
#define OPT_18         9028            // Eighteen automatical control
#define OPT_19         9029            // Nineteen automatical control
#define OPT_20         9030            // Twentieth automatical control
#define OPT_21         9031            // Twenty-first automatical control
#define OPT_22         9032            // Twenty-second automatical control
#define OPT_23         9033            // Twenty-third automatical control
#define OPT_24         9034            // Twenty-fourth automatical control
#define OPT_W1         9101            // First automatical autowarn control
#define OPT_W2         9102            // Second automatical autowarn control
#define OPT_W3         9103            // Third automatical autowarn control
#define OPT_W4         9104            // Fourth automatical autowarn control
#define OPT_W5         9105            // Fifth automatical autowarn control
#define OPT_W6         9106            // Sixth automatical autowarn control
#define OPT_W7         9107            // Seventh automatical autowarn control
#define OPT_W8         9108            // Eighth automatical autowarn control
#define OPT_W9         9109            // Ninth automatical autowarn control
#define OPT_W10        9110            // Tenth automatical autowarn control
#define OPT_W11        9111            // Eleventh automatical autowarn control
#define OPT_W12        9112            // Twelfth automatical autowarn control
#define OPT_S1         9121            // First autowarn-if-turned-on control
#define OPT_S2         9122            // Second autowarn-if-turned-on control
#define OPT_S3         9123            // Third autowarn-if-turned-on control
#define OPT_S4         9124            // Fourth autowarn-if-turned-on control
#define OPT_S5         9125            // Fifth autowarn-if-turned-on control
#define OPT_S6         9126            // Sixth autowarn-if-turned-on control
#define OPT_S7         9127            // Seventh autowarn-if-turned-on control
#define OPT_S8         9128            // Eighth autowarn-if-turned-on control
#define OPT_S9         9129            // Ninth autowarn-if-turned-on control
#define OPT_S10        9130            // Tenth autowarn-if-turned-on control
#define OPT_S11        9131            // Eleventh autowarn-if-turned-on control
#define OPT_S12        9132            // Twelfth autowarn-if-turned-on control
#define OPT_X1         9141            // First autowarn-if-all-on control
#define OPT_X2         9142            // Second autowarn-if-all-on control
#define OPT_X3         9143            // Third autowarn-if-all-on control
#define OPT_X4         9144            // Fourth autowarn-if-all-on control
#define OPT_X5         9145            // Fifth autowarn-if-all-on control
#define OPT_X6         9146            // Sixth autowarn-if-all-on control
#define OPT_X7         9147            // Seventh autowarn-if-all-on control
#define OPT_X8         9148            // Eighth autowarn-if-all-on control
#define OPT_X9         9149            // Ninth autowarn-if-all-on control
#define OPT_X10        9150            // Tenth autowarn-if-all-on control
#define OPT_X11        9151            // Eleventh autowarn-if-all-on control
#define OPT_X12        9152            // Twelfth autowarn-if-all-on control

#define OPT_CUSTMIN    9500            // Custom controls by plugins
#define OPT_CUSTMAX    9999            // End of custom area


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// COMMENTS ///////////////////////////////////

// Comments types used by Commentaddress().
#define COMM_USER      0x00000001      // Add user-defined comment
#define COMM_MARK      0x00000002      // Add important arguments
#define COMM_PROC      0x00000004      // Add procedure description
#define COMM_ALL       0xFFFFFFFF      // Add all possible comments

stdapi (int)     Stringtotext(wchar_t *data,int ndata,wchar_t *text,int ntext,
                   int stopatzero);
stdapi (int)     Isstring(ulong addr,int isstatic,wchar_t *symb,int nsymb);
stdapi (int)     Squeezename(wchar_t *dest,int ndest,wchar_t *src,int nsrc);
stdapi (void)    Uncapitalize(wchar_t *s);
stdapi (int)     Decoderelativeoffset(ulong addr,int addrmode,
                   wchar_t *symb,int nsymb);
stdapi (int)     Decodeaddress(ulong addr,ulong amod,int mode,
                   wchar_t *symb,int nsymb,wchar_t *comment);
stdapi (int)     Decodearglocal(ulong ip,ulong offs,ulong datasize,
                   wchar_t *name,int len);
stdapi (int)     Getanalysercomment(struct t_module *pmod,ulong addr,
                   wchar_t *comment,int len);
stdapi (int)     Getswitchcomment(ulong addr,wchar_t *comment,int len);
stdapi (int)     Getloopcomment(struct t_module *pmod,ulong addr,int level,
                   wchar_t *comment,int len);
stdapi (int)     Getproccomment(ulong addr,ulong acall,
                   wchar_t *comment,int len,int argonly);
stdapi (int)     Commentaddress(ulong addr,int typelist,
                   wchar_t *comment,int len);


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// LOG WINDOW //////////////////////////////////

stdapi (void)    Redrawlist(void);
varapi (void)    Addtolist(ulong addr,int color,wchar_t *format,...);


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// DUMP /////////////////////////////////////

#define DU_STACK       0x80000000      // Used for internal purposes
#define DU_NOSMALL     0x40000000      // Used for internal purposes
#define DU_MODEMASK    0x3C000000      // Mask for mode bits
#define   DU_SMALL     0x20000000      // Small-size dump
#define   DU_FIXADDR   0x10000000      // Fix first visible address
#define   DU_BACKUP    0x08000000      // Display backup instead of actual data
#define   DU_USEDEC    0x04000000      // Show contents using decoding data
#define DU_COMMMASK    0x03000000      // Mask for disassembly comments
#define   DU_COMMENT   0x00000000      // Show comments
#define   DU_SOURCE    0x01000000      // Show source
#define DU_DISCARD     0x00800000      // Discardable by Esc
#define DU_PROFILE     0x00400000      // Show profile
#define DU_TYPEMASK    0x003F0000      // Mask for dump type
#define   DU_HEXTEXT   0x00010000      // Hexadecimal dump with ASCII text
#define   DU_HEXUNI    0x00020000      // Hexadecimal dump with UNICODE text
#define   DU_TEXT      0x00030000      // Character dump
#define   DU_UNICODE   0x00040000      // Unicode dump
#define   DU_INT       0x00050000      // Integer signed dump
#define   DU_UINT      0x00060000      // Integer unsigned dump
#define   DU_IHEX      0x00070000      // Integer hexadecimal dump
#define   DU_FLOAT     0x00080000      // Floating-point dump
#define   DU_ADDR      0x00090000      // Address dump
#define   DU_ADRASC    0x000A0000      // Address dump with ASCII text
#define   DU_ADRUNI    0x000B0000      // Address dump with UNICODE text
#define   DU_DISASM    0x000C0000      // Disassembly
#define   DU_DECODE    0x000D0000      // Same as DU_DISASM but for decoded data
#define DU_COUNTMASK   0x0000FF00      // Mask for number of items/line
#define DU_SIZEMASK    0x000000FF      // Mask for size of single item

#define DU_MAINPART    (DU_TYPEMASK|DU_COUNTMASK|DU_SIZEMASK)

#define DUMP_HEXA8     0x00010801      // Hex/ASCII dump, 8 bytes per line
#define DUMP_HEXA16    0x00011001      // Hex/ASCII dump, 16 bytes per line
#define DUMP_HEXU8     0x00020801      // Hex/UNICODE dump, 8 bytes per line
#define DUMP_HEXU16    0x00021001      // Hex/UNICODE dump, 16 bytes per line
#define DUMP_ASC32     0x00032001      // ASCII dump, 32 characters per line
#define DUMP_ASC64     0x00034001      // ASCII dump, 64 characters per line
#define DUMP_UNI16     0x00041002      // UNICODE dump, 16 characters per line
#define DUMP_UNI32     0x00042002      // UNICODE dump, 32 characters per line
#define DUMP_UNI64     0x00044002      // UNICODE dump, 64 characters per line
#define DUMP_INT16     0x00050802      // 16-bit signed integer dump, 8 items
#define DUMP_INT16S    0x00050402      // 16-bit signed integer dump, 4 items
#define DUMP_INT32     0x00050404      // 32-bit signed integer dump, 4 items
#define DUMP_INT32S    0x00050204      // 32-bit signed integer dump, 2 items
#define DUMP_UINT16    0x00060802      // 16-bit unsigned integer dump, 8 items
#define DUMP_UINT16S   0x00060402      // 16-bit unsigned integer dump, 4 items
#define DUMP_UINT32    0x00060404      // 32-bit unsigned integer dump, 4 items
#define DUMP_UINT32S   0x00060204      // 32-bit unsigned integer dump, 2 items
#define DUMP_IHEX16    0x00070802      // 16-bit hex integer dump, 8 items
#define DUMP_IHEX16S   0x00070402      // 16-bit hex integer dump, 4 items
#define DUMP_IHEX32    0x00070404      // 32-bit hex integer dump, 4 items
#define DUMP_IHEX32S   0x00070204      // 32-bit hex integer dump, 2 items
#define DUMP_FLOAT32   0x00080404      // 32-bit floats, 4 items
#define DUMP_FLOAT32S  0x00080104      // 32-bit floats, 1 item
#define DUMP_FLOAT64   0x00080208      // 64-bit floats, 2 items
#define DUMP_FLOAT64S  0x00080108      // 64-bit floats, 1 item
#define DUMP_FLOAT80   0x0008010A      // 80-bit floats
#define DUMP_ADDR      0x00090104      // Address dump
#define DUMP_ADDRASC   0x000A0104      // Address dump with ASCII text
#define DUMP_ADDRUNI   0x000B0104      // Address dump with UNICODE text
#define DUMP_DISASM    0x000C0110      // Disassembly (max. 16 bytes per cmd)
#define DUMP_DECODE    0x000D0110      // Decoded data (max. 16 bytes per line)

// Types of dump menu in t_dump.menutype.
#define DMT_FIXTYPE    0x00000001      // Fixed dump type, no change
#define DMT_STRUCT     0x00000002      // Dump of the structure
#define DMT_CPUMASK    0x00070000      // Dump belongs to CPU window
#define   DMT_CPUDASM  0x00010000      // This is CPU Disassembler pane
#define   DMT_CPUDUMP  0x00020000      // This is CPU Dump pane
#define   DMT_CPUSTACK 0x00040000      // This is CPU Stack pane

// Modes of Scrolldumpwindow().
#define SD_REALIGN     0x01            // Realign on specified address
#define SD_CENTERY     0x02            // Center destination vertically

// Modes of t_dump.dumpselfunc() and Reportdumpselection().
#define SCH_SEL0       0x01            // t_dump.sel0 changed
#define SCH_SEL1       0x02            // t_dump.sel1 changed

// Modes of Copydumpselection().
#define CDS_TITLES     0x00000001      // Prepend window name and column titles
#define CDS_NOGRAPH    0x00000002      // Replace graphical symbols by spaces

typedef void DUMPSELFUNC(struct t_dump *,int);

typedef struct t_dump {                // Descriptor of dump data and window
  ulong          base;                 // Start of memory block or file
  ulong          size;                 // Size of memory block or file
  ulong          dumptype;             // Dump type, DU_xxx+count+size=DUMP_xxx
  ulong          menutype;             // Menu type, set of DMT_xxx
  ulong          itemwidth;            // Width of one item, characters
  ulong          threadid;             // Use decoding and registers if not 0
  t_table        table;                // Dump window is a custom table
  ulong          addr;                 // Address of first visible byte
  ulong          sel0;                 // Address of first selected byte
  ulong          sel1;                 // Last selected byte (not included!)
  ulong          selstart;             // Addr of first byte of selection start
  ulong          selend;               // Addr of first byte of selection end
  uchar          *filecopy;            // Copy of the file or NULL
  wchar_t        path[MAXPATH];        // Name of displayed file
  uchar          *backup;              // Old backup of memory/file or NULL
  wchar_t        strname[SHORTNAME];   // Name of the structure to decode
  uchar          *decode;              // Local decoding information or NULL
  wchar_t        bkpath[MAXPATH];      // Name of last used backup file
  int            relreg;               // Addresses relative to register
  ulong          reladdr;              // Addresses relative to this address
  ulong          hilitereg;            // One of OP_SOMEREG if reg highlighting
  int            hiregindex;           // Index of register to highlight
  ulong          graylimit;            // Gray data below this address
  DUMPSELFUNC    *dumpselfunc;         // Callback indicating change of sel0
} t_dump;

stdapi (void)    Setdumptype(t_dump *pd,ulong dumptype);
stdapi (int)     Ensurememorybackup(t_memory *pmem,int makebackup);
stdapi (void)    Backupusercode(struct t_module *pm,int force);
stdapi (HGLOBAL) Copydumpselection(t_dump *pd,int mode);
stdapi (ulong)   Dumpback(t_dump *pd,ulong addr,int n);
stdapi (ulong)   Dumpforward(t_dump *pd,ulong addr,int n);
stdapi (ulong)   Scrolldumpwindow(t_dump *pd,ulong addr,int mode);
stdapi (int)     Alignselection(t_dump *pd,ulong *sel0,ulong *sel1);
stdapi (int)     Getproclimits(ulong addr,ulong *amin,ulong *amax);
stdapi (int)     Getextproclimits(ulong addr,ulong *amin,ulong *amax);
stdapi (int)     Newdumpselection(t_dump *pd,ulong addr,ulong size);
stdapi (t_dump *) Findfiledump(wchar_t *path);
stdapi (HWND)    Createdumpwindow(wchar_t *title,ulong base,ulong size,
                   wchar_t *path,ulong dumptype,ulong sel0,ulong sel1,
                   wchar_t *strname);
stdapi (HWND)    Embeddumpwindow(HWND hw,t_dump *pd,ulong dumptype);


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// SEARCH ////////////////////////////////////

// Layouts of search panel.
#define SL_UNDEF       0               // Undefined layout
#define SL_DISASM      1               // Commands or refs within one module
#define SL_SEQASM      2               // Sequences within one module
#define SL_STRINGS     3               // Referenced strings within one module
#define SL_GUIDS       4               // Referenced GUIDs within one module
#define SL_COMMENTS    5               // All user-defined comments
#define SL_SWITCHES    6               // Switches and cascaded IFs
#define SL_FLOATS      7               // Referenced floats within one module
#define SL_CALLS       8               // Intermodular calls
#define SL_MOD         9               // Modifications

// Search types.
#define SEARCH_NONE    0               // Type is not yet defined
#define SEARCH_CMD     1               // Search for assembler commands
#define SEARCH_SEQ     2               // Search for the sequence of commands
#define SEARCH_BINARY  3               // Search for binary code
#define SEARCH_CONST   4               // Search for referenced constant range
#define SEARCH_MOD     5               // Search for modifications

// Search directions.
#define SDIR_GLOBAL    0               // Search forward from the beginning
#define SDIR_FORWARD   1               // Search forward from selection
#define SDIR_BACKWARD  2               // Search backward from selection

// Search modes.
#define SRCH_NEW       0               // Ask for new search pattern
#define SRCH_NEWMEM    1               // Ask for new pattern, memory mode
#define SRCH_SAMEDIR   2               // Search in the specified direction
#define SRCH_OPPDIR    3               // Search in the opposite direction
#define SRCH_MEM       4               // Search forward, memory mode

// Mode bits in Comparesequence().
#define CSEQ_IGNORECMD 0x00000001      // Ignore non-influencing commands
#define CSEQ_ALLOWJMP  0x00000002      // Allow jumps from outside

typedef struct t_found {               // Search result
  ulong          addr;                 // Address of found item
  ulong          size;                 // Size of found item, or 0 on error
} t_found;

typedef struct t_search {              // Descriptor of found item
  ulong          addr;                 // Address of found item
  ulong          size;                 // Must be 1
  ulong          type;                 // Type of found item, TY_xxx+SE_xxx
  ulong          data;                 // Mode-related data
  ulong          seqlen;               // Length of command sequence
} t_search;

stdapi (ulong)   Comparecommand(uchar *cmd,ulong cmdsize,ulong cmdip,
                   t_asmmod *model,int nmodel,int *pa,int *pb,t_disasm *da);
stdapi (ulong)   Comparesequence(uchar *cmd,ulong cmdsize,ulong cmdip,
                   uchar *decode,t_asmmod *model,int nmodel,int mode,
                   int *pa,int *pb,t_disasm *da,ulong *amatch,int namatch);


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// PATCHES ////////////////////////////////////

#define PATCHSIZE      512             // Maximal patch size, bytes

typedef struct t_patch {
  ulong          addr;                 // Base address of patch in memory
  ulong          size;                 // Size of patch, bytes
  ulong          type;                 // Type of patch, set of TY_xxx
  uchar          orig[PATCHSIZE];      // Original code
  uchar          mod[PATCHSIZE];       // Patched code
} t_patch;


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// BREAKPOINTS //////////////////////////////////

// Actions that must be performed if breakpoint of type BP_ONESHOT or BP_TEMP
// is hit.
#define BA_PERMANENT   0x00000001      // Permanent INT3 BP_TEMP on system call
#define BA_PLUGIN      0x80000000      // Pass notification to plugin

typedef struct t_bpoint {              // INT3 breakpoints
  ulong          addr;                 // Address of breakpoint
  ulong          size;                 // Must be 1
  ulong          type;                 // Type of breakpoint, TY_xxx+BP_xxx
  ushort         fnindex;              // Index of predefined function
  uchar          cmd;                  // First byte of original command
  uchar          patch;                // Used only in .udd files
  ulong          limit;                // Original pass count (0 if not set)
  ulong          count;                // Actual pass count
  ulong          actions;              // Actions, set of BA_xxx
} t_bpoint;

typedef struct t_bpmem {               // Memory breakpoints
  ulong          addr;                 // Address of breakpoint
  ulong          size;                 // Size of the breakpoint, bytes
  ulong          type;                 // Type of breakpoint, TY_xxx+BP_xxx
  ulong          limit;                // Original pass count (0 if not set)
  ulong          count;                // Actual pass count
} t_bpmem;

typedef struct t_bppage {              // Pages with modified attributes
  ulong          base;                 // Base address of memory page
  ulong          size;                 // Always PAGESIZE
  ulong          type;                 // Set of TY_xxx+BP_ACCESSMASK
  ulong          oldaccess;            // Initial access
  ulong          newaccess;            // Modified (actual) access
} t_bppage;

typedef struct t_bphard {              // Hardware breakpoints
  ulong          index;                // Index of the breakpoint (0..NHARD-1)
  ulong          dummy;                // Must be 1
  ulong          type;                 // Type of the breakpoint, TY_xxx+BP_xxx
  ulong          addr;                 // Address of breakpoint
  ulong          size;                 // Size of the breakpoint, bytes
  int            fnindex;              // Index of predefined function
  ulong          limit;                // Original pass count (0 if not set)
  ulong          count;                // Actual pass count
  ulong          actions;              // Actions, set of BA_xxx
  ulong          modbase;              // Module base, used by .udd only
  wchar_t        path[MAXPATH];        // Full module name, used by .udd only
} t_bphard;

stdapi (int)     Removeint3breakpoint(ulong addr,ulong type);
stdapi (int)     Setint3breakpoint(ulong addr,ulong type,int fnindex,
                   int limit,int count,ulong actions,
                   wchar_t *condition,wchar_t *expression,wchar_t *exprtype);
stdapi (int)     Enableint3breakpoint(ulong addr,int enable);
stdapi (int)     Confirmint3breakpoint(ulong addr);
stdapi (int)     Confirmhardwarebreakpoint(ulong addr);
stdapi (int)     Confirmint3breakpointlist(ulong *addr,int naddr);
stdapi (void)    Wipebreakpointrange(ulong addr0,ulong addr1);
stdapi (int)     Removemembreakpoint(ulong addr);
stdapi (int)     Setmembreakpoint(ulong addr,ulong size,ulong type,
                   int limit,int count,wchar_t *condition,
                   wchar_t *expression,wchar_t *exprtype);
stdapi (int)     Enablemembreakpoint(ulong addr,int enable);
stdapi (int)     Removehardbreakpoint(int index);
stdapi (int)     Sethardbreakpoint(int index,ulong size,ulong type,int fnindex,
                   ulong addr,int limit,int count,ulong actions,
                   wchar_t *condition,wchar_t *expression,wchar_t *exprtype);
stdapi (int)     Enablehardbreakpoint(int index,int enable);
stdapi (int)     Findfreehardbreakslot(ulong type);


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// CPU //////////////////////////////////////

// Mode bits for Setcpu().
#define CPU_ASMHIST    0x00000001      // Add change to Disassembler history
#define CPU_ASMCENTER  0x00000004      // Make address in the middle of window
#define CPU_ASMFOCUS   0x00000008      // Move focus to Disassembler
#define CPU_DUMPHIST   0x00000010      // Add change to Dump history
#define CPU_DUMPFIRST  0x00000020      // Make address the first byte in Dump
#define CPU_DUMPFOCUS  0x00000080      // Move focus to Dump
#define CPU_STACKFOCUS 0x00000100      // Move focus to Stack
#define CPU_STACKCTR   0x00000200      // Center stack instead moving to top
#define CPU_REGAUTO    0x00001000      // Automatically switch to FPU/MMX/3DNow!
#define CPU_NOCREATE   0x00002000      // Don't create CPU window if absent
#define CPU_REDRAW     0x00004000      // Redraw CPU window immediately
#define CPU_NOFOCUS    0x00008000      // Don't assign focus to main window
#define CPU_RUNTRACE   0x00010000      // asmaddr is run trace backstep
#define CPU_NOTRACE    0x00020000      // Stop run trace display

// Options for autoregtype.
#define ASR_OFF        0               // No FPU/MMX/3DNow! autoselection
#define ASR_EVENT      1               // Autoselection on debug events
#define ASR_ALWAYS     2               // Autoselection when command selected

#define NHISTORY       1024            // Length of history buffer, records

typedef struct t_histrec {             // Walk history record
  ulong          threadid;             // Thread ID, ignored by Dump pane
  ulong          dumptype;             // Dump type, ignored by Disasm pane
  ulong          addr;                 // Address of first visible line
  ulong          sel0;                 // Begin of selection
  ulong          sel1;                 // End of selection (not included)
} t_histrec;

// Note that hnext points to the free record following the last written, and
// hcurr points record that follows currently selected one.
typedef struct t_history {             // Walk history data
  t_histrec      h[NHISTORY];          // Circular buffer with history records
  int            holdest;              // Index of oldest valid record in h
  int            hnext;                // Index of first free record in h
  int            hcurr;                // Index of record following actual in h
} t_history;

stdapi (void)    Redrawcpudisasm(void);
stdapi (void)    Redrawcpureg(void);
stdapi (ulong)   Getcputhreadid(void);
stdapi (int)     Getcpuruntracebackstep(void);
stdapi (t_dump *) Getcpudisasmdump(void);
stdapi (ulong)   Getcpudisasmselection(void);
stdapi (t_table *) Getcpudisasmtable(void);
stdapi (void)    Addtohistory(t_history *ph,ulong threadid,ulong dumptype,
                   ulong addr,ulong sel0,ulong sel1);
stdapi (int)     Walkhistory(t_history *ph,int dir,ulong *threadid,
                   ulong *dumptype,ulong *addr,ulong *sel0,ulong *sel1);
stdapi (int)     Checkhistory(t_history *ph,int dir,int *isnewest);
stdapi (void)    Setcpu(ulong threadid,ulong asmaddr,ulong dumpaddr,
                   ulong selsize,ulong stackaddr,int mode);


////////////////////////////////////////////////////////////////////////////////
/////////////////////// DEBUGGING AND TRACING FUNCTIONS ////////////////////////

#define NIGNORE        32              // Max. no. of ignored exception ranges
#define NRTPROT        64              // No. of protocolled address ranges

#define FP_SYSBP       0               // First pause on system breakpoint
#define FP_TLS         1               // First pause on TLS callback, if any
#define FP_ENTRY       2               // First pause on program entry point
#define FP_WINMAIN     3               // First pause on WinMain, if known
#define FP_NONE        4               // Run program immediately

#define AP_SYSBP       0               // Attach pause on system breakpoint
#define AP_CODE        1               // Attach pause on program code
#define AP_NONE        2               // Run attached program immediately

#define DP_LOADDLL     0               // Loaddll pause on Loaddll entry point
#define DP_ENTRY       1               // Loaddll pause on DllEntryPoint()
#define DP_LOADED      2               // Loaddll pause after LoadLibrary()
#define DP_NONE        3               // Run Loaddll immediately

#define DR6_SET        0xFFFF0FF0      // DR6 bits specified as always 1
#define DR6_TRAP       0x00004000      // Single-step trap
#define DR6_BD         0x00002000      // Debug register access detected
#define DR6_BHIT       0x0000000F      // Some hardware breakpoint hit
#define   DR6_B3       0x00000008      // Hardware breakpoint 3 hit
#define   DR6_B2       0x00000004      // Hardware breakpoint 2 hit
#define   DR6_B1       0x00000002      // Hardware breakpoint 1 hit
#define   DR6_B0       0x00000001      // Hardware breakpoint 0 hit

#define DR7_GD         0x00002000      // Enable debug register protection
#define DR7_SET        0x00000400      // DR7 bits specified as always 1
#define DR7_EXACT      0x00000100      // Local exact instruction detection
#define DR7_G3         0x00000080      // Enable breakpoint 3 globally
#define DR7_L3         0x00000040      // Enable breakpoint 3 locally
#define DR7_G2         0x00000020      // Enable breakpoint 2 globally
#define DR7_L2         0x00000010      // Enable breakpoint 2 locally
#define DR7_G1         0x00000008      // Enable breakpoint 1 globally
#define DR7_L1         0x00000004      // Enable breakpoint 1 locally
#define DR7_G0         0x00000002      // Enable breakpoint 0 globally
#define DR7_L0         0x00000001      // Enable breakpoint 0 locally

#define DR7_IMPORTANT  (DR7_G3|DR7_L3|DR7_G2|DR7_L2|DR7_G1|DR7_L1|DR7_G0|DR7_L0)

#define NCOND          4               // Number of run trace conditions
#define NRANGE         2               // Number of memory ranges
#define NCMD           2               // Number of commands
#define NMODLIST       24              // Number of modules in pause list

// Run trace condition bits.
#define RTC_COND1      0x00000001      // Stop run trace if condition 1 is met
#define RTC_COND2      0x00000002      // Stop run trace if condition 2 is met
#define RTC_COND3      0x00000004      // Stop run trace if condition 3 is met
#define RTC_COND4      0x00000008      // Stop run trace if condition 4 is met
#define RTC_CMD1       0x00000010      // Stop run trace if command 1 matches
#define RTC_CMD2       0x00000020      // Stop run trace if command 2 matches
#define RTC_INRANGE    0x00000100      // Stop run trace if in range
#define RTC_OUTRANGE   0x00000200      // Stop run trace if out of range
#define RTC_COUNT      0x00000400      // Stop run trace if count is reached
#define RTC_MEM1       0x00001000      // Access to memory range 1
#define RTC_MEM2       0x00002000      // Access to memory range 2
#define RTC_MODCMD     0x00008000      // Attempt to execute modified command

// Run trace protocol types.
#define RTL_ALL        0               // Log all commands
#define RTL_JUMPS      1               // Taken jmp/call/ret/int + destinations
#define RTL_CDEST      2               // Call destinations only
#define RTL_MEM        3               // Access to memory

// Hit trace outside the code section.
#define HTNC_RUN       0               // Continue trace the same way as code
#define HTNC_PAUSE     1               // Pause hit trace if outside the code
#define HTNC_TRACE     2               // Trace command by command (run trace)

// SFX extraction mode.
#define SFM_RUNTRACE   0               // Use run trace to extract SFX
#define SFM_HITTRACE   1               // Use hit trace to extract SFX

typedef struct t_rtcond {              // Run trace break condition
  // These fields are saved to .udd data directly.
  int            options;              // Set of RTC_xxx
  ulong          inrange0;             // Start of in range
  ulong          inrange1;             // End of in range (not included)
  ulong          outrange0;            // Start of out range
  ulong          outrange1;            // End of out range (not included)
  ulong          count;                // Stop count
  ulong          currcount;            // Actual command count
  int            memaccess[NRANGE];    // Type of access (0:R, 1:W, 2:R/W)
  ulong          memrange0[NRANGE];    // Start of memory range
  ulong          memrange1[NRANGE];    // End of memory range
  // These fields are saved to .udd data truncated by first null.
  wchar_t        cond[NCOND][TEXTLEN]; // Conditions as text
  wchar_t        cmd[NCMD][TEXTLEN];   // Matching commands
  // These fields are not saved to .udd data.
  uchar          ccomp[NCOND][TEXTLEN];// Precompiled conditions
  int            validmodels;          // Valid command models, RTC_xxx
  t_asmmod       model[NCMD][NSEARCHCMD]; // Command search models
  int            nmodel[NCMD];         // Number of slots in each model
} t_rtcond;

typedef struct t_rtprot {              // Run trace protocol condition
  int            tracelogtype;         // Commands to protocol, one of RTL_xxx
  int            memranges;            // 0x1: range 1, 0x2: range 2 active
  int            memaccess[NRANGE];    // Type of access (0:R, 1:W, 2:R/W)
  ulong          memrange0[NRANGE];    // Start of memory range
  ulong          memrange1[NRANGE];    // End of memory range
  int            rangeactive;          // Log only commands in the range
  t_range        range[NRTPROT];       // Set of EIP ranges to protocol
} t_rtprot;

stdapi (void)    Suspendallthreads(void);
stdapi (void)    Resumeallthreads(void);
stdapi (int)     Pauseprocess(void);
stdapi (int)     Closeprocess(int confirm);
stdapi (int)     Detachprocess(void);
stdapi (int)     Getlasterror(t_thread *pthr,ulong *error,wchar_t *s);
stdapi (ulong)   Followcall(ulong addr);
stdapi (int)     Run(t_status status,int pass);
stdapi (int)     Checkfordebugevent(void);
stdapi (int)     Addprotocolrange(ulong addr0,ulong addr1);
stdapi (int)     Getruntrace(int nback,t_reg *preg,uchar *cmd);
stdapi (int)     Findruntracerecord(ulong addr0,ulong addr1);


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// LIST OF GUIDS /////////////////////////////////

#define GUIDSIZE       16              // GUID size, bytes

stdapi (int)     Getguidname(uchar *data,ulong ndata,wchar_t *name);
stdapi (int)     Isguid(ulong addr,wchar_t *name,int nname);


////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// SOURCE CODE //////////////////////////////////

typedef struct t_srcline {             // Descriptor of source line
  ulong          offset;               // Offset in source text
  int            nextent;              // Number of code extents (-1: unknown)
  int            extent;               // Index of first extent (nextent>0)
} t_srcline;

typedef struct t_srcext {              // Descriptor of code extent
  ulong          amin;                 // Address of the first command
  ulong          amax;                 // Address of last command, included
} t_srcext;

typedef struct t_source {              // Descriptor of source file
  ulong          addr;                 // Module base plus file index
  ulong          size;                 // Dummy parameter, must be 1
  ulong          type;                 // Type, TY_xxx+SRC_xxx
  wchar_t        path[MAXPATH];        // File path
  int            nameoffs;             // Name offset in path, characters
  char           *text;                // Source code in UTF-8 format or NULL
  t_srcline      *line;                // nline+1 line descriptors or NULL
  int            nline;                // Number of lines (0: as yet unknown)
  t_srcext       *extent;              // List of code extents
  int            maxextent;            // Capacity of extent table
  int            nextent;              // Current number of extents
  int            lastline;             // Last selected line
  int            lastoffset;           // Last topmost visible line
} t_source;

stdapi (t_source *) Findsource(ulong base,wchar_t *path);
stdapi (int)     Getsourceline(ulong base,wchar_t *path,int line,int skipspaces,
                   wchar_t *text,wchar_t *fname,t_srcext **extent,int *nextent);
stdapi (int)     Showsourcecode(ulong base,wchar_t *path,int line);


////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// DEBUGGEE ///////////////////////////////////

// Types of exception in application.
#define AE_NONE        0               // No exception, or caused by OllyDbg
#define AE_APP         1               // Exception in the application
#define AE_SYS         2               // System exception, don't pass

typedef struct t_run {                 // Run status of debugged application
  t_status       status;               // Operation mode, one of STAT_xxx
  ulong          threadid;             // ID of single running thread, 0 if all
  ulong          tpausing;             // Tick count when pausing was requested
  int            wakestep;             // 0: wait, 1: waked, 2: warned
  ulong          eip;                  // EIP at last debugging event
  ulong          ecx;                  // ECX at last debugging event
  ulong          restoreint3addr;      // Address of temporarily removed INT3
  ulong          stepoverdest;         // Destination of STAT_STEPOVER
  int            updatebppage;         // Update temporarily removed bppage's
  DEBUG_EVENT    de;                   // Information from WaitForDebugEvent()
  int            indebugevent;         // Paused on event, threads suspended
  int            netevent;             // Event is from .NET debugger
  int            isappexception;       // Exception in application, AE_xxx
  ulong          lastexception;        // Last exception in application or 0
  int            suspended;            // Suspension counter
  int            suspendonpause;       // Whether first suspension on pause
  int            updatedebugreg;       // 1: set, -1: reset HW breakpoints
  int            dregmodified;         // Debug regs modified by application
} t_run;


////////////////////////////////////////////////////////////////////////////////
//////////// OLLYDBG VARIABLES AND STRUCTURES ACCESSIBLE BY PLUGINS ////////////

// ATTENTION, never, ever change these variables directly! Either use plugin
// API or keep your hands off! Names of variables are preceded with underscore.

///////////////////////////////// DISASSEMBLER /////////////////////////////////

oddata (t_bincmd) bincmd[];            // List of 80x86 commands

oddata (wchar_t *) regname[3][NREG];   // Names of 8/16/32-bit registers
oddata (wchar_t *) segname[NREG];      // Names of segment registers
oddata (wchar_t *) fpuname[2][NREG];   // FPU regs (ST(n) and STn forms)
oddata (wchar_t *) mmxname[NREG];      // Names of MMX/3DNow! registers
oddata (wchar_t *) ssename[NREG];      // Names of SSE registers
oddata (wchar_t *) crname[NREG];       // Names of control registers
oddata (wchar_t *) drname[NREG];       // Names of debug registers
oddata (wchar_t *) sizename[17];       // Data size keywords
oddata (wchar_t *) sizekey[17];        // Keywords for immediate data
oddata (wchar_t *) sizeatt[17];        // Keywords for immediate data, AT&T

/////////////////////////////// OLLYDBG SETTINGS ///////////////////////////////

oddata (wchar_t) ollyfile[MAXPATH];    // Path to OllyDbg
oddata (wchar_t) ollydir[MAXPATH];     // OllyDbg directory w/o backslash
oddata (wchar_t) systemdir[MAXPATH];   // Windows system directory
oddata (wchar_t) plugindir[MAXPATH];   // Plugin data dir without backslash

oddata (HINSTANCE) hollyinst;          // Current OllyDbg instance
oddata (HWND)    hwollymain;           // Handle of the main OllyDbg window
oddata (HWND)    hwclient;             // Handle of MDI client or NULL
oddata (wchar_t) ottable[SHORTNAME];   // Class of table windows
oddata (ulong)   cpufeatures;          // CPUID feature information
oddata (int)     ischild;              // Whether child debugger

oddata (int)     asciicodepage;        // Code page to display ASCII dumps
#ifdef FILE                            // Requires <stdio.h>
oddata (FILE *)  tracefile;            // System log file or NULL
#endif
oddata (int)     restorewinpos;        // Restore window position & appearance

////////////////////////////// OLLYDBG STRUCTURES //////////////////////////////

oddata (t_font)  font[NFIXFONTS];      // Fixed fonts used in table windows
oddata (t_font)  sysfont;              // Proportional system font
oddata (t_font)  titlefont;            // Proportional, 2x height of sysfont
oddata (t_font)  fixfont;              // Fixed system font
oddata (COLORREF) color[NCOLORS];      // Colours used by OllyDbg
oddata (t_scheme) scheme[NSCHEMES];    // Colour schemes used in table windows
oddata (t_scheme) hilite[NHILITE];     // Colour schemes used for highlighting

/////////////////////////////////// DEBUGGEE ///////////////////////////////////

oddata (wchar_t) executable[MAXPATH];  // Path to main (.exe) file
oddata (wchar_t) arguments[ARGLEN];    // Command line passed to debuggee

oddata (int)     netdbg;               // .NET debugging active
oddata (int)     rundll;               // Debugged file is a DLL
oddata (HANDLE)  process;              // Handle of Debuggee or NULL
oddata (ulong)   processid;            // Process ID of Debuggee or 0
oddata (ulong)   mainthreadid;         // Thread ID of main thread or 0
oddata (t_run)   run;                  // Run status of debugged application
oddata (int)     skipsystembp;         // First system INT3 not yet hit

oddata (ulong)   debugbreak;           // Address of DebugBreak() in Debuggee
oddata (ulong)   dbgbreakpoint;        // Address of DbgBreakPoint() in Debuggee
oddata (ulong)   kiuserexcept;         // Address of KiUserExceptionDispatcher()
oddata (ulong)   zwcontinue;           // Address of ZwContinue() in Debuggee
oddata (ulong)   uefilter;             // Address of UnhandledExceptionFilter()
oddata (ulong)   ntqueryinfo;          // Address of NtQueryInformationProcess()
oddata (ulong)   corexemain;           // Address of MSCOREE:_CorExeMain()
oddata (ulong)   peblock;              // Address of PE block in Debuggee
oddata (ulong)   kusershareddata;      // Address of KUSER_SHARED_DATA
oddata (ulong)   userspacelimit;       // Size of virtual process memory

oddata (t_rtcond) rtcond;              // Run trace break condition
oddata (t_rtprot) rtprot;              // Run trace protocol condition

///////////////////////////////// DATA TABLES //////////////////////////////////

oddata (t_table) list;                 // List descriptor
oddata (t_sorted) premod;              // Preliminary module data
oddata (t_table) module;               // Loaded modules
oddata (t_sorted) aqueue;              // Modules that are not yet analysed
oddata (t_table) thread;               // Active threads
oddata (t_table) memory;               // Allocated memory blocks
oddata (t_table) win;                  // List of windows
oddata (t_table) bpoint;               // INT3 breakpoints
oddata (t_table) bpmem;                // Memory breakpoints
oddata (t_sorted) bppage;              // Memory pages with changed attributes
oddata (t_table) bphard;               // Hardware breakpoints
oddata (t_table) watch;                // Watch expressions
oddata (t_table) patch;                // List of patches from previous runs
oddata (t_sorted) procdata;            // Descriptions of analyzed procedures
oddata (t_table) source;               // List of source files
oddata (t_table) srccode;              // Source code


////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// PLUGIN EXPORTS ////////////////////////////////

// Relatively infrequent events passed to ODBG2_Pluginnotify().
#define PN_NEWPROC     1               // New process is created
#define PN_ENDPROC     2               // Process is terminated
#define PN_NEWTHR      3               // New thread is created
#define PN_ENDTHR      4               // Thread is terminated
#define PN_PREMOD      5               // New module is reported by Windows
#define PN_NEWMOD      6               // New module is added to the table
#define PN_ENDMOD      7               // Module is removed from the memory
#define PN_STATUS      8               // Execution status has changed
#define PN_REMOVE      16              // OllyDbg removes analysis from range
#define PN_RUN         24              // User continues code execution

// Flags returned by ODBG2_Pluginexception().
#define PE_IGNORED     0x00000000      // Plugin does not process exception
#define PE_CONTINUE    0x00000001      // Exception by plugin, continue
#define PE_STEP        0x00000002      // Exception by plugin, execute command
#define PE_PAUSE       0x00000004      // Exception by plugin, pause program

pentry (int)         ODBG2_Pluginquery(int ollydbgversion,ulong *features,
                       wchar_t pluginname[SHORTNAME],
                       wchar_t pluginversion[SHORTNAME]);
pentry (int)         ODBG2_Plugininit(void);
pentry (void)        ODBG2_Pluginanalyse(t_module *pmod);
pentry (void)        ODBG2_Pluginmainloop(DEBUG_EVENT *debugevent);
pentry (int)         ODBG2_Pluginexception(t_run *prun,const t_disasm *da,
                       t_thread *pthr,t_reg *preg,wchar_t *message);
pentry (void)        ODBG2_Plugintempbreakpoint(ulong addr,
                       const t_disasm *da,t_thread *pthr,t_reg *preg);
pentry (void)        ODBG2_Pluginnotify(int code,void *data,
                       ulong parm1,ulong parm2);
pentry (int)         ODBG2_Plugindump(t_dump *pd,wchar_t *s,uchar *mask,
                       int n,int *select,ulong addr,int column);
pentry (t_menu *)    ODBG2_Pluginmenu(wchar_t *type);
pentry (t_control *) ODBG2_Pluginoptions(UINT msg,WPARAM wp,LPARAM lp);
pentry (void)        ODBG2_Pluginsaveudd(t_uddsave *psave,t_module *pmod,
                       int ismainmodule);
pentry (void)        ODBG2_Pluginuddrecord(t_module *pmod,int ismainmodule,
                       ulong tag,ulong size,void *data);
pentry (void)        ODBG2_Pluginreset(void);
pentry (int)         ODBG2_Pluginclose(void);
pentry (void)        ODBG2_Plugindestroy(void);

#endif                                 // __ODBG_PLUGIN_H

