/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _PRO_H
#define _PRO_H

/*
  This is the first header included in IDA project.
  It defines the most common types, functions and data.
  Also, it tries to make system dependent definitions.

  The following preprocessor macros are used in the project
  (the list may be incomplete)

  Platform must be specified as one of:

   __OS2__     OS/2
   __MSDOS__   MS DOS 32-bit extender
   __NT__      MS Windows (all platforms)
   __LINUX__   Linux
   __MAC__     MAC OS X
   __BSD__     FreeBSD

   UNDER_CE    Compiling for WindowsCE

   __EA64__    64-bit address size (sizeof(ea_t)==8)
   __X64__     64-bit IDA itself (sizeof(void*)==8)

   __X86__     Intel x86 processor (default)
   __PPC__     PowerPC
   __ARM__     ARM

*/

#define IDA_SDK_VERSION      630        // IDA SDK v6.3

// x86 processor by default
#ifndef __PPC__
#define __X86__
#endif

// Linux, Mac, or BSD imply Unix
#if defined(__LINUX__) || defined(__MAC__) || defined(__BSD__)
#define __UNIX__
#endif

#ifdef __PLUGIN__
#if defined(__LP64__) || defined(_M_X64)
#error Do not build plugins for x64! IDA64 is a 32-bit executable.
#endif
#endif

// Only 64-bit IDA is available on 64-bit plaforms
#ifdef __X64__
#undef __EA64__
#define __EA64__
#endif

#ifdef __X64__
#define BADMEMSIZE 0xDEADBEEFDEADBEEF
#else
#define BADMEMSIZE 0xDEADBEEF
#endif

#ifndef SWIG
#if defined(__VC__) && !defined(_lint)
#define ENUM_SIZE(t) : t
#else
#define ENUM_SIZE(t)
#endif

#include <stdlib.h>     /* size_t, NULL, memory */
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <new>
#if defined(__NT__)
#  include <malloc.h>
#endif

#if defined(__BORLANDC__)
#  define WIN32_LEAN_AND_MEAN   // to compile faster
#  include <io.h>
#  include <dir.h>
#  include <mem.h>
#  include <alloc.h>
#elif defined(_MSC_VER)
#  include <string.h>
#  ifndef UNDER_CE
#    include <io.h>
#    include <direct.h>
#  endif
#  include <map>
#else
#  include <algorithm>
#  include <wchar.h>
#  include <string.h>
#  include <unistd.h>
#  include <sys/stat.h>
#  include <errno.h>
#endif
#ifdef UNDER_CE         // Many files are missing in Windows CE
void abort(void);
typedef int off_t;
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#pragma pack(push, 4)
#define STL_SUPPORT_PRESENT
//---------------------------------------------------------------------------
#ifdef __cplusplus
#define EXTERNC         extern "C"
#define C_INCLUDE       EXTERNC {
#define C_INCLUDE_END   }
#define INLINE          inline
#else
#define EXTERNC
#define C_INCLUDE
#define C_INCLUDE_END
#define INLINE          __inline
#endif

//---------------------------------------------------------------------------
#if !defined(__OS2__) && !defined(__MSDOS__) && !defined(__NT__) \
 && !defined(__LINUX__) && !defined(__MAC__) && !defined(__BSD__)
#error "Please define one of: __NT__, __OS2__, __MSDOS__, __LINUX__,__MAC__,__BSD__"
#endif

#endif // SWIG
//---------------------------------------------------------------------------
#ifndef MAXSTR
#define MAXSTR 1024
#endif

#define SMAXSTR QSTRINGIZE(MAXSTR)

// Some NT functions require __cdecl calling convention
#ifdef __NT__
#define NT_CDECL __cdecl
#else
#define NT_CDECL
#endif

// GNU C and CodeGear do not allow enum name; without initializers
#if defined(__GNUC__) || defined(__CODEGEARC__) || defined(_lint)
#define FORBID_UNINITED_ENUMS
#endif

#if defined(SWIG)
#define DEPRECATED
#define NORETURN                                // function does not return
#define PACKED                                  // type is packed
#define AS_PRINTF(format_idx, varg_idx)         // function accepts printf-style format
#define AS_SCANF(format_idx, varg_idx)          // function accepts scanf-style format
#elif defined(__GNUC__)
#define DEPRECATED __attribute__((deprecated))
#define NORETURN  __attribute__((noreturn))
#define PACKED __attribute__((__packed__))
#define AS_PRINTF(format_idx, varg_idx) __attribute__((format(printf, format_idx, varg_idx)))
#define AS_SCANF(format_idx, varg_idx)  __attribute__((format(scanf, format_idx, varg_idx)))
#else
#define DEPRECATED __declspec(deprecated)
#define NORETURN  __declspec(noreturn)
#define PACKED
#define AS_PRINTF(format_idx, varg_idx)
#define AS_SCANF(format_idx, varg_idx)
#endif

#if defined(DONT_DEPRECATE) || defined(__BORLANDC__)
#undef DEPRECATED
#define DEPRECATED
#endif

//---------------------------------------------------------------------------

#define __MF__  0               // Byte sex of our platform
                                // (Most significant byte First)
                                // 0 - little endian (Intel 80x86)
                                // 1 - big endian (PowerPC)

//---------------------------------------------------------------------------
/* Macro to avoid of message 'Parameter x is never used' */
#define qnotused(x)   (void)x

// GNU C complains about some data types in va_arg because they are promoted to int
// and proposes to replace them by int.
#ifdef __GNUC__
#define va_argi(va, type)  ((type)va_arg(va, int))
#else
#define va_argi(va, type)  va_arg(va, type)
#endif

//---------------------------------------------------------------------------
#define CONST_CAST(x)   const_cast<x>
#define _QSTRINGIZE(x)  #x
#define QSTRINGIZE(x)   _QSTRINGIZE(x)

//---------------------------------------------------------------------------

#if defined(SWIG)                       // for SWIG
  #define idaapi
  #define idaman
  #define ida_export
  #define ida_export_data
  #define ida_module_data
  #define __fastcall
  #define ida_local
#elif defined(__NT__)                   // MS Windows
  #define idaapi            __stdcall
  #define ida_export        idaapi
  #if defined(__IDP__)                  // modules
    #define idaman          EXTERNC
    #define ida_export_data __declspec(dllimport)
    #define ida_module_data __declspec(dllexport)
  #else                                 // kernel
    #if defined(__X64__) || defined(__NOEXPORT__)
      #define idaman          EXTERNC
    #else
      #define idaman          EXTERNC __declspec(dllexport)
    #endif
    #define ida_export_data
    #define ida_module_data
  #endif
  #define ida_local
#elif defined(__UNIX__)                 // for unix
  #define idaapi
  #if defined(__MAC__)
    #define idaman          EXTERNC __attribute__((visibility("default")))
    #define ida_local       __attribute__((visibility("hidden")))
  #else
    #if __GNUC__ >= 4
      #define idaman          EXTERNC __attribute__ ((visibility("default")))
      #define ida_local       __attribute__((visibility("hidden")))
    #else
      #define idaman          EXTERNC
      #define ida_local
    #endif
  #endif
  #define ida_export
  #define ida_export_data
  #define ida_module_data
  #define __fastcall
#endif

// functions callable from any thread are marked with this keyword:
#define THREAD_SAFE

//---------------------------------------------------------------------------
#ifndef __cplusplus
typedef int bool;
#define false 0
#define true 1
#endif

//---------------------------------------------------------------------------
// Linux C mode compiler already has these types defined
#if !defined(__LINUX__) || defined(__cplusplus)
typedef unsigned char  uchar;
typedef unsigned short ushort;
typedef unsigned int   uint;
#endif

typedef          char   int8;
typedef signed   char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef unsigned short  uint16;
typedef          int    int32;
typedef unsigned int    uint32;

#include <llong.hpp>

typedef longlong        int64;
typedef ulonglong       uint64;

#if defined(__BORLANDC__) || defined(_MSC_VER)
typedef wchar_t         wchar16_t;
typedef uint32          wchar32_t;
#elif defined(__GNUC__)
typedef uint16          wchar16_t;
typedef uint32          wchar32_t;
#endif

// signed size_t - used to check for size overflows when the counter becomes
// negative. also signed size_t allows us to signal an error condition using
// a negative value, for example, as a function return value.
#if !defined(_SSIZE_T_DEFINED) && !defined(__ssize_t_defined) && !defined(__GNUC__)
#ifdef __X64__
typedef int64 ssize_t;
#else
typedef int32 ssize_t;
#endif
#endif

// define compiler-specific printf format specifiers
// for 64-bit numbers and size_t/ssize_t
#if defined(__GNUC__) && !defined(__MINGW32__)
  #define FMT_64 "ll"
  #define FMT_Z  "zu"
  #define FMT_ZS "zd"
#elif defined(_MSC_VER) || defined(__MINGW32__)
  #define FMT_64 "I64"
  #ifdef __X64__
    #define FMT_Z  "uI64"
    #define FMT_ZS "dI64"
  #else
    #define FMT_Z  "u"
    #define FMT_ZS "d"
  #endif
#elif defined(__BORLANDC__)
  #define FMT_64 "L"
  #define FMT_Z  "u"
  #define FMT_ZS "d"
#elif !defined(SWIG)
  #error "unknown compiler"
#endif

#ifdef __EA64__
  typedef uint64 ea_t;      // effective address
  typedef uint64 sel_t;     // segment selector
  typedef uint64 asize_t;   // memory chunk size
  typedef int64 adiff_t;    // address difference
  #define FMT_EA FMT_64
  #ifdef __GNUC__
    #define SVAL_MIN LLONG_MIN
    #define SVAL_MAX LLONG_MAX
  #else
    #define SVAL_MIN _I64_MIN
    #define SVAL_MAX _I64_MAX
  #endif
#else
  typedef uint32 ea_t;      // effective address
  typedef uint32 sel_t;     // segment selector
  typedef uint32 asize_t;   // memory chunk size
  typedef int32 adiff_t;    // address difference
  #define SVAL_MIN INT_MIN
  #define SVAL_MAX INT_MAX
  #define FMT_EA ""
#endif

typedef asize_t uval_t;   // unsigned value used by the processor
                          // for 32-bit ea_t, uint32
                          // for 64-bit ea_t, uint64
typedef adiff_t sval_t;   // signed value used by the processor
                          // for 32-bit ea_t, int32
                          // for 64-bit ea_t, int64
#ifndef SWIG
#define BADADDR ea_t(-1)  // this value is used for 'bad address'
#define BADSEL  sel_t(-1) // 'bad selector' value

//-------------------------------------------------------------------------
// Time related functions

typedef int32 qtime32_t;  // We use our own time type because time_t
                          // can be 32-bit or 64-bit depending on the compiler
typedef uint64 qtime64_t; // 64-bit time value expressed as seconds and
                          // microseconds since the Epoch

idaman THREAD_SAFE bool ida_export qctime(char *buf, size_t bufsize, qtime32_t t); // puts 'wrong timestamp\n' into the buffer if failed
idaman THREAD_SAFE bool ida_export qlocaltime(struct tm *_tm, qtime32_t t);
idaman THREAD_SAFE size_t ida_export qstrftime(char *buf, size_t bufsize, const char *format, qtime32_t t);
idaman THREAD_SAFE size_t ida_export qstrftime64(char *buf, size_t bufsize, const char *format, qtime64_t t);

idaman THREAD_SAFE void ida_export qsleep(int milliseconds);

// High resolution timer. On Unix systems, returns current time in nanoseconds
// On Windows, returns a high resolution counter (QueryPerformanceCounter)

idaman THREAD_SAFE void ida_export get_nsec_stamp(uint64 *nsecs);

// Get the current time with microsecond resolution (in fact the resolution
// is worse on windows)

idaman THREAD_SAFE qtime64_t ida_export qtime64(void);

// return the 'seconds since the epoch' part of qtime64_t
inline THREAD_SAFE bool qlocaltime64(struct tm *_tm, qtime64_t t)
{
  return qlocaltime(_tm, t >> 32);
}

// return the microseconds part of qtime64_t
inline uint32 get_usecs(qtime64_t t)
{
  return uint32(t);
}

// Generate a random buffer with a given size

idaman THREAD_SAFE bool ida_export gen_rand_buf(void *buffer, size_t bufsz);


// Windows64 declarations
#if defined(__VC__) && defined(__X64__)
#define __VC64__
#define qstat _stat64
#define qfstat _fstat64
#define qstatbuf struct __stat64
#else
#define qstat stat
#define qfstat fstat
#define qstatbuf struct stat
#endif

// non standard functions are missing:
#ifdef _MSC_VER
//AS_SCANF(2, 0) int idaapi vsscanf(const char *input, const char *format, va_list va);
#if _MSC_VER <= 1200
#define for if(0) ; else for  // MSVC is not compliant to the ANSI standard :(
#else
#pragma warning(disable : 4200) // zero-sized array in structure (non accept from cmdline)
#endif
// visual studio deprecated posix names but it seems that there is no good
// reason for that. the following definitions are to shut up visual studio
#define chdir  _chdir
#define fileno _fileno
#define getcwd _getcwd
#define memicmp _memicmp
#endif

// Is this IDA kernel? If not, we are executing a standalone application.
idaman bool ida_export_data is_ida_kernel;

//---------------------------------------------------------------------------
/* error codes */
/*--------------------------------------------------*/

#define eOk           0    /* No error             */
#define eOS           1    /* OS error, see errno  */
#define eDiskFull     2    /* Disk Full            */
#define eReadError    3    /* Read Error           */
#define eFileTooLarge 4    /* File too large       */

typedef int error_t;

idaman THREAD_SAFE error_t ida_export set_qerrno(error_t code);
idaman THREAD_SAFE error_t ida_export get_qerrno(void);

//---------------------------------------------------------------------------
enum ostype_t
{
   osMSDOS,
   osAIX_RISC,
   osOS2,
   osNT,
   osLINUX,
   osMACOSX,
   osBSD,
};

extern ostype_t ostype;

//---------------------------------------------------------------------------
// debugging macros
#define ZZZ msg("%s:%d\n", __FILE__, __LINE__)
#if defined(__BORLANDC__)
#  define BPT __emit__(0xcc)
#  define __FUNCTION__ __FUNC__
#elif defined(__GNUC__)
#  ifdef __arm__
#    ifdef __LINUX__
#      define BPT __builtin_trap()
#    else
#      define BPT asm("trap")
#    endif
#  else
#    define BPT asm("int3")
#  endif
#elif defined(_MSC_VER) // Visual C++
#  define BPT __debugbreak()
#  ifdef _lint
     NORETURN void __debugbreak(void);
#  endif
#endif

// compile time assertion
#ifdef _lint
#define CASSERT(cnd) extern int pclint_cassert_dummy_var
#else
#define __CASSERT_N0__(l) COMPILE_TIME_ASSERT_ ## l
#define __CASSERT_N1__(l) __CASSERT_N0__(l)
#define CASSERT(cnd) typedef char __CASSERT_N1__(__LINE__) [(cnd) ? 1 : -1]
#endif

// run time assertion
#if defined(UNDER_CE) || defined(_lint)
#define INTERR(code) interr(code)
#else
#define INTERR(code) do { if ( under_debugger ) BPT; interr(code); } while(1)
#endif
#define QASSERT(code, cond) do if ( !(cond) ) INTERR(code); while (0)
#define QBUFCHECK(buf, size, src) ida_fill_buffer(buf, size, src, __FILE__, __LINE__)
idaman bool ida_export_data under_debugger;
idaman THREAD_SAFE NORETURN void ida_export interr(int code);

//#define TOUGH_BUFFER_CHECK
#ifdef TOUGH_BUFFER_CHECK
idaman
void ida_fill_buffer(void *buf,
                     ssize_t size,
                     const void *src,
                     const char *file,
                     int line);
#else
#define ida_fill_buffer(buf, size, src, file, line)
#endif

CASSERT(sizeof(int16) == 2);
CASSERT(sizeof(int32) == 4);
CASSERT(sizeof(int64) == 8);
//---------------------------------------------------------------------------
idaman THREAD_SAFE void *ida_export qalloc(size_t size);
idaman THREAD_SAFE void *ida_export qrealloc(void *alloc, size_t newsize);
idaman THREAD_SAFE void *ida_export qcalloc(size_t nitems, size_t itemsize);
idaman THREAD_SAFE void  ida_export qfree(void *alloc);
idaman THREAD_SAFE char *ida_export qstrdup(const char *string);
#define qnew(t)        ((t*)qalloc(sizeof(t)))
#ifdef NO_OBSOLETE_FUNCS
// qalloc_array is safer than qnewarray
#define qnewarray(t,n)  use_qalloc_array
#else
#define qnewarray(t,n) ((t*)qcalloc((n),sizeof(t)))
#endif

// Use this class to avoid integer overflows when allocating arrays
template <class T>
T *qalloc_array(size_t n)
{
  return (T *)qcalloc(n, sizeof(T));
}

template <class T>
T *qrealloc_array(T *ptr, size_t n)
{
  size_t nbytes = n * sizeof(T);
  if ( nbytes < n )
    return NULL; // integer overflow
  return (T *)qrealloc(ptr, nbytes);
}

#define qnumber(a)     (sizeof(a)/sizeof((a)[0]))

// gcc complains about offsetof(), we had make our version
#ifdef __GNUC__
#define qoffsetof(type, name) size_t(((char *)&((type *)1)->name)-(char*)1)
#else
#define qoffsetof offsetof
#endif

// gcc64 uses special 24-bit va_list. copy it with memcpy
#if defined(__GNUC__) && defined(__X64__)
  #define va_assign(dst, src) memcpy(&dst, src, sizeof(dst))
  #define set_vva(va2, vp) va_assign(va2, va_arg(vp, void*))
#else
  #define va_assign(dst, src) dst = src
  #define set_vva(va2, vp) va_assign(va2, va_arg(vp, va_list))
#endif

// Reverse memory block
// (the first byte is exchanged with the last bytes, etc.)
// analog of strrev() function
//      buf - pointer to buffer to reverse
//      size - size of buffer
// returns: pointer to buffer

idaman THREAD_SAFE void *ida_export memrev(void *buf, ssize_t size);

#ifdef __GNUC__
idaman THREAD_SAFE int ida_export memicmp(const void *x, const void *y, size_t size);
#endif

//---------------------------------------------------------------------------
/* strings */
#ifdef __GNUC__
#define strnicmp strncasecmp
#define stricmp  strcasecmp
#elif defined(_MSC_VER) && !defined(_lint)
#define strnicmp _strnicmp
#define stricmp  _stricmp
#endif
//---------------------------------------------------------------------------
char *strcompact(char *string);
char *strcenter(char *s, size_t len);

// Replace all entries of 'char1' by 'char2' in string 'str'

idaman THREAD_SAFE char *ida_export strrpl(char *str, int char1, int char2);

// Get tail of a string

inline       char *tail(      char *str) { return strchr(str, '\0'); }
inline const char *tail(const char *str) { return strchr(str, '\0'); }


// qstrncpy makes sure that there is a terminating zero
// nb: this function doesn't fill the whole buffer zeroes as strncpy does

idaman THREAD_SAFE char *ida_export qstrncpy(char *dst, const char *src, size_t dstsize);


// qstpncpy returns pointer to the end of the destination

idaman THREAD_SAFE char *ida_export qstpncpy(char *dst, const char *src, size_t dstsize);


// nb: qstrncat() accepts the size of the 'dst' as 'dstsize' and returns dst

idaman THREAD_SAFE char *ida_export qstrncat(char *dst, const char *src, size_t dstsize);

// thread-safe version of strtok
idaman THREAD_SAFE char *ida_export qstrtok(char *s, const char *delim, char **save_ptr);


// convert the string to uppercase or lowercase
idaman THREAD_SAFE char *ida_export qstrlwr(char *str);
idaman THREAD_SAFE char *ida_export qstrupr(char *str);

// Find one string in another.
// Case insensivite analog of strstr()

idaman THREAD_SAFE const char *ida_export stristr(const char *s1, const char *s2);
inline char *idaapi stristr(char *s1, const char *s2) { return CONST_CAST(char *)(stristr((const char *)s1, s2)); }

// is...() functions misbehave with 'char' argument. introduce more robust functions:
inline bool ida_local qisspace(char c) { return isspace(uchar(c)) != 0; }
inline bool ida_local qisalpha(char c) { return isalpha(uchar(c)) != 0; }
inline bool ida_local qisalnum(char c) { return isalnum(uchar(c)) != 0; }
inline bool ida_local qispunct(char c) { return ispunct(uchar(c)) != 0; }
inline bool ida_local qislower(char c) { return islower(uchar(c)) != 0; }
inline bool ida_local qisupper(char c) { return isupper(uchar(c)) != 0; }
inline bool ida_local qisprint(char c) { return isprint(uchar(c)) != 0; }
inline bool ida_local qisdigit(char c) { return isdigit(uchar(c)) != 0; }
inline bool ida_local qisxdigit(char c) { return isxdigit(uchar(c)) != 0; }

inline char ida_local qtolower(char c) { return tolower(uchar(c)); }
inline char ida_local qtoupper(char c) { return toupper(uchar(c)); }

// We forbid using dangerous functions in IDA
#if !defined(USE_DANGEROUS_FUNCTIONS) && !defined(_lint)
#if defined(__BORLANDC__) && (__BORLANDC__ < 0x560  || __BORLANDC__ >= 0x580) // for BCB5 (YH)
#include <stdio.h>
#endif
#undef strcpy
#define strcpy          dont_use_strcpy            // use qstrcpy
#define stpcpy          dont_use_stpcpy            // use qstpncpy
#define strncpy         dont_use_strncpy           // use qstrncpy
#define strcat          dont_use_strcat            // use qstrncat
#define strncat         dont_use_strncat           // use qstrncat
#define gets            dont_use_gets              // use qfgets
#define sprintf         dont_use_sprintf           // use qsnprintf
#define snprintf        dont_use_snprintf          // use qsnprintf
#define wsprintfA       dont_use_wsprintf          // use qsnprintf
#undef strcmpi
#undef strncmpi
#define strcmpi         dont_use_strcmpi           // use stricmp
#define strncmpi        dont_use_strncmpi          // use strnicmp
#define getenv          dont_use_getenv            // use qgetenv
#define setenv          dont_use_setenv            // use qsetenv
#define putenv          dont_use_putenv            // use qsetenv
#define strtok          dont_use_strrok            // use qstrtok
#undef strlwr
#undef strupr
#define strlwr          dont_use_strlwr            // use qstrlwr
#define strupr          dont_use_strupr            // use qstrupr
#endif

//---------------------------------------------------------------------------
// Our definitions of qsnprintf/qsscanf support one additional format specifier
//
//      %a              which corresponds to ea_t
//
// Usual optional fields like the width can be used too: %04a
// The width specifier will be doubled for 64-bit version
// These function return the number of characters _actually written_ to the output string
// excluding the terminating zero. (which is different from the snprintf)
// They always terminate the output with a zero byte (if n > 0)
idaman AS_PRINTF(3, 0) THREAD_SAFE int ida_export qvsnprintf(char *buffer, size_t n, const char *format, va_list va);
idaman AS_SCANF (2, 0) THREAD_SAFE int ida_export qvsscanf(const char *input, const char *format, va_list va);
idaman AS_PRINTF(3, 4) THREAD_SAFE int ida_export qsnprintf(char *buffer, size_t n, const char *format, ...);
idaman AS_PRINTF(3, 4) THREAD_SAFE int ida_export append_snprintf(char *buf, const char *end, const char *format, ...);
idaman AS_SCANF (2, 3) THREAD_SAFE int ida_export qsscanf(const char *input, const char *format, ...);

//---------------------------------------------------------------------------
/* file name declarations */
/* maximum number of characters in path and file specification */
#if defined(__NT__)
#define QMAXPATH        260
#define QMAXFILE        260
#else
#define QMAXPATH        PATH_MAX
#define QMAXFILE        PATH_MAX
#endif


// construct 'path' from component's list terminated by NULL, return 'path'.
// It is forbidden to pass NULL as the output buffer
// buf may be == s1
// Returns pointer to buf

idaman THREAD_SAFE char *ida_export vqmakepath(char *buf, size_t bufsize, const char *s1, va_list);
idaman THREAD_SAFE char *ida_export qmakepath(char *buf, size_t bufsize, const char *s1, ...);

// get the directory part of the path
//      buf      - out: buffer for the directory part. may be NULL.
//      bufsize  - out: size of this buffer
//      path     - in: path to split
// returns true if ok, false if input buffer did not have the directory part
//                     in this case the buffer is filled with "."
// path and buf may point to the same buffer

idaman THREAD_SAFE bool ida_export qdirname(char *buf, size_t bufsize, const char *path);


// construct filename from base name and extension, return 'file'.
// buf may be == base
// It is forbidden to pass NULL as the output buffer

idaman THREAD_SAFE char *ida_export qmakefile(
        char *buf,
        size_t bufsize,
        const char *base,
        const char *ext);


// split filename to base name and extension, you may specify NULL
// as 'base'/'ext' parameters. 'file' may be changed.
//  return the base part

idaman THREAD_SAFE char *ida_export qsplitfile(char *file, char **base, char **ext);


// Is the file name absolute (not relative to the current dir?)

idaman THREAD_SAFE bool ida_export qisabspath(const char *file);


// Get the file name part of the path
// path==NULL -> returns NULL

idaman THREAD_SAFE const char *ida_export qbasename(const char *path);
#ifdef __cplusplus
inline char *qbasename(char *path) { return CONST_CAST(char *)(qbasename((const char *)path)); }
#endif

// Convert relative path to absolute path

idaman THREAD_SAFE char *ida_export qmake_full_path(char *dst, size_t dstsize, const char *src);


// Searches for a file in the PATH environment variable or the current directory
//      file       - the file name to look for. If the file is an absolute path
//                   then buf will return the file value.
//      buf        - output buffer to hold the full file path
//      bufsize    - output buffer size
//      search_cwd - search the current directory if file was not found in the PATH
// returns: true if the file was found and false otherwise

idaman THREAD_SAFE bool ida_export search_path(
        const char *file,
        char *buf,
        size_t bufsize,
        bool search_cwd);

// Delimiter of directory lists
#if defined(__UNIX__)
#define DELIMITER       ":"     // Unix
#else
#define DELIMITER       ";"     // MS DOS, Windows, other systems
#endif

// Set file name extension unconditionally
//      outbuf  - buffer to hold the answer. may be the same
//                as the file name.
//      bufsize - output buffer size
//      file    - the file name
//      ext     - new extension (with or without '.')
// returns: pointer to the new file name

idaman THREAD_SAFE char *ida_export set_file_ext(
        char *outbuf,
        size_t bufsize,
        const char *file,
        const char *ext);


// Get pointer to extension of file name
//      file - file name
// returns: pointer to the file extension or NULL if extension doesn't exist

idaman THREAD_SAFE const char *ida_export get_file_ext(const char *file);
#ifdef __cplusplus
inline bool idaapi has_file_ext(const char *file)
  { return get_file_ext(file) != NULL; }
#endif

// Set file name extension if none exist
// This function appends the extension to a file name.
// It won't change file name if extension already exists
//      buf     - output buffer
//      bufsize - size of the output buffer
//      file    - file name
//      ext     - extension (with or without '.')
// returns: pointer to the new file name

#ifdef __cplusplus
inline char *idaapi make_file_ext(
        char *buf,
        size_t bufsize,
        const char *file,
        const char *ext)
{
  if ( has_file_ext(file) )
    return ::qstrncpy(buf, file, bufsize);
  else
    return set_file_ext(buf, bufsize, file, ext);
}
#endif

// Sanitize the file name
// Remove the directory path
// Replace wildcards ? * and chars<' ' by _
// If the file name is empty, then
//      namesize != 0: generate a new temporary name
//      namesize == 0: return false
// else return true

idaman THREAD_SAFE bool ida_export sanitize_file_name(char *name, size_t namesize);

//---------------------------------------------------------------------------
/* input/output */
/*--------------------------------------------------*/
#if !defined(__MSDOS__) && !defined(__OS2__) && !defined(__NT__) && !defined(_MSC_VER)
#define O_BINARY        0
#endif

#ifndef SEEK_SET
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2
#endif
/*--------------------------------------------------*/
/* you should use these functions for file i/o                */
/* they do the same as their counterparts from Clib.          */
/* the only difference is that they set 'qerrno' variable too */

idaman THREAD_SAFE int   ida_export qopen(const char *file, int mode);     /* open existing file */
idaman THREAD_SAFE int   ida_export qcreate(const char *file, int stat);   /* create new file with O_RDWR */
idaman THREAD_SAFE int   ida_export qread(int h, void *buf, size_t n);
idaman THREAD_SAFE int   ida_export qwrite(int h, const void *buf, size_t n);
idaman THREAD_SAFE int32 ida_export qtell(int h);
idaman THREAD_SAFE int32 ida_export qseek(int h, int32 offset, int whence);
idaman THREAD_SAFE int   ida_export qclose(int h);

// Return the file size.
// This function may return 0 if the file is not found or if the file is too large (>4GB).
// Call get_qerrno() and compare against eFileTooLarge to tell between the two cases.
idaman THREAD_SAFE uint32 ida_export qfilesize(const char *fname);

idaman THREAD_SAFE uint32 ida_export qfilelength(int h);            // -1 if error
idaman THREAD_SAFE int   ida_export qchsize(int h, uint32 fsize);
idaman THREAD_SAFE int   ida_export qmkdir(const char *file, int mode);
idaman THREAD_SAFE bool  ida_export qfileexist(const char *file);
idaman THREAD_SAFE bool  ida_export qisdir(const char *file);

//---------------------------------------------------------------------------
// add a function to be called at exit time
idaman THREAD_SAFE void ida_export qatexit(void (idaapi *func)(void));
// remove a previously added exit-time function
idaman THREAD_SAFE void ida_export del_qatexit(void (idaapi*func)(void));
#endif // SWIG
// call qatexit functions, shut down UI and kernel, and exit
idaman THREAD_SAFE NORETURN void ida_export qexit(int code);

//---------------------------------------------------------------------------
/* universal min, max */
/*--------------------------------------------------*/
#define qmin(a,b) ((a) < (b)? (a): (b))
#define qmax(a,b) ((a) > (b)? (a): (b))
#if defined(__EA64__) && defined(__VC__) && defined(__cplusplus)
#if _MSC_VER < 1600
static inline int64 abs(int64 n) { return _abs64(n); }
#endif
static inline int32 abs(uint32 n) { return abs((int32)n); }
#endif

//----------------------------------------------------------------------
// Bitmap operations
inline bool idaapi test_bit(const uchar *bitmap, size_t bit)
{
  return (bitmap[bit/8] & (1<<(bit&7))) != 0;
}

inline void idaapi set_bit(uchar *bitmap, size_t bit)
{
  uchar *p = bitmap + bit/8;
  *p = uchar(*p | (1<<(bit&7)));
}

inline void idaapi clear_bit(uchar *bitmap, size_t bit)
{
  uchar *p = bitmap + bit/8;
  *p = uchar(*p & ~(1<<(bit&7)));
}

inline void idaapi set_all_bits(uchar *bitmap, size_t nbits)
{
  memset(bitmap, 0xFF, (nbits+7)/8);
  if ( (nbits & 7) != 0 )
  {
    uchar *p = bitmap + nbits/8;
    *p = uchar(*p & ~((1 << (nbits&7))-1));
  }
}

inline void idaapi clear_all_bits(uchar *bitmap, size_t nbits)
{
  memset(bitmap, 0, (nbits+7)/8);
}

//----------------------------------------------------------------------
/// Function to work with intervals
namespace interval
{
  /// do (off1,s1) and (off2,s2) overlap?
  inline bool overlap(uval_t off1, asize_t s1, uval_t off2, asize_t s2)
  {
    return off2 < off1+s1 && off1 < off2+s2;
  }
  /// does (off1,s1) include (off2,s2)?
  inline bool includes(uval_t off1, asize_t s1, uval_t off2, asize_t s2)
  {
    return off2 >= off1 && off2+s2 <= off1+s1;
  }
  /// does (off1,s1) contain off?
  inline bool contains(uval_t off1, asize_t s1, uval_t off)
  {
    return off >= off1 && off < off1+s1;
  }
};

//----------------------------------------------------------------------
#ifdef __cplusplus
// rotate left
template<class T> T qrotl(T value, size_t count)
{
  const size_t nbits = sizeof(T) * 8;
  count %= nbits;

  T high = value >> (nbits - count);
  value <<= count;
  value |= high;
  return value;
}

// rotate right
template<class T> T qrotr(T value, size_t count)
{
  const size_t nbits = sizeof(T) * 8;
  count %= nbits;

  T low = value << (nbits - count);
  value >>= count;
  value |= low;
  return value;
}

// set a 'bit' in 'where' if 'value' if not zero
template<class T, class U> void idaapi setflag(T &where, U bit, bool cnd)
{
   if ( cnd )
     where = T(where | bit);
   else
     where = T(where & ~T(bit));
}

// check that unsigned multiplication does not overflow
template<class T> bool is_mul_ok(T count, T elsize)
{
  CASSERT((T)(-1) > 0); // make sure T is unsigned
  if ( elsize  == 0 || count == 0 )
    return true;
  return count <= ((T)(-1)) / elsize;
}

// GCC does not check for an integer overflow in 'operator new[]'. We have to do it
// ourselves. Please note that 'char' arrays can still be allocated with
// plain 'operator new'
#ifdef __GNUC__
#  define OPERATOR_NEW(type, count) (is_mul_ok(size_t(count), sizeof(type)) \
                                     ? new type[count] \
                                     : (type *)qalloc_or_throw(BADMEMSIZE))
#else
#  define OPERATOR_NEW(type, count) new type[count]
#endif

#endif

// BCB6 treats multicharacter constant differently from old versions
// We are forced to abandon them (it is good because they are not portable anyway)

#define MC2(c1, c2)          ushort(((c2)<<8)|c1)
#define MC3(c1, c2, c3)      uint32(((((c3)<<8)|(c2))<<8)|c1)
#define MC4(c1, c2, c3, c4)  uint32(((((((c4)<<8)|(c3))<<8)|(c2))<<8)|c1)

//---------------------------------------------------------------------------
/* Functions to read/write 2/4 byte entities.
        h - file handle
        res - value read from file
        size - size of value in bytes (1,2,4)
        mf - is MSB first?

   All these functions return 0 - Ok */

idaman THREAD_SAFE int ida_export readbytes(int h, uint32 *res, int size, bool mf);
idaman THREAD_SAFE int ida_export writebytes(int h, uint32 l, int size, bool mf);

idaman THREAD_SAFE int ida_export read2bytes(int h, uint16 *res, bool mf);
#define read4bytes(h, res, mf)  readbytes(h, res, 4, mf)
#define write2bytes(h, l, mf)   writebytes(h, l, 2, mf)
#define write4bytes(h, l, mf)   writebytes(h, l, 4, mf)

//---------------------------------------------------------------------------
#ifdef __cplusplus
#  ifndef swap32
inline uint32 swap32(uint32 x)
  { return (x>>24) | (x<<24) | ((x>>8) & 0x0000FF00L) | ((x<<8) & 0x00FF0000L); }
#  endif
#  ifndef swap16
inline ushort swap16(ushort x)
  { return ushort((x<<8) | (x>>8)); }
#  endif
#else
#  ifndef swap32
#    define swap32(x) uint32((x>>24) | (x<<24) | ((x>>8) & 0x0000FF00L) | ((x<<8) & 0x00FF0000L))
#  endif
#  ifndef swap16
#    define swap16(x) ushort((x<<8) | (x>>8))
#  endif
#endif

#ifdef __EA64__
#define swapea  swap64
#else
#define swapea  swap32
#endif

#if __MF__
#define qhtonl(x) (x)
#define qntohl(x) (x)
#define qhtons(x) (x)
#define qntohs(x) (x)
#else
#define qhtons(x) swap16(x)
#define qntohs(x) swap16(x)
#define qhtonl(x) swap32(x)
#define qntohl(x) swap32(x)
#endif

idaman THREAD_SAFE void ida_export swap_value(void *dst, const void *src, int size);
idaman THREAD_SAFE void ida_export reloc_value(void *value, int size, adiff_t delta, bool mf);

// Rotate a value
// this function can be used to rotate a value to the right
// if the count is negative
//  x - value to rotate
//  count - shift amount
//  bits - number of bits to rotate (32 will rotate a dword)
//  offset - number of first bit to rotate
//           (bits=8 offset=16 will rotate the third byte of the value)
// returns the rotated value

idaman THREAD_SAFE uval_t ida_export rotate_left(uval_t x, int count, size_t bits, size_t offset);


#ifdef __cplusplus
// swap 2 objects of the same type using memory copies
template <class T> inline void qswap(T &a, T &b)
{
  char temp[sizeof(T)];
  memcpy(&temp, &a, sizeof(T));
  memcpy(&a, &b, sizeof(T));
  memcpy(&b, &temp, sizeof(T));
}
#endif

// NB: in the following macros, buf must be always less than end
// when we run up to the end, we put a 0 there and don't increase buf anymore

// append a character to the buffer checking the buffer size
#define APPCHAR(buf, end, chr)                    \
  do                                              \
  {                                               \
    char __chr = (chr);                           \
    QASSERT(518, (buf) < (end));                  \
    *(buf)++ = __chr;                             \
    if ( (buf) >= (end) )                         \
    {                                             \
        (buf) = (end)-1;                          \
        (buf)[0] = '\0';                          \
    }                                             \
  } while (0)

// put a zero byte at buffer
// NB: does not increase buf pointer!
#define APPZERO(buf, end)                         \
  do                                              \
  {                                               \
    QASSERT(519, (buf) < (end));                  \
    *(buf) = '\0';                                \
  } while (0)

// append a string to the buffer checking the buffer size
#define APPEND(buf, end, name)                    \
  do                                              \
  {                                               \
    QASSERT(520, (buf) < (end));                  \
    const char *__ida_in = (name);                \
    while ( true )                                \
    {                                             \
      if ( (buf) >= (end) )                       \
      {                                           \
        (buf) = (end)-1;                          \
        (buf)[0] = '\0';                          \
        break;                                    \
      }                                           \
      if (( *(buf) = *__ida_in++) == '\0' )       \
        break;                                    \
      (buf)++;                                    \
    }                                             \
  } while ( 0 )

//---------------------------------------------------------------------------
// The following templates are reimplementation of the vector and string
// classes from STL. Only the most essential functions are implemented.
// The vector container accepts object agnostic to their positions
// in the memory because it will move them arbitrarily (realloc and memmove)
// The reason why we have them is that they are not compiler dependent
// (hopefully) and therefore can be used in IDA API

idaman THREAD_SAFE void *ida_export qalloc_or_throw(size_t size);
idaman THREAD_SAFE void *ida_export qrealloc_or_throw(void *ptr, size_t size);
idaman THREAD_SAFE void *ida_export qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize);

// Convenience macro to declare memory allocation functions.
// It must be used for all classes that can be allocated/freed by the IDA kernel
#if defined(__cplusplus)
  #if defined(SWIG)
    #define DEFINE_MEMORY_ALLOCATION_FUNCS()
  #else
    #ifndef __BORLANDC__ // bcc complains about placement delete
      #define PLACEMENT_DELETE void operator delete(void *, void *) {}
    #else
      #define PLACEMENT_DELETE
    #endif
    #define DEFINE_MEMORY_ALLOCATION_FUNCS()                              \
      void *operator new  (size_t size) { return qalloc_or_throw(size); } \
      void *operator new[](size_t size) { return qalloc_or_throw(size); } \
      void *operator new(size_t /*size*/, void *v) { return v; }          \
      void operator delete  (void *blk) { qfree(blk); }                   \
      void operator delete[](void *blk) { qfree(blk); }                   \
      PLACEMENT_DELETE
  #endif

// Macro to declare standard inline comparison operators
#define DECLARE_COMPARISON_OPERATORS(type)                              \
  bool operator==(const type &r) const { return compare(r) == 0; }      \
  bool operator!=(const type &r) const { return compare(r) != 0; }      \
  bool operator< (const type &r) const { return compare(r) <  0; }      \
  bool operator> (const type &r) const { return compare(r) >  0; }      \
  bool operator<=(const type &r) const { return compare(r) <= 0; }      \
  bool operator>=(const type &r) const { return compare(r) >= 0; }

// Macro to declare comparisons for our classes
// All comparison operators call the compare() function which returns -1/0/1
#define DECLARE_COMPARISONS(type)    \
  DECLARE_COMPARISON_OPERATORS(type) \
  friend int compare(const type &a, const type &b) { return a.compare(b); } \
  int compare(const type &r) const

// Internal declarations to detect pod-types
struct ida_true_type {};
struct ida_false_type {};
template <class T> struct ida_type_traits     { typedef ida_false_type is_pod_type; };
template <class T> struct ida_type_traits<T*> { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits< char>  { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits<uchar>  { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits<  int>  { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits< uint>  { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits<short>  { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits<ushort> { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits< long>  { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits<unsigned long> { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits< int64> { typedef ida_true_type is_pod_type; };
template <> struct ida_type_traits<uint64> { typedef ida_true_type is_pod_type; };
inline bool check_type_trait(ida_false_type) { return false; }
inline bool check_type_trait(ida_true_type) { return true; }
template <class T> inline bool is_pod_type(void)
{
  typedef typename ida_type_traits<T>::is_pod_type is_pod_type;
  return check_type_trait(is_pod_type());
}

// Can we move around objects of type T using simple memcpy/memmove?
// This class can be specialized for any type T to improve qvector's behavior.
template <class T> struct ida_movable_type
{
  typedef typename ida_type_traits<T>::is_pod_type is_movable_type;
};
#define DECLARE_TYPE_AS_MOVABLE(T) template <> struct ida_movable_type<T> { typedef ida_true_type is_movable_type; }
template <class T> inline bool may_move_bytes(void)
{
  typedef typename ida_movable_type<T>::is_movable_type mmb_t;
  return check_type_trait(mmb_t());
}

// qvector class
template <class T> class qvector
{
  T *array;
  size_t n, alloc;
  friend void *ida_export qvector_reserve(void *vec, void *old, size_t cnt, size_t elsize);
  qvector<T> &assign(const qvector<T> &x)
  {
    if ( x.n > 0 )
    {
      array = (T*)qalloc_or_throw(x.alloc * sizeof(T));
      alloc = x.alloc;
      while ( n < x.n )
      {
        new (array+n) T(x.array[n]);
        ++n;
      }
    }
    return *this;
  }
  // move data down in memory
  void shift_down(T *dst, T *src, size_t cnt)
  {
    if ( may_move_bytes<T>() )
    {
      memmove(dst, src, cnt*sizeof(T));
    }
    else
    {
      ssize_t s = cnt;
      while( --s >= 0 )
      {
        new(dst) T(*src);
        src->~T();
        ++src;
        ++dst;
      }
    }
  }
  // move data up in memory
  void shift_up(T *dst, T *src, size_t cnt)
  {
    if ( may_move_bytes<T>() )
    {
      memmove(dst, src, cnt*sizeof(T));
    }
    else
    {
      ssize_t s = cnt;
      dst += s;
      src += s;
      while( --s >= 0 )
      {
        --src;
        --dst;
        new(dst) T(*src);
        src->~T();
      }
    }
  }
public:
  typedef T value_type;
  qvector(void) : array(NULL), n(0), alloc(0) {}
  qvector(const qvector<T> &x) : array(NULL), n(0), alloc(0) { assign(x); }
  ~qvector(void) { clear(); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void push_back(const T &x)
  {
    reserve(n+1);
    new (array+n) T(x); // create a new element in the qvector
    ++n;
  }
  T &push_back(void)
  {
    reserve(n+1);
    T *ptr = array + n;
    new (ptr) T;
    ++n;
    return *ptr;
  }
  void pop_back(void)
  {
    if ( n > 0 )
    {
#ifdef UNDER_CE         // clarm.exe is buggy
      --n;
      if ( !is_pod_type<T>() )
        array[n].~T();
#else
      array[--n].~T();
#endif
    }
  }
  size_t size(void) const { return n; }
  bool empty(void) const { return n == 0; }
  const T &operator[](size_t idx) const { return array[idx]; }
        T &operator[](size_t idx)       { return array[idx]; }
  const T &at(size_t idx) const { return array[idx]; }
        T &at(size_t idx)       { return array[idx]; }
  const T &front(void) const { return array[0]; }
        T &front(void)       { return array[0]; }
  const T &back(void) const { return array[n-1]; }
        T &back(void)       { return array[n-1]; }
  void qclear(void) // destruct elements but do not free memory
  {
    if ( is_pod_type<T>() )
    {
      n = 0;
    }
    else
    {
      while ( n > 0 )
      {
        array[n-1].~T();
        --n;
      }
    }
  }
  void clear(void)
  {
    if ( array != NULL )
    {
      qclear();
      qfree(array);
      array = NULL;
      alloc = 0;
    }
  }
  qvector<T> &operator=(const qvector<T> &x)
  {
    size_t mn = qmin(n, x.n);
    for ( size_t i=0; i < mn; i++ )
      array[i] = x.array[i];
    if ( n > x.n )
    {
      if ( is_pod_type<T>() )
      {
        n = x.n;
      }
      else
      {
        while ( n > x.n )
        {
          array[n-1].~T();
          --n;
        }
      }
    }
    else
    {
      reserve(x.n);
      while ( n < x.n )
      {
        new(array+n) T(x.array[n]);
        ++n;
      }
    }
    return *this;
  }
  void resize(size_t s, const T &x)
  {
    if ( s < n )
    {
      if ( !is_pod_type<T>() )
        for ( ssize_t i=ssize_t(n); --i >= ssize_t(s); )
          array[i].~T();
      n = s;
    }
    else
    {
      reserve(s);
      while ( n < s )
      {
        new(array+n) T(x);
        ++n;
      }
    }
  }
  void resize(size_t s)
  {
    if ( is_pod_type<T>() )
    {
      if ( n < s )
      {
        reserve(s);
        memset(array+n, 0, (s-n)*sizeof(T));
      }
      n = s;
    }
    else
    {
      resize(s, T());
    }
  }
  void grow(const T &x=T())
  {
    reserve(n+1);
    new(array+n) T(x);
    ++n;
  }
  size_t capacity(void) const { return alloc; }
  void reserve(size_t cnt)
  {
    if ( cnt > alloc )
    {
      if ( may_move_bytes<T>() )
      {
        array = (T *)qvector_reserve(this, array, cnt, sizeof(T));
      }
      else
      {
        int old_alloc = alloc;
        T *new_array = (T *)qvector_reserve(this, NULL, cnt, sizeof(T));
        int new_alloc = alloc;
        alloc = old_alloc;
        shift_down(new_array, array, n);
        qfree(array);
        array = new_array;
        alloc = new_alloc;
      }
    }
  }
  void truncate(void)
  {
    if ( alloc > n )
    {
      array = (T*)qrealloc(array, n*sizeof(T)); // should not fail
      alloc = n;
    }
  }
  void swap(qvector<T> &r)
  {
    T *array2     = array;
    size_t n2     = n;
    size_t alloc2 = alloc;

    array = r.array;
    n     = r.n;
    alloc = r.alloc;
    r.array = array2;

    r.n     = n2;
    r.alloc = alloc2;
  }
  // method to extract data from the vector and to empty it
  // the caller must free the result of this function
  T *extract(void)
  {
    truncate();
    alloc = 0;
    n = 0;
    T *res = array;
    array = NULL;
    return res;
  }
  // method to populate qvector with a pointer to dynamic memory
  // qvector must be empty before calling this method!
  void inject(T *s, size_t len)
  {
    array = s;
    alloc = len;
    n = len;
  }
  bool operator == (const qvector<T> &r) const
  {
    if ( n != r.n )
      return false;
    for ( size_t i=0; i < n; i++ )
      if ( array[i] != r[i] )
        return false;
    return true;
  }
  bool operator != (const qvector<T> &r) const { return !(*this == r); }

  typedef T *iterator;
  typedef const T *const_iterator;

  iterator begin(void) { return array; }
  iterator end(void) { return array + n; }
  const_iterator begin(void) const { return array; }
  const_iterator end(void) const { return array + n; }

  iterator insert(iterator it, const T &x)
  {
    size_t idx = it - array;
    reserve(n+1);
    T *p = array + idx;
    size_t rest = end() - p;
    shift_up(p+1, p, rest);
    new(p) T(x);
    n++;
    return iterator(p);
  }
  template <class it2> iterator insert(iterator it, it2 first, it2 last)
  {
    size_t cnt = last - first;
    if ( cnt == 0 )
      return it;

    size_t idx = it - array;
    reserve(n+cnt);
    T *p = array + idx;
    size_t rest = end() - p;
    shift_up(p+cnt, p, rest);
    while ( first != last )
    {
      new(p) T(*first);
      ++p;
      ++first;
    }
    n += cnt;
    return iterator(array+idx);
  }
  iterator erase(iterator it)
  {
    it->~T();
    size_t rest = end() - it - 1;
    shift_down(it, it+1, rest);
    n--;
    return it;
  }
  iterator erase(iterator first, iterator last)
  {
    for ( T *p=first; p != last; ++p )
      p->~T();
    size_t rest = end() - last;
    shift_down(first, last, rest);
    n -= last - first;
    return first;
  }
  // non-standard extensions:
  iterator find(const T &x)
  {
    iterator p;
    for ( p=begin(); p != end(); ++p )
      if ( x == *p )
        break;
    return p;
  }
  const_iterator find(const T &x) const
  {
    const_iterator p;
    for ( p=begin(); p != end(); ++p )
      if ( x == *p )
        break;
    return p;
  }
  bool has(const T &x) const { return find(x) != end(); }
  bool add_unique(const T &x)
  {
    if ( has(x) )
      return false;
    push_back(x);
    return true;
  }
  bool del(const T &x)
  {
    iterator p = find(x);
    if ( p == end() )
      return false;
    erase(p);
    return true;
  }
};

template<class T>
class qstack : public qvector<T>
{
  typedef qvector<T> base;
public:
  T pop(void)
  {
    T v = base::back();
    base::pop_back();
    return v;
  }
  const T &top(void) const
  {
    return base::back();
  }
  T &top(void) { return CONST_CAST(T&)(CONST_CAST(const qstack<T>*)(this)->top()); }
  void push(const T &v)
  {
    push_back(v);
  }
};

// smart pointer to objects derived from qrefcnt_obj_t
template <class T>
class qrefcnt_t
{
  T *ptr;
  void delref(void)
  {
    if ( ptr != NULL && --ptr->refcnt == 0 )
      ptr->release();
  }
public:
  explicit qrefcnt_t(T *p) : ptr(p) {}
  qrefcnt_t(const qrefcnt_t &r) : ptr(r.ptr)
  {
    if ( ptr != NULL )
      ptr->refcnt++;
  }
  qrefcnt_t &operator=(const qrefcnt_t &r)
  {
    delref();
    ptr = r.ptr;
    if ( ptr != NULL )
      ptr->refcnt++;
    return *this;
  }
  ~qrefcnt_t(void)
  {
    delref();
  }
  void reset(void)
  {
    delref();
    ptr = NULL;
  }
  operator T *() const
  {
    return ptr;
  }
  T *operator ->() const
  {
    return ptr;
  }
  T &operator *() const
  {
    return *ptr;
  }
};

// base class for reference count objects
class qrefcnt_obj_t
{
public:
  int refcnt;
  qrefcnt_obj_t(void) : refcnt(1) {}
  // call destructor.
  // we use release() instead of operator delete() to maintain binary
  // compatibility with all compilers (vc and gcc use different vtable layouts
  // for operator delete)
  virtual void idaapi release(void) = 0;
};

template <class T>
class qiterator : public qrefcnt_obj_t
{
public:
  typedef T value_type;
  virtual bool idaapi first(void) = 0;
  virtual bool idaapi next(void) = 0;
  virtual T idaapi operator *(void) = 0;
  virtual T get(void) { return this->operator*(); }
};

inline size_t idaapi qstrlen(const char *s) { return strlen(s); }
inline size_t idaapi qstrlen(const uchar *s) { return strlen((const char *)s); }
idaman THREAD_SAFE size_t ida_export qstrlen(const wchar16_t *s);

inline int idaapi qstrcmp(const char *s1, const char *s2) { return strcmp(s1, s2); }
inline int idaapi qstrcmp(const uchar *s1, const uchar *s2) { return strcmp((const char *)s1, (const char *)s2); }
idaman THREAD_SAFE int ida_export qstrcmp(const wchar16_t *s1, const wchar16_t *s2);

inline const char *idaapi qstrstr(const char *s1, const char *s2) { return strstr(s1, s2); }
inline const uchar *idaapi qstrstr(const uchar *s1, const uchar *s2) { return (const uchar *)strstr((const char *)s1, (const char *)s2); }

inline const char *idaapi qstrchr(const char *s1, char c) { return strchr(s1, c); }
inline const uchar *idaapi qstrchr(const uchar *s1, uchar c) { return (const uchar *)strchr((const char *)s1, c); }
idaman THREAD_SAFE const wchar16_t *ida_export qstrchr(const wchar16_t *s1, wchar16_t c);

inline const char *idaapi qstrrchr(const char *s1, char c) { return strrchr(s1, c); }
inline const uchar *idaapi qstrrchr(const uchar *s1, uchar c) { return (const uchar *)strrchr((const char *)s1, c); }
idaman THREAD_SAFE const wchar16_t *ida_export qstrrchr(const wchar16_t *s1, wchar16_t c);

template<class qchar>
class _qstring    // implement simple qstring class
{
  qvector<qchar> body;
public:
  _qstring(void) {}
  _qstring(const qchar *ptr)
  {
    if ( ptr != NULL )
    {
      size_t len = ::qstrlen(ptr) + 1;
      body.resize(len);
      memcpy(body.begin(), ptr, len*sizeof(qchar));
    }
  }
  _qstring(const qchar *ptr, size_t len)
  {
    if ( len > 0 )
    {
      body.resize(len+1);
      memcpy(body.begin(), ptr, len*sizeof(qchar));
    }
  }
  void swap(_qstring<qchar> &r) { body.swap(r.body); }
  size_t length(void) const { size_t l = body.size(); return l ? l - 1 : 0; }
  size_t size(void) const { return body.size(); }
  void resize(size_t s, qchar c)
  {
    int oldsize = body.size();
    if ( oldsize != 0 && s >= oldsize )
      body[oldsize-1] = c; // erase the terminating zero
    body.resize(s+1, c);
    body[s] = 0; // ensure the terminating zero
  }
  void resize(size_t s)
  {
    body.resize(s+1);
    body[s] = 0; // ensure the terminating zero
  }
  void reserve(size_t cnt) { body.reserve(cnt); }
  void clear(void) { body.clear(); }
  void qclear(void) { body.qclear(); } // clear string but do not free memory yet
  bool empty(void) const { return body.size() <= 1; }
  const qchar *c_str(void) const
  {
    static const qchar nullstr[] = { 0 };
    return body.empty() ? nullstr : &body[0];
  }
  typedef qchar *iterator;
  typedef const qchar *const_iterator;
        iterator begin(void)       { return body.begin(); }
  const_iterator begin(void) const { return body.begin(); }
        iterator end(void)       { return body.end(); }
  const_iterator end(void) const { return body.end(); }
  _qstring &operator=(const qchar *str)
  {
    size_t len = str == NULL ? 0 : ::qstrlen(str);
    if ( len > 0 )
    {
      body.resize(len+1);
      memcpy(body.begin(), str, len*sizeof(qchar));
      body[len] = '\0';
    }
    else
    {
      qclear();
    }
    return *this;
  }
  _qstring &operator+=(qchar c)
  {
    return append(c);
  }
  _qstring &operator+=(const _qstring &r)
  {
    return append(r);
  }
  _qstring operator+(const _qstring &r) const
  {
    _qstring s = *this;
    s += r;
    return s;
  }
  bool operator==(const _qstring &r) const
  {
    return ::qstrcmp(c_str(), r.c_str()) == 0;
  }
  bool operator==(const qchar *r) const
  {
    return ::qstrcmp(c_str(), r) == 0;
  }
  bool operator!=(const _qstring &r) const { return !(*this == r); }
  bool operator!=(const qchar *r) const { return !(*this == r); }
  bool operator<(const _qstring &r) const
  {
    return ::qstrcmp(c_str(), r.c_str()) < 0;
  }
  bool operator<(const qchar *r) const
  {
    return ::qstrcmp(c_str(), r) < 0;
  }
  const qchar &operator[](size_t idx) const
  {
    if ( !body.empty() || idx )
      return body[idx];
    static const qchar nullstr[] = { 0 };
    return nullstr[0];
  }
  qchar &operator[](size_t idx)
  {
    if ( !body.empty() || idx )
      return body[idx];
    static qchar nullstr[] = { 0 };
    return nullstr[0];
  }
  // extract C string from _qstring. Must qfree() it.
  qchar *extract(void) { return body.extract(); }
  void inject(qchar *s, size_t len)
  {
    body.inject(s, len);
  }
  void inject(qchar *s)
  {
    if ( s != NULL )
    {
      size_t len = ::qstrlen(s) + 1;
      body.inject(s, len);
    }
  }
  // the last qchar in the string (for concatenation checks)
  qchar last(void) const
  {
    size_t len = length();
    return len == 0 ? '\0' : body[len-1];
  }
  // find a substring
  size_t find(const qchar *str, size_t pos=0) const
  {
    if ( pos <= length() )
    {
      const qchar *beg = c_str();
      const qchar *ptr = ::qstrstr(beg+pos, str);
      if ( ptr != NULL )
        return ptr - beg;
    }
    return npos;
  }
  // replace all occurrences of 'what' with 'with'
  bool replace(const qchar *what, const qchar *with)
  {
    _qstring result;
    size_t len_what = ::qstrlen(what);
    const qchar *last_pos = c_str();
    const qchar *pos = c_str();
    while ( (pos=::qstrstr(pos, what)) != NULL )
    {
      size_t n = pos - last_pos;
      if ( n > 0 )
        result.append(last_pos, n);
      result.append(with);
      pos += len_what;
      last_pos = pos;
    }
    // no match at all?
    if ( last_pos == c_str() )
      return false;
    // any pending characters?
    if ( *last_pos )
      result.append(last_pos);
    swap(result);
    return true;
  }
  size_t find(const _qstring &str, size_t pos=0) const { return find(str.c_str(), pos); }
  size_t find(qchar c, size_t pos=0) const
  {
    if ( pos <= length() )
    {
      const qchar *beg = c_str();
      const qchar *ptr = qstrchr(beg+pos, c);
      if ( ptr != NULL )
        return ptr - beg;
    }
    return npos;
  }
  size_t rfind(qchar c, size_t pos=0) const
  {
    if ( pos <= length() )
    {
      const qchar *beg = c_str();
      const qchar *ptr = qstrrchr(beg+pos, c);
      if ( ptr != NULL )
        return ptr - beg;
    }
    return npos;
  }
  // get a substring
  _qstring<qchar> substr(size_t pos=0, size_t n=npos) const
  {
    size_t endp = qmin(length(), n);
    if ( pos >= endp )
      pos = endp;
    return _qstring<qchar>(c_str()+pos, endp-pos);
  }
  // remove 'cnt' qchars at the position 'idx'. If parameter(s) are invalid, ignore it
  _qstring& remove(size_t idx, size_t cnt)
  {
    size_t len = length();
    if ( idx < len && cnt != 0 )
    {
      cnt += idx;
      if ( cnt < len )
      {
        iterator p1 = body.begin() + cnt;
        iterator p2 = body.begin() + idx;
        memmove(p2, p1, (len-cnt)*sizeof(qchar));
        idx += len - cnt;
      }
      body.resize(idx+1);
      body[idx] = '\0';
    }
    return *this;
  }
  // insert qchar/str/qstr at the position 'idx'.
  // If idx >= size, th effect is the same as append
  _qstring& insert(size_t idx, qchar c)
  {
    size_t len = length();
    body.resize(len+2);
    body[len+1] = '\0';
    if ( idx < len )
    {
      iterator p1 = body.begin() + idx;
      memmove(p1+1, p1, (len-idx)*sizeof(qchar));
      len = idx;
    }
    body[len] = c;
    return *this;
  }
  _qstring& insert(size_t idx, const qchar *str, size_t addlen)
  {
    size_t len = length();
    body.resize(len+addlen+1);
    body[len+addlen] = '\0';
    if ( idx < len )
    {
      iterator p1 = body.begin() + idx;
      iterator p2 = p1 + addlen;
      memmove(p2, p1, (len-idx)*sizeof(qchar));
      len = idx;
    }
    memcpy(body.begin()+len, str, addlen*sizeof(qchar));
    return *this;
  }
  _qstring& insert(size_t idx, const qchar *str)
  {
    if ( str != NULL )
    {
      size_t addlen = ::qstrlen(str);
      insert(idx, str, addlen);
    }
    return *this;
  }
  _qstring& insert(size_t idx, const _qstring &qstr)
  {
    size_t len = length();
    size_t add = qstr.length();
    body.resize(len+add+1);
    body[len+add] = '\0';
    if ( idx < len )
    {
      iterator p1 = body.begin() + idx;
      iterator p2 = p1 + add;
      memmove(p2, p1, (len-idx)*sizeof(qchar));
      len = idx;
    }
    memcpy(body.begin()+len, qstr.begin(), add*sizeof(qchar));
    return *this;
  }
  _qstring& before(qchar c)               { return insert(0, c);    }
  _qstring& before(const qchar *str)      { return insert(0, str);  }
  _qstring& insert(const _qstring &qstr)  { return insert(0, qstr); }
  _qstring& append(qchar c)
  {
    size_t len = length();
    body.resize(len+2);
    body[len] = c;
    body[len+1] = '\0';
    return *this;
  }
  _qstring& append(const qchar *str, size_t addlen)
  {
    size_t len = length();
    body.resize(len+addlen+1);
    body[len+addlen] = '\0';
    memcpy(body.begin()+len, str, addlen*sizeof(qchar));
    return *this;
  }
  _qstring& append(const qchar *str)
  {
    if ( str != NULL )
    {
      size_t addlen = ::qstrlen(str);
      append(str, addlen);
    }
    return *this;
  }
  _qstring& append(const _qstring &qstr)
  {
    size_t add = qstr.length();
    if ( add != 0 )
    {
      size_t len = length();
      body.resize(len+add+1);
      body[len+add] = '\0';
      memcpy(body.begin()+len, qstr.begin(), add*sizeof(qchar));
    }
    return *this;
  }
  // append result of sprintf to qstring
  AS_PRINTF(2, 0) _qstring& cat_vsprnt(const char *format, va_list va)
  { // since gcc64 forbids reuse of va_list, we make a copy for the second call:
    va_list copy;
    va_assign(copy, va);
    size_t add = ::qvsnprintf(NULL, 0, format, va);
    if ( add != 0 )
    {
      size_t len = length();
      body.resize(len+add+1);
      ::qvsnprintf(body.begin()+len, add+1, format, copy);
    }
    return *this;
  }
  // replace qstring with the result of sprintf
  AS_PRINTF(2, 0) _qstring& vsprnt(const char *format, va_list va)
  { // since gcc64 forbids reuse of va_list, we make a copy for the second call:
    va_list copy;
    va_assign(copy, va);
    body.clear();
    size_t add = ::qvsnprintf(NULL, 0, format, va);
    if ( add != 0 )
    {
      body.resize(add+1);
      ::qvsnprintf(body.begin(), add+1, format, copy);
    }
    return *this;
  }
  // append result of sprintf to qstring
  AS_PRINTF(2, 3) _qstring& cat_sprnt(const char *format, ...)
  {
    va_list va;
    va_start(va, format);
    cat_vsprnt(format, va);
    va_end(va);
    return *this;
  }
  // replace qstring with the result of sprintf
  AS_PRINTF(2, 3) _qstring& sprnt(const char *format, ...)
  {
    va_list va;
    va_start(va, format);
    vsprnt(format, va);
    va_end(va);
    return *this;
  }
  _qstring& fill(int pos, qchar c, size_t len)
  {
    size_t endp = pos + len + 1;
    if ( body.size() < endp )
    {
      body.resize(endp);
      body[endp-1] = '\0';
    }
    memset(body.begin()+pos, c, len);
    return *this;
  }
  _qstring& fill(qchar c, size_t len)
  {
    body.qclear();
    if ( len > 0 )
      resize(len, c);
    return *this;
  }
// embedded visual studio and visual C/C++ 6.0 are not aware of
//   static const varname = init_value;
#if defined(UNDER_CE) || defined(_MSC_VER) && _MSC_VER <= 1200
  enum { npos = -1 };
#else
  static const size_t npos = (size_t) -1;
#endif
};
typedef _qstring<char> qstring;       // regular string
typedef _qstring<uchar> qtype;        // type string
typedef _qstring<wchar16_t> qwstring; // unicode string

// vector of bytes (use for dynamic memory)
class bytevec_t: public qvector<uchar>
{
public:
  bytevec_t() {}
  bytevec_t(const void *buf, size_t sz) { append(buf, sz); }
  bytevec_t &append(const void *buf, size_t sz)
  {
    if ( sz > 0 )
    {
      size_t cur_sz = size();
      size_t new_sz = cur_sz + sz;
      if ( new_sz < cur_sz )
        new_sz = BADMEMSIZE; // integer overflow, ask too much and it will throw
      resize(new_sz);
      memcpy(begin() + cur_sz, buf, sz);
    }
    return *this;
  }
  bytevec_t &growfill(size_t sz, uchar filler=0)
  {
    if ( sz > 0 )
    {
      size_t cur_sz = size();
      size_t new_sz = cur_sz + sz;
      if ( new_sz < cur_sz )
        new_sz = BADMEMSIZE; // integer overflow, ask too much and it will throw
      resize(new_sz, filler);
    }
    return *this;
  }
  void inject(void *buf, size_t len)
  {
    qvector<uchar>::inject((uchar *)buf, len);
  }
  bool test_bit(size_t bit) const   { return ::test_bit(begin(), bit); }
  void set_bit(size_t bit)          { ::set_bit(begin(), bit); }
  void clear_bit(size_t bit)        { ::clear_bit(begin(), bit); }
  void set_all_bits(size_t nbits)   { resize((nbits+7)/8); ::set_all_bits(begin(), nbits); }
  void clear_all_bits(size_t nbits) { ::clear_all_bits(begin(), nbits); }
  void set_bits(const bytevec_t &b)
  {
    size_t nbytes = b.size();
    if ( size() < nbytes )
      resize(nbytes);
    for ( size_t i=0; i < nbytes; i++ )
      at(i) |= b[i];
  }
  void clear_bits(const bytevec_t &b)
  {
    size_t nbytes = qmin(size(), b.size());
    iterator p = begin();
    for ( size_t i=0; i < nbytes; i++, ++p )
      *p = uchar(*p & ~b[i]);
  }
};

// Relocatable objects (relobj_t)
struct reloc_info_t : public bytevec_t  // relocation information
{
  // the first byte describes the relocation entry types:
#define RELOBJ_MASK 0xF
#define   RELSIZE_1     0  // 8-bit relocations
#define   RELSIZE_2     1  // 16-bit relocations
#define   RELSIZE_4     2  // 32-bit relocations
#define   RELSIZE_8     3  // 64-bit relocations
#define   RELSIZE_CUST 15  // custom relocations, should be handled internally
#define RELOBJ_CNT 0x80    // counter present (not used yet)
};

idaman THREAD_SAFE bool ida_export relocate_relobj(struct relobj_t *_relobj, ea_t ea, bool mf);

struct relobj_t : public bytevec_t      // relocatable object
{
  ea_t base;                            // current base
  reloc_info_t ri;

  relobj_t(void) : base(0) {}
  bool relocate(ea_t ea, bool mf) { return relocate_relobj(this, ea, mf); } // mf=1:big endian
};

#define QLIST_DEFINED
template <class T> class qlist
{
  struct listnode_t
  {
    listnode_t *next;
    listnode_t *prev;
  };

  struct datanode_t : public listnode_t
  {
    T data;
  };

  listnode_t node;
  size_t length;

  void init(void)
  {
    node.next = &node;
    node.prev = &node;
    length = 0;
  }

public:
  typedef T value_type;
  class const_iterator;
#define DEFINE_LIST_ITERATOR(iter, constness, cstr)                     \
  class iter                                                            \
  {                                                                     \
    friend class qlist<T>;                                              \
    constness listnode_t *cur;                                          \
    iter(constness listnode_t *x) : cur(x) {}                           \
  public:                                                               \
    typedef constness T value_type;                                     \
    iter(void) {}                                                       \
    iter(const iter &x) : cur(x.cur) {}                                 \
    cstr                                                                \
    bool operator==(const iter& x) const { return cur == x.cur; }       \
    bool operator!=(const iter& x) const { return cur != x.cur; }       \
    constness T &operator*(void) const { return ((datanode_t*)cur)->data; }  \
    constness T *operator->(void) const { return &(operator*()); } \
    iter& operator++(void)       /* prefix ++  */                       \
    {                                                                   \
      cur = cur->next;                                                  \
      return *this;                                                     \
    }                                                                   \
    iter operator++(int)         /* postfix ++ */                       \
    {                                                                   \
      iter tmp = *this;                                                 \
      ++(*this);                                                        \
      return tmp;                                                       \
    }                                                                   \
    iter& operator--(void)       /* prefix --  */                       \
    {                                                                   \
      cur = cur->prev;                                                  \
      return *this;                                                     \
    }                                                                   \
    iter operator--(int)         /* postfix -- */                       \
    {                                                                   \
      iter tmp = *this;                                                 \
      --(*this);                                                        \
      return tmp;                                                       \
    }                                                                   \
  };
  DEFINE_LIST_ITERATOR(iterator, , friend class const_iterator;)
  DEFINE_LIST_ITERATOR(const_iterator, const, const_iterator(const iterator &x) : cur(x.cur) {})

#define DEFINE_REVERSE_ITERATOR(riter, iter)                            \
  class riter                                                           \
  {                                                                     \
    iter p;                                                             \
  public:                                                               \
    riter(void) {}                                                      \
    riter(const iter &x) : p(x) {}                                      \
    typename iter::value_type &operator*(void) const { iter q=p; return *--q; }  \
    typename iter::value_type *operator->(void) const { return &(operator*()); } \
    riter &operator++(void) { --p; return *this; }                      \
    riter &operator++(int) { iter q=p; --p; return q; }                 \
    riter &operator--(void) { ++p; return *this; }                      \
    riter &operator--(int) { iter q=p; ++p; return q; }                 \
    bool operator==(const riter& x) const { return p == x.p; }          \
    bool operator!=(const riter& x) const { return p != x.p; }          \
  };
  DEFINE_REVERSE_ITERATOR(reverse_iterator, iterator)
  DEFINE_REVERSE_ITERATOR(const_reverse_iterator, const_iterator)

#undef DEFINE_LIST_ITERATOR
#undef DEFINE_REVERSE_ITERATOR

  qlist(void) { init(); }
  qlist(const qlist<T> &x)
  {
    init();
    insert(begin(), x.begin(), x.end());
  }
  ~qlist(void)
  {
    clear();
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  qlist<T> &operator=(const qlist<T> &x)
  {
    if ( this != &x )
    {
      iterator first1 = begin();
      iterator last1 = end();
      const_iterator first2 = x.begin();
      const_iterator last2 = x.end();
      while ( first1 != last1 && first2 != last2 )
        *first1++ = *first2++;
      if ( first2 == last2 )
        erase(first1, last1);
      else
        insert(last1, first2, last2);
    }
    return *this;
  }
  void swap(qlist<T> &x)
  {
    std::swap(node, x.node);
    std::swap(length, x.length);
  }

  iterator begin(void) { return node.next; }
  iterator end(void) { return &node; }
  bool empty(void) const { return length == 0; }
  size_t size(void) const { return length; }
  T &front(void) { return *begin(); }
  T &back(void) { return *(--end()); }

  const_iterator begin(void) const { return node.next; }
  const_iterator end(void) const { return &node; }
  const T&front(void) const { return *begin(); }
  const T&back(void) const { return *(--end()); }

  reverse_iterator rbegin() { return reverse_iterator(end()); }
  reverse_iterator rend() { return reverse_iterator(begin()); }
  const_reverse_iterator rbegin() const { return const_reverse_iterator(end()); }
  const_reverse_iterator rend() const { return const_reverse_iterator(begin()); }

  iterator insert(iterator p, const T& x)
  {
    datanode_t *tmp = (datanode_t*)qalloc_or_throw(sizeof(datanode_t));
    new (&(tmp->data)) T(x);
    linkin(p, tmp);
    return tmp;
  }
  T &insert(iterator p)
  {
    datanode_t *tmp = (datanode_t*)qalloc_or_throw(sizeof(datanode_t));
    new (&(tmp->data)) T();
    linkin(p, tmp);
    return tmp->data;
  }
  template <class it2> void insert(iterator p, it2 first, it2 last)
  {
    while ( first != last )
      insert(p, *first++);
  }
  void push_front(const T &x) { insert(begin(), x); }
  void push_back(const T &x) { insert(end(), x); }
  T &push_back(void) { return insert(end()); }

  void erase(iterator p)
  {
    p.cur->prev->next = p.cur->next;
    p.cur->next->prev = p.cur->prev;
    ((datanode_t*)p.cur)->data.~T();
    qfree(p.cur);
    --length;
  }
  void erase(iterator first, iterator last)
  {
    while ( first != last )
      erase(first++);
  }
  void clear(void) { erase(begin(), end()); }
  void pop_front(void) { erase(begin()); }
  void pop_back(void) { iterator tmp = end(); erase(--tmp); }

  bool operator==(const qlist<T> &x) const
  {
    if ( length != x.length )
      return false;
    const_iterator q=x.begin();
    for ( const_iterator p=begin(); p != end(); ++p,++q )
      if ( *p != *q )
        return false;
    return true;
  }
  bool operator!=(const qlist<T> &x) const { return !(*this == x); }
private:
  void linkin(iterator p, listnode_t *tmp)
  {
    tmp->next = p.cur;
    tmp->prev = p.cur->prev;
    p.cur->prev->next = tmp;
    p.cur->prev = tmp;
    ++length;
  }
};

typedef qvector<uval_t> uvalvec_t;    // vector of unsigned values
typedef qvector<sval_t> svalvec_t;    // vector of signed values
typedef qvector<ea_t> eavec_t;        // vector of addresses
typedef qvector<int> intvec_t;        // vector of integers
typedef qvector<qstring> qstrvec_t;   // vector of strings
typedef qvector<qwstring> qwstrvec_t; // vector of unicode strings
typedef qvector<bool> boolvec_t;      // vector of bools

// Our containers do not care about their addresses can be moved around with simple memcpy()
template <class T> struct ida_movable_type<qvector<T> >   { typedef ida_true_type is_movable_type; };
template <class T> struct ida_movable_type<_qstring<T> >  { typedef ida_true_type is_movable_type; };
template <class T> struct ida_movable_type<qlist<T> >     { typedef ida_true_type is_movable_type; };
template <class T> struct ida_movable_type<qiterator<T> > { typedef ida_true_type is_movable_type; };

//-------------------------------------------------------------------------
// Resource janitor to facilitate use of the RAII idiom
template <typename T>
struct janitor_t
{
  janitor_t(T &r) : resource(r) {}
  ~janitor_t(); // we provide no implementation for this function, you should
                // provide specialized implementation yourself
private:
  T &resource;
};

//-------------------------------------------------------------------------
template <class T> T align_up(T val, int elsize)
{
  int mask = elsize - 1;
  val += mask;
  val &= ~mask;
  return val;
}

//-------------------------------------------------------------------------
template <class T> T align_down(T val, int elsize)
{
  int mask = elsize - 1;
  val &= ~mask;
  return val;
}

//-------------------------------------------------------------------------
// GCC generates multiple destructors and they occupy multiple slots of the
// virtual function table. Since it makes the vft incompatible with other
// compilers, we simply never generate virtual destructors for gcc. This is not an
// ideal solution but it works.
// We have this problem only under MS Windows. On other platforms everything is
// compiled with GCC, so the vft layout is the same for the kernel and plugins.

#if defined(SWIG)
  #define DEFINE_VIRTUAL_DTOR(name)
#elif defined(__GNUC__) && defined(__NT__)
  #define DEFINE_VIRTUAL_DTOR(name) virtual void idaapi dummy_dtor_for_gcc(void) {}
#else
  #define DEFINE_VIRTUAL_DTOR(name) virtual idaapi ~name(void) {}
#endif

// Declare class as uncopyable
// (copy assignment and copy ctr are undefined, so if anyone calls them,
//  there will be a compilation or link error)
#define DECLARE_UNCOPYABLE(T) T &operator=(const T &); T(const T &);

#endif // _cplusplus

// Statistical counter for profiling -- for internal use
struct hit_counter_t;
idaman void ida_export reg_hit_counter(hit_counter_t *, bool do_reg);
idaman THREAD_SAFE hit_counter_t *ida_export create_hit_counter(const char *name);
idaman THREAD_SAFE void ida_export hit_counter_timer(hit_counter_t *, bool enable);
void print_all_counters(const char *fname);
struct hit_counter_t
{
  const char *name;     // name is owned by hit_counter_t
                        // reg_hit_counter() allocates it
  int total, misses;
  uint64 elapsed;       // number of elapsed counts
  uint64 stamp;         // start time
  hit_counter_t(const char *_name)
    : name(_name), total(0), misses(0), elapsed(0)
    { reg_hit_counter(this, true); }
  virtual ~hit_counter_t(void) { reg_hit_counter(this, false); }
  // prints the counter to the message window and resets it
  virtual void print(void);
  // time functions
  void start(void) { hit_counter_timer(this, true); }
  void stop(void) { hit_counter_timer(this, false); }
};
class incrementer_t
{
  hit_counter_t &ctr;
public:
  incrementer_t(hit_counter_t &_ctr) : ctr(_ctr) { ctr.total++; ctr.start(); }
  ~incrementer_t(void) { ctr.stop(); }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
  void failed(void) { ctr.misses++; }
};

#ifdef UNICODE
// Convert an ascii string to a unicode string. Return the result
// bufsize must be number of characters the output buffer can hold
const wchar16_t *cwstr(wchar16_t *buf, const char *src, size_t bufsize);
// Convert a unicode string to an ascii string. Return the result
const char *wcstr(char *buf, const wchar16_t *src, size_t bufsize);
#else
#define cwstr(dst, src, dstsize) ::qstrncpy(dst, src, dstsize)
#define wcstr(dst, src, dstsize) ::qstrncpy(dst, src, dstsize)
#endif

// Functions to perform base64 encoding/decoding

idaman THREAD_SAFE bool ida_export base64_encode(qstring *output, const void *input, size_t size);
idaman THREAD_SAFE bool ida_export base64_decode(bytevec_t *output, const char *input, size_t size);


// Convert tabulations to spaces
//      out     - output buffer to append to
//      str     - input string. can not be equal to out->c_str()
//      tabsize - tabulation size
// returns: true-replaced some tabs

idaman THREAD_SAFE bool ida_export replace_tabs(qstring *out, const char *str, int tabsize);


// Convert a unicode character to 1 byte character. If failed, return 0.
uchar wchar2char(wchar16_t wc);

idaman THREAD_SAFE bool ida_export u2cstr(const wchar16_t *in, qstring *out, int nsyms=-1); // unicode -> char
idaman THREAD_SAFE bool ida_export c2ustr(const char *in, qwstring *out, int nsyms=-1);   // char -> unicode
// utf8 -> 16bit unicode
idaman THREAD_SAFE int ida_export utf8_unicode(const char *in, wchar16_t *out, size_t outsize);
// windows utf8 (<0xFFFF) -> idb representation (oem)
idaman THREAD_SAFE bool ida_export win_utf2idb(char *buf);

// do not use windows CharToOem/OemToChar functions - ida can replace CodePage
#if defined(__NT__) && !defined(UNDER_CE)
idaman void ida_export char2oem(char *inout);
idaman void ida_export oem2char(char *inout);
#else
inline void idaapi char2oem(char* /*inout*/) { }
inline void idaapi oem2char(char* /*inout*/) { }
#endif

#ifdef __NT__
// if parameter == -1, use CP_ACP and CP_OEMCP
// return false if codepage unsupported
idaman bool ida_export set_codepages(int acp/* = CP_ACP*/, int oemcp/* = CP_OEMCP*/);
idaman int ida_export get_codepages(int* oemcp);

// convert data from codepage incp to outcp
// either codepage can be CP_UTF16 for Unicode text (buffer sizes are still in bytes!)
// insize == -1: input is null-terminated
// returns number of bytes after conversion (not counting termination zero)
// flags: 1: convert control characters (0x01-0x1F) to glyphs
idaman int ida_export convert_codepage(const void* in, int insize, void* out, size_t outsize, int incp, int outcp, int flags = 0);

#else
inline bool idaapi set_codepages(int /*acp*/, int /*oemcp*/) { return true; }
inline int idaapi get_codepages(int * /*oemcp*/) { return -1; }
inline int idaapi convert_codepage(const void* /*in*/, int /*insize*/, void* /*out*/, size_t /*outsize*/, int /*incp*/, int /*outcp*/, int /*flags*/ = 0) { return 0; }
#endif

// convert data from encoding fromcode into tocode
// returns number of input bytes converted (can be less than actual size if there was an invalid character)
// -1 if source or target encoding is not supported
// possible encoding names: windows codepages ("CP1251" etc), charset names ("Shift-JIS"), and many encodings supported by iconv
idaman int ida_export convert_encoding(const char *fromcode, const char *tocode, const bytevec_t *indata, bytevec_t *out, int flags = 0);

#ifndef CP_UTF8
#define CP_UTF8 65001
#endif

#ifndef CP_UTF16
#define CP_UTF16 1200
#endif

// Old Visual C++ compilers were not defining the following:
#ifdef __NT__
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif
#ifndef BELOW_NORMAL_PRIORITY_CLASS
#define BELOW_NORMAL_PRIORITY_CLASS       0x00004000
#endif
#endif

idaman ida_export_data char SubstChar;

typedef uint32 flags_t;   // 32-bit flags for each address
typedef ea_t tid_t;       // type id (for enums, structs, etc)

typedef uint32 bgcolor_t;       // Background color in RGB
#define DEFCOLOR bgcolor_t(-1)  // Default color (used in function, segment definitions)

//-------------------------------------------------------------------------
/// PROCESSES
//-------------------------------------------------------------------------

// Parse a space separated string (escaping with backslash is supported)
//      cmdline  - in: the string to be parsed
//      args     - out: a string vector to hold the results
//      redirs   - out: map of channel redirections found in cmdline
//                      if NULL, redirections won't be parsed
//                      if there are syntax errors in redirections, consider them
//                      as arguments
// Returns the number of parsed arguments

struct channel_redir_t
{
  int fd;                     // channel number
  qstring file;               // file name to redirect to/from.
                              // if empty, the channel must be closed.
  int flags;
#define IOREDIR_INPUT  0x01   // input redirection
#define IOREDIR_OUTPUT 0x02   // output redirection
#define IOREDIR_APPEND 0x04   // append, do not overwrite the output file
#define IOREDIR_QUOTED 0x08   // the file name was quoted
  bool is_input(void) const { return (flags & IOREDIR_INPUT) != 0; }
  bool is_output(void) const { return (flags & IOREDIR_OUTPUT) != 0; }
  bool is_append(void) const { return (flags & IOREDIR_APPEND) != 0; }
  bool is_quoted(void) const { return (flags & IOREDIR_QUOTED) != 0; }
  int start;                   // begin of the redirection string in the command line
  int length;                  // length of the redirection string in the command line
};
typedef qvector<channel_redir_t> channel_redirs_t;

idaman THREAD_SAFE size_t ida_export parse_command_line2(
        const char *cmdline,
        qstrvec_t *args,
        channel_redirs_t *redirs);


struct launch_process_params_t
{
  size_t cb;                    // size of this structure
  int flags;
#define LP_NEW_CONSOLE    0x0001 // create new console (only ms windows)
#define LP_TRACE          0x0002 // debug: unix: ptrace(TRACEME), windows: DEBUG_PROCESS
#define LP_PATH_WITH_ARGS 0x0004 // 'args' contains executable path too
#define LP_USE_SHELL      0x0008 // use shell to launch the command.
                                 // 'path' is ignored in this case.
#define LP_LAUNCH_32_BIT  0x0010 // prefer to launch 32-bit part of file (only mac)
#define LP_LAUNCH_64_BIT  0x0020 // prefer to launch 64-bit part of file (only mac)
                                 // only one of LP_LAUNCH_*_BIT bits can be specified
#define LP_NO_ASLR        0x0040 // disable ASLR (only mac)

  const char *path;             // File to run
  const char *args;             // Command line arguments
  ssize_t in_handle;            // Handle for stdin or -1
  ssize_t out_handle;           // Handle for stdout or -1
  ssize_t err_handle;           // Handle for stderr or -1
  char *env;                    // Zero separated environment variables that will be appended
                                // to the existing environment block (existing variables will be updated).
                                // Each variable has the following form: var=value\0
                                // Must be terminated with two zero bytes!
  const char *startdir;         // Current directory for the new process
  void *info;                   // os specific info (on windows it points to PROCESS_INFORMATION)
                                // on unix, not used
  launch_process_params_t(void)
    : cb(sizeof(*this)), flags(0), path(NULL), args(NULL),
      in_handle(-1), out_handle(-1),  err_handle(-1),
      env(NULL), startdir(NULL), info(NULL) {}
};

// Launch the specified process in parallel
// Returns: handle (unix: child pid), NULL - error

idaman THREAD_SAFE void *ida_export launch_process(
        const launch_process_params_t &lpp,
        qstring *errbuf);


// Forcibly terminate a running process
// Returns: 0-ok, otherwise an error code that can be passed to winerr()

idaman THREAD_SAFE int ida_export term_process(void *handle);


// Get exit code of a process
// Returns: ==0: process has exited, and the exit code is available
//          !=0: error code for winerr()

idaman THREAD_SAFE int ida_export get_process_exit_code(
        void *handle,
        int *exit_code);


//-------------------------------------------------------------------------
/// THREADS
//-------------------------------------------------------------------------

// Thread callback function
typedef int (idaapi *qthread_cb_t)(void *ud);

// Thread opaque handle
typedef struct __qthread_t {} *qthread_t;

// Creates a thread and returns a thread handle
idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t thread_cb, void *ud);

// Frees a thread resource (does not kill the thread)
idaman THREAD_SAFE void ida_export qthread_free(qthread_t q);

// Waits a thread until it terminates
idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q);

// Forcefully kills a thread (calls pthread_cancel under unix)
idaman THREAD_SAFE bool ida_export qthread_kill(qthread_t q);

// Get current thread. Must call qthread_free() to free it!
idaman THREAD_SAFE qthread_t ida_export qthread_self(void);

// Is the current thread the same as 'q'?
idaman THREAD_SAFE bool ida_export qthread_same(qthread_t q);

// Are we running in the main thread?
idaman THREAD_SAFE bool ida_export is_main_thread(void);

// Thread safe functions to work with the environment

idaman THREAD_SAFE bool ida_export qsetenv(const char *varname, const char *value);
idaman THREAD_SAFE bool ida_export qgetenv(const char *varname, qstring *buf=NULL);


//-------------------------------------------------------------------------
//  SEMAPHORES (named semaphores are public, nameless ones are local to the process)
//-------------------------------------------------------------------------
typedef struct __qsemaphore_t {} *qsemaphore_t;
idaman THREAD_SAFE qsemaphore_t ida_export qsem_create(const char *name, int init_count);
idaman THREAD_SAFE bool ida_export qsem_free(qsemaphore_t sem);
idaman THREAD_SAFE bool ida_export qsem_post(qsemaphore_t sem);
idaman THREAD_SAFE bool ida_export qsem_wait(qsemaphore_t sem, int timeout_ms); // -1 = infinite

//-------------------------------------------------------------------------
//  MUTEX
//-------------------------------------------------------------------------
typedef struct __qmutex_t {} *qmutex_t;
idaman THREAD_SAFE bool ida_export qmutex_free(qmutex_t m);
idaman THREAD_SAFE qmutex_t ida_export qmutex_create();
idaman THREAD_SAFE bool ida_export qmutex_lock(qmutex_t m);
idaman THREAD_SAFE bool ida_export qmutex_unlock(qmutex_t m);

//-------------------------------------------------------------------------
//  PIPES
//-------------------------------------------------------------------------
#ifdef __NT__
typedef void *qhandle_t;        // MS Windows HANDLE
#else
typedef int qhandle_t;          // file handle in Unix
#endif

// create a pipe. returns error code (0-ok)
// out: handles[0] - read handle, handles[1] - write handle
idaman THREAD_SAFE int ida_export qpipe_create(qhandle_t handles[2]);

// read from a pipe. returns number of read bytes. -1-error
idaman THREAD_SAFE ssize_t ida_export qpipe_read(qhandle_t handle, void *buf, size_t size);

// write to a pipe. returns number of written bytes. -1-error
idaman THREAD_SAFE ssize_t ida_export qpipe_write(qhandle_t handle, const void *buf, size_t size);

// close a pipe. returns error code (0-ok)
idaman THREAD_SAFE int ida_export qpipe_close(qhandle_t handle);

// wait for file/socket/pipe handles.
// returns: error code. on timeout, returns 0 and sets idx to -1
idaman THREAD_SAFE int ida_export qwait_for_handles(
        const qhandle_t *handles,
        int n,                  // number of handles
        uint32 write_bitmask,   // bitmask of indexes of handles opened for writing
        int *idx,
        int timeout_ms);

#ifndef NO_OBSOLETE_FUNCS
idaman DEPRECATED THREAD_SAFE size_t ida_export parse_command_line(const char *cmdline, qstrvec_t *args);
idaman DEPRECATED char *ida_export qsplitpath(char *path, char **dir, char **file);
idaman DEPRECATED void *ida_export init_process(const launch_process_params_t &lpi, qstring *errbuf);
idaman DEPRECATED NORETURN void ida_export vinterr(const char *file, int line, const char *format, va_list va);
idaman DEPRECATED error_t ida_export_data qerrno;
#if !defined(__BORLANDC__) && !defined(_MSC_VER)
idaman DEPRECATED THREAD_SAFE char *ida_export strlwr(char *s);
idaman DEPRECATED THREAD_SAFE char *ida_export strupr(char *s);
#endif
#define launch_process_t launch_process_params_t
#ifndef __GNUC__
typedef uint32 ulong;
#endif
#endif

// internal functions
qstring &get_buffer_for_sysdir(void);
qstring &get_buffer_for_winerr(void);
void call_atexits(bool noreturn, int exitcode = 0);

#pragma pack(pop)
#endif /* _PRO_H */
