/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2008 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef __FPRO_H
#define __FPRO_H
#pragma pack(push, 1)

//
//      This file contains q.. counterparts of FILE* functions from Clib.
//      The only difference is that they set 'qerrno' variable too.
//      You should not use C standard I/O functions in your modules.
//      The reason: Each module compiled with Borland
//      (and statically linked to Borland's library) will host a copy of
//      the FILE * information.
//      So if you open a file in the plugin and pass the handle to the
//      kernel, the kernel will not be able to use it.
//

#ifndef _PRO_H
#include <pro.h>
#endif

#include <stdio.h>

// If you really need to use the standard functions, define USE_STANDARD_FILE_FUNCTIONS
// In this case do not mix them with q... functions
#if !defined(USE_STANDARD_FILE_FUNCTIONS) && !defined(_lint)
#undef stdin
#undef stdout
#undef stderr
#undef fgetc
#undef fputc
#define stdin      dont_use_stdin
#define stdout     dont_use_stdout
#define stderr     dont_use_stderr
#define fopen      dont_use_fopen
#define fread      dont_use_fread
#define fwrite     dont_use_fwrite
#define ftell      dont_use_ftell
#define fseek      dont_use_fseek
#define fclose     dont_use_fclose
#define fflush     dont_use_fflush
#define fputc      dont_use_fputc
#define fgetc      dont_use_fgetc
#define fgets      dont_use_fgets
#define fputs      dont_use_fputs
#define vfprintf   dont_use_vfprintf
#define vfscanf    dont_use_vfscanf
#define fprintf    dont_use_fprintf
#define fprintf    dont_use_fprintf
#define fscanf     dont_use_fscanf
#endif

idaman THREAD_SAFE FILE *ida_export qfopen(const char *file, const char *mode);
idaman THREAD_SAFE int   ida_export qfread(FILE *fp, void *buf, size_t n);
idaman THREAD_SAFE int   ida_export qfwrite(FILE *fp, const void *buf, size_t n);
idaman THREAD_SAFE int32 ida_export qftell(FILE *fp);
idaman THREAD_SAFE int   ida_export qfseek(FILE *fp, int32 offset, int whence);                  /* 0-Ok */
idaman THREAD_SAFE int   ida_export qfclose(FILE *fp);
idaman THREAD_SAFE int   ida_export qflush(FILE *fp);         // flush stream and call dup/close(). 0 - ok
idaman             FILE *ida_export qtmpfile(void);
idaman THREAD_SAFE int   ida_export qrename(const char *oldfname, const char *newfname); // newname may exist, will be deleted
idaman THREAD_SAFE int   ida_export qunlink(const char *fname);

// Copy a file
//  from      - source file name
//  to        - destination file name
//  overwrite - overwrite output if it exists?
//  cb        - user callback. return false to abort the copy loop
//  ud        - user data passed back to cb
//  flags     - reserved (should be zero)
//
// returns:
//   -1       - input file not found
//   -2       - output file not writeable
//   -3       - output file already exists while overwrite is false
//   -4       - write failure
//   -5       - interrupted from the callback
idaman THREAD_SAFE int   ida_export qcopyfile(
        const char *from,
        const char *to,
        bool overwrite = true,
        bool (idaapi *cb)(size_t pos, size_t total, void *ud) = NULL,
        void *ud = NULL,
        int flags = 0);

// returns temporary file name
// (abs path, includes directory, uses TEMP/TMP vars)
idaman             char *ida_export qtmpnam(char *buf, size_t bufsize);

idaman THREAD_SAFE int ida_export qfputc(int chr, FILE *fp);
idaman THREAD_SAFE int ida_export qfgetc(FILE *fp);
idaman THREAD_SAFE char *ida_export qfgets(char *s, size_t len, FILE *fp);
idaman THREAD_SAFE int ida_export qfputs(const char *s, FILE *fp);
idaman THREAD_SAFE AS_PRINTF(2, 0) int ida_export qvfprintf(FILE *fp, const char *format, va_list va); // out to FILE*
idaman THREAD_SAFE AS_PRINTF(1, 0) int ida_export qvprintf(const char *format, va_list va);    // out to stdout
idaman THREAD_SAFE AS_PRINTF(1, 0) int ida_export qveprintf(const char *format, va_list va);   // out to stderr
idaman THREAD_SAFE AS_SCANF (2, 0) int ida_export qvfscanf(FILE *fp, const char *format, va_list va);
idaman THREAD_SAFE char *ida_export qgets(char *line, size_t linesize);
int idaapi qgetchar(void);
#ifdef __cplusplus
THREAD_SAFE AS_PRINTF(2, 3) inline int qfprintf(FILE *fp, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int code = qvfprintf(fp, format, va);
  va_end(va);
  return code;
}

THREAD_SAFE AS_PRINTF(1, 2) inline int qprintf(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int code = qvprintf(format, va);
  va_end(va);
  return code;
}

THREAD_SAFE AS_PRINTF(1, 2) inline int qeprintf(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int code = qveprintf(format, va);
  va_end(va);
  return code;
}

THREAD_SAFE AS_SCANF(2, 3) inline int qfscanf(FILE *fp, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int code = qvfscanf(fp, format, va);
  va_end(va);
  return code;
}
#endif

#if !defined(feof) || !defined(ferror)
// If feof() and ferror() are not macros, we can not use them
// Fortunately, for borland and vc they are macros, so there is no problem
// GCC defines them as functions: I have no idea whether they will work or not
// Anyway we remove the error directive from this file
// so the plugins can be compiled with gcc
//#error  feof or ferror are not macros!
#endif

/*==================================================*/
/* Add-ins for 2..32 byte read/writes.
        fp   - pointer to file
        res  - value read from file
        size - size of value in bytes (1..32)
        mostfirst - is MSB first? (0/1)
   All these functions return 0 - Ok */

idaman THREAD_SAFE int ida_export freadbytes(FILE *fp,void *res,int size,int mostfirst);
idaman THREAD_SAFE int ida_export fwritebytes(FILE *fp,const void *l,int size,int mostfirst);

#ifdef __cplusplus
#define DEF_FREADBYTES(read, write, type, size)                         \
        inline int read(FILE *fp, type *res, bool mostfirst)            \
                { return freadbytes(fp, res, size, mostfirst); }        \
        inline int write(FILE *fp, const type *res, bool mostfirst)     \
                { return fwritebytes(fp, res, size, mostfirst); }
DEF_FREADBYTES(fread2bytes, fwrite2bytes, int16, 2)
DEF_FREADBYTES(fread2bytes, fwrite2bytes, uint16, 2)
DEF_FREADBYTES(fread4bytes, fwrite4bytes, int32, 4)
DEF_FREADBYTES(fread4bytes, fwrite4bytes, uint32, 4)
DEF_FREADBYTES(fread8bytes, fwrite8bytes, longlong, 8)
DEF_FREADBYTES(fread8bytes, fwrite8bytes, ulonglong, 8)
#else
#define fread2bytes(fp,v,mf)  freadbytes(fp,v,2,mf)
#define fwrite2bytes(fp,v,mf) fwritebytes(fp,v,2,mf)
#define fread4bytes(fp,v,mf)  freadbytes(fp,v,4,mf)
#define fwrite4bytes(fp,v,mf) fwritebytes(fp,v,4,mf)
#define fread8bytes(fp,v,mf)  freadbytes(fp,v,8,mf)
#define fwrite8bytes(fp,v,mf) fwritebytes(fp,v,8,mf)
#endif

// ---------------------------------------------------------------------------
typedef janitor_t<FILE*> file_janitor_t;
template <> inline file_janitor_t::~janitor_t()
{
  qfclose(resource);
}


#pragma pack(pop)
#endif
