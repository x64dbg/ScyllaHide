#pragma once


#ifndef _WIN64
#pragma comment(lib, "ntdllext_x86.lib")
#else
#pragma comment(lib, "ntdllext_x64.lib")
#endif

#ifdef __cplusplus
extern "C" {
#endif

//__declspec(dllimport) int __cdecl memcmp(const void *Buf1, const void *Buf2, size_t Size);
//__declspec(dllimport) void * __cdecl memmove(void *mem1, const void *mem2, int size);
//__declspec(dllimport) void * __cdecl memcpy(void *mem1, const void *mem2, int size);
//__declspec(dllimport) void * __cdecl memset(void *mem1, int x, int y);
//__declspec(dllimport) char *  __cdecl strcpy(char *Str1, const char *Str2); 
//__declspec(dllimport) size_t  __cdecl strlen(const char *Str);
//__declspec(dllimport) size_t __cdecl wcslen(const wchar_t *Str);
//__declspec(dllimport) int __cdecl _wcsicmp(const wchar_t *Str1, const wchar_t *Str2);
//__declspec(dllimport) int __cdecl _wcsnicmp(const wchar_t *Str1, const wchar_t *Str2, size_t MaxCount);

#ifdef __cplusplus
};
#endif