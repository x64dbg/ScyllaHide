#include "Logger.h"
#include <windows.h>
#include <string>


#define DEBUG_LOG_FILE_NAME L"scyllahide_debug.log"
#define ERROR_LOG_FILE_NAME L"scyllahide_error.log"

char textTemp[1500] = { 0 };
char text[2000] = { 0 };

WCHAR debugLogFile[MAX_PATH] = { 0 };
WCHAR errorLogFile[MAX_PATH] = { 0 };

void LogFile(const wchar_t * filepath, const char * textEnd);
void WriteToFile(const wchar_t * filepath, const char * text, int textSize);
void GetLogFilePaths();

void GetLogFilePaths()
{
    if (errorLogFile[0] != 0)
    {
        return;
    }

    if (!GetModuleFileNameW(0, debugLogFile, _countof(debugLogFile)))
    {
        MessageBoxA(0, "GetModuleFileNameW debugLogFile", "ERROR", MB_ICONERROR);
        return;
    }

    for (size_t i = (wcslen(debugLogFile) - 1); i >= 0; i--) //remove the exe file name from full path
    {
        if (debugLogFile[i] == '\\')
        {
            debugLogFile[i + 1] = 0;
            break;
        }
    }

    wcscpy(errorLogFile, debugLogFile);
    wcscat(errorLogFile, ERROR_LOG_FILE_NAME);
    wcscat(debugLogFile, DEBUG_LOG_FILE_NAME);
}

void WriteToFile(const wchar_t * filepath, const char * text, int textSize)
{
    GetLogFilePaths();

    DWORD lpNumberOfBytesWritten = 0;

    HANDLE hFile = CreateFileW(filepath, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        SetFilePointer(hFile, 0, 0, FILE_END);
        WriteFile(hFile, text, textSize, &lpNumberOfBytesWritten, 0);
        CloseHandle(hFile);
    }
    else
    {
        MessageBoxA(0, "CreateFileW failed for log file", "ERROR", MB_ICONERROR);
    }
}

void LogFile(const wchar_t * filepath, const char * textEnd)
{
    SYSTEMTIME sysTime;
    GetLocalTime(&sysTime);
    wsprintfA(text, "%04d-%02d-%02d,%02d:%02d:%02d: ",
        sysTime.wYear,
        sysTime.wMonth,
        sysTime.wDay,
        sysTime.wHour,
        sysTime.wMinute,
        sysTime.wSecond);

    strcat(text, textEnd);
    strcat(text, "\r\n");


    WriteToFile(filepath, text, (int)strlen(text));
}

void LogErrorBox(const char * format, ...)
{
    va_list va_alist;
    va_start(va_alist, format);
    wvsprintfA(textTemp, format, va_alist);
    va_end(va_alist);

    LogFile(errorLogFile, textTemp);

    MessageBoxA(0, textTemp, "ERROR", MB_ICONERROR);
}

void LogError(const char * format, ...)
{
    va_list va_alist;
    va_start(va_alist, format);
    wvsprintfA(textTemp, format, va_alist);
    va_end(va_alist);

    LogFile(errorLogFile, textTemp);
}

void LogDebug(const char * format, ...)
{

#ifdef ENABLE_DEBUG_LOGGING
    va_list va_alist;
    va_start(va_alist, format);
    wvsprintfA(textTemp, format, va_alist);
    va_end(va_alist);

    LogFile(debugLogFile, textTemp);
#endif

}
