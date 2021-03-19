#pragma once

#include <cstdarg>
#include <fstream>

namespace scl
{
    class Logger
    {
    public:
        enum Severity
        {
            Debug = 0,
            Info,
            Error,
            MaxSeverity
        };

        typedef void(*LogCbA)(const char* msg);
        typedef void(*LogCbW)(const wchar_t* msg);

    private:
        LogCbA cb_a_[MaxSeverity];
        LogCbW cb_w_[MaxSeverity];
        std::ofstream file_;

    protected:
        void LogGeneric(const char* prefix, LogCbA cb_a, LogCbW cb_w, const wchar_t* fmt, va_list ap);

    public:
        typedef void(*LogCbA)(const char *msg);
        typedef void(*LogCbW)(const wchar_t *msg);

        static const wchar_t kFileName[];

        Logger();
        ~Logger();

        bool SetLogFile(const wchar_t *filepath);

        void SetLogCb(Severity lvl, LogCbA cb)
        {
            cb_a_[lvl] = cb;
        }

        void SetLogCb(Severity lvl, LogCbW cb)
        {
            cb_w_[lvl] = cb;
        }

        void LogDebug(const wchar_t *fmt, ...);
        void LogInfo(const wchar_t *fmt, ...);
        void LogError(const wchar_t *fmt, ...);
    };
}
