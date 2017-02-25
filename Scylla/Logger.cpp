#include "Logger.h"
#include <cassert>
#include <chrono>
#include <iomanip>
#include "Util.h"

const wchar_t scl::Logger::kFileName[] = L"scylla_hide.log";

scl::Logger::Logger()
{
    ZeroMemory(cb_a_, sizeof(cb_a_));
    ZeroMemory(cb_w_, sizeof(cb_w_));
}

scl::Logger::~Logger()
{
    if (file_.is_open())
        file_.close();
}

bool scl::Logger::SetLogFile(const wchar_t *filepath)
{
    if (file_.is_open())
        file_.close();

    file_.open(filepath);

    return file_.is_open();
}

void scl::Logger::LogDebug(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    LogGeneric("DEBUG", cb_a_[Debug], cb_w_[Debug], fmt, ap);
    va_end(ap);
}

void scl::Logger::LogInfo(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    LogGeneric("INFO", cb_a_[Info], cb_w_[Info], fmt, ap);
    va_end(ap);
}

void scl::Logger::LogError(const wchar_t *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    LogGeneric("ERROR", cb_a_[Error], cb_w_[Error], fmt, ap);
    va_end(ap);
}

void scl::Logger::LogGeneric(const char *prefix, LogCbA cb_a, LogCbW cb_w, const wchar_t *fmt, va_list ap)
{
    va_list vap;
    va_copy(vap, ap);
    auto strw = scl::vfmtw(fmt, ap);
    va_end(ap);

    if (cb_w)
        cb_w(strw.c_str());

    if (cb_a || file_.is_open())
    {
        auto stra = scl::wstr_conv().to_bytes(strw);

        if (cb_a)
            cb_a(stra.c_str());

        if (file_.is_open())
        {
            struct tm ltm;
            auto now = std::chrono::system_clock::now();
            auto now_t = std::chrono::system_clock::to_time_t(now);
            localtime_s(&ltm, &now_t);
            file_ << std::put_time(&ltm, "%Y.%m.%d %H:%M:%S ") << prefix << ": " << stra << std::endl;
            file_.flush();
        }
    }
}
