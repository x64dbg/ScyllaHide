#pragma once

#include <Windows.h>

namespace scl
{
    class Handle
    {
    public:
        explicit Handle(HANDLE handle) : handle_(handle) {}
        ~Handle()
        {
            if (handle_ && (handle_ != INVALID_HANDLE_VALUE))
                CloseHandle(handle_);
        }

        Handle(const Handle &other) = delete;
        Handle &operator=(const Handle &other) = delete;

        HANDLE get() const { return handle_; }

    private:
        HANDLE handle_;
    };
}
