#pragma once

#include <Windows.h>
#include <map>
#include <string>
#include <vector>

namespace scl
{
    class NtApiLoader
    {
    public:
        typedef std::map<std::wstring, std::map<std::wstring, ULONG64>> fun_storage;
        typedef void *(log_callback)(const wchar_t *msg);

        static const wchar_t kFileName[];

        std::wstring GetOsId() const;

        std::pair<bool, std::wstring> Resolve(log_callback log_cb = nullptr);
        std::pair<bool, std::wstring> Save(const wchar_t *file) const;
        std::pair<bool, std::wstring> Load(const wchar_t *file);

        const fun_storage &funs() const { return fun_rvas_; };
        const ULONG64 get_fun(const wchar_t *dll_name, const wchar_t *fun_name) const { return fun_rvas_.at(dll_name).at(fun_name); }

    protected:
        bool InitSymServ(const wchar_t *search_path, log_callback log_cb);
        static BOOL CALLBACK SymServCallbackLogger(HANDLE hProcess, ULONG uActionCode, ULONG64 pCallbackData, ULONG64 pUserContext);
        ULONG64 GetSymbolAddressFromPDB(HMODULE hModule, const wchar_t *symbol_name);

    private:
        static const std::map<std::wstring, std::vector<std::wstring>> fun_names_;
        fun_storage fun_rvas_;
    };
}
