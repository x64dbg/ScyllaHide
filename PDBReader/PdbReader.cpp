#include <Windows.h>
#include <cstdio>
#include <Scylla/NtApiLoader.h>
#include <Scylla/Util.h>

static void logger(const wchar_t *msg)
{
    fputws(msg, stdout);
}

int wmain(int argc, wchar_t* argv[])
{
    scl::NtApiLoader api_loader;

    auto ini_file = scl::GetModuleFileNameW();
    ini_file.resize(ini_file.find_last_of(L"\\") + 1);
    ini_file += scl::NtApiLoader::kFileName;

    wprintf(L"OS ID: %s\n", api_loader.GetOsId().c_str());

    auto res = api_loader.Resolve((scl::NtApiLoader::log_callback *)logger);
    if (!res.first)
    {
        fputws(res.second.c_str(), stdout);
        return EXIT_FAILURE;
    }

    for (auto dll : api_loader.funs())
    {
        for (auto fun : dll.second)
        {
            wprintf(L"Resolved %s!%s = %llx\n", dll.first.c_str(), fun.first.c_str(), fun.second);
        }
    }

    res = api_loader.Save(ini_file.c_str());
    if (!res.first)
    {
        fputws(res.second.c_str(), stdout);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
