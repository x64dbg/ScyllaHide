#pragma once

#pragma warning(push)
#pragma warning(disable: 4091)
#include "../3rdparty/dbghelp/dbghelp.h"
#pragma warning(pop)

#ifdef _WIN64
#pragma comment(lib,"../3rdparty/dbghelp/dbghelp_x64.lib")
#else
#pragma comment(lib,"../3rdparty/dbghelp/dbghelp_x86.lib")
#endif