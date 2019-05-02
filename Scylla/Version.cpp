#include "Version.h"

void scl::ShowAboutBox(HWND hWnd)
{
    MessageBoxW(hWnd,
        SCYLLA_HIDE_NAME_W L" Plugin v" SCYLLA_HIDE_VERSION_STRING_W L" (" TEXT(__DATE__) L")\n\n"
        L"Copyright (C) 2014-" COMPILE_YEAR_W L" Aguila / cypher\n\n"
        L"Special thanks to:\n"
        L"- What for his POISON assembler source code\n"
        L"- waliedassar for his blog posts\n"
        L"- Peter Ferrie for his Anti-Debug PDFs\n"
        L"- MaRKuS-DJM for OllyAdvanced assembler source code\n"
        L"- Steve Micallef for his IDA SDK doc\n"
        L"- Authors of PhantOm and StrongOD\n"
        L"- Tuts4You, Exetools, Exelab community for testing\n"
        L"- last but not least deepzero & mr.exodia for tech chats",
        SCYLLA_HIDE_NAME_W L" Plugin", MB_ICONINFORMATION);
}
