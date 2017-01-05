#include "ScyllaHideOlly2Plugin.h"
#include <cstdio>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Version.h>

#include "..\PluginGeneric\Injector.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"

#include "resource.h"

#pragma comment(lib, "ollydbg2\\ollydbg.lib")

std::vector<std::wstring> g_hideProfileNames;
std::wstring g_hideProfileName;
Scylla::HideSettings g_hideSettings;

typedef int (__cdecl * t_Attachtoactiveprocess)(int newprocessid);
#define OLLY201_Attachtoactiveprocess_VA 0x44B108
//PUSH EBP
#define OLLY201_Attachtoactiveprocess_CHECKVALUE 0x55

typedef void (__cdecl * t_AttachProcess)(DWORD dwPID);
void AttachProcess(DWORD dwPID);

const WCHAR ScyllaHideDllFilename[] = L"HookLibraryx86.dll";
const WCHAR NtApiIniFilename[] = L"NtApiCollection.ini";
const WCHAR ScyllaHideIniFilename[] = L"scylla_hide.ini";

WCHAR ScyllaHideDllPath[MAX_PATH] = {0};
WCHAR NtApiIniPath[MAX_PATH] = {0};
WCHAR ScyllaHideIniPath[MAX_PATH] = {0};

extern HOOK_DLL_EXCHANGE DllExchangeLoader;
extern t_LogWrapper LogWrap;
extern t_LogWrapper LogErrorWrap;
extern t_AttachProcess _AttachProcess;

//globals
HINSTANCE hinst;

HMODULE hNtdllModule = 0;
bool specialPebFix = false;
DWORD ProcessId = 0;
bool bHooked = false;

//Menu->Options
static int Moptions(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        DialogBox(hinst, MAKEINTRESOURCE(IDD_OPTIONS), hwollymain, &OptionsProc);
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->Load Profile
static int Mprofiles(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY) {
        if (name == g_hideProfileName)
            return MENU_CHECKED;

        return MENU_NORMAL;
    }
    else if (mode==MENU_EXECUTE)
    {
        g_hideProfileName = g_hideProfileNames[index];
        Scylla::LoadHideProfileSettings(ScyllaHideIniPath, g_hideProfileName.c_str(), &g_hideSettings);

        if (ProcessId)
        {
            startInjection(ProcessId, ScyllaHideDllPath, true);
            bHooked = true;
            MessageBoxA(hwollymain, "Applied changes! Restarting target is NOT necessary!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxA(hwollymain, "Please start the target to apply changes!", "[ScyllaHide Options]", MB_OK | MB_ICONINFORMATION);
        }

        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->Inject DLL
static int MinjectDll(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        if(!ProcessId) return MENU_GRAYED;
        else return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        wchar_t dllPath[MAX_PATH] = {};
        if(GetFileDialog(dllPath))
            injectDll(ProcessId, dllPath);

        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->Attach Process
static int MattachProcess(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        DialogBox(hinst, MAKEINTRESOURCE(IDD_ATTACH), hwollymain, &AttachProc);
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Context Menu in Thread window -> Suspend/Resume all Threads
static int Mthreads(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        t_table threadWindow = thread;
        int threadCount = threadWindow.sorted.n;
        int threadSize = threadWindow.sorted.itemsize;
        t_thread* threadData = (t_thread*)threadWindow.sorted.data;

        switch(index)
        {
        case 0:
        {
            //Resumeallthreads(); doesnt work as expected
            for(int i=0; i<threadCount; i++) {
                ResumeThread(threadData->thread);

                //yup this is super-hacky-pointer-kungfu but threadData++ wont work coz there
                //is 0x20bytes extra data between thread elements
                threadData = reinterpret_cast<t_thread*>((DWORD)threadData+threadSize);
            }
            break;
        }
        case 1:
        {
            //Suspendallthreads(); doesnt work as expected
            for(int i=0; i<threadCount; i++) {
                SuspendThread(threadData->thread);

                //yup this is super-hacky-pointer-kungfu but threadData++ wont work coz there
                //is 0x20bytes extra data between thread elements
                threadData = reinterpret_cast<t_thread*>((DWORD)threadData+threadSize);
            }
            break;
        }
        }
        return MENU_REDRAW;
    };
    return MENU_ABSENT;
}

//Menu->About
static int Mabout(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        // Debuggee should continue execution while message box is displayed.
        Resumeallthreads();

        ShowAbout(hwollymain);

        // Suspendallthreads() and Resumeallthreads() must be paired, even if they
        // are called in inverse order!
        Suspendallthreads();
        return MENU_NOREDRAW;
    };
    return MENU_ABSENT;
}
//menus

BOOL WINAPI DllMain(HINSTANCE hi,DWORD reason,LPVOID reserved)
{
    if (reason==DLL_PROCESS_ATTACH)
    {
		_AttachProcess = AttachProcess;
        LogWrap = LogWrapper;
        LogErrorWrap = LogErrorWrapper;

        hNtdllModule = GetModuleHandleW(L"ntdll.dll");
        GetModuleFileNameW(hi, NtApiIniPath, _countof(NtApiIniPath));
        WCHAR *temp = wcsrchr(NtApiIniPath, L'\\');
        if (temp)
        {
            temp++;
            *temp = 0;
            wcscpy(ScyllaHideDllPath, NtApiIniPath);
            wcscat(ScyllaHideDllPath, ScyllaHideDllFilename);
            wcscpy(ScyllaHideIniPath, NtApiIniPath);
            wcscat(ScyllaHideIniPath, ScyllaHideIniFilename);
            wcscat(NtApiIniPath, NtApiIniFilename);
        }

        hinst=hi;
    }
    return TRUE;
};

//register plugin
extc int ODBG2_Pluginquery(int ollydbgversion,ulong *features, wchar_t pluginname[SHORTNAME],wchar_t pluginversion[SHORTNAME])
{
    if (ollydbgversion<201)
        return 0;

    wcscpy(pluginname,PLUGINNAME);
    wcscpy(pluginversion,SCYLLA_HIDE_VERSION_STRING_W);

    return PLUGIN_VERSION;
};

//initialization happens in here
extc int __cdecl ODBG2_Plugininit(void)
{
    g_hideProfileName = Scylla::LoadHideProfileName(ScyllaHideIniPath);
    Scylla::LoadHideProfileSettings(ScyllaHideIniPath, g_hideProfileName.c_str(), &g_hideSettings);

    Addtolist(0,0,L"ScyllaHide Plugin v" SCYLLA_HIDE_VERSION_STRING_W);
    Addtolist(0,2,L"  Copyright (C) 2014 Aguila / cypher");
    Addtolist(0,2,L"  Operating System: %S", Scylla::GetWindowsVersionNameA());

    //change olly caption
    SetWindowTextW(hwollymain, g_hideSettings.ollyTitle.c_str());

    if (g_hideSettings.killAntiAttach) {
        InstallAntiAttachHook();
    }

    return 0;
}

//setup menus
extc t_menu* ODBG2_Pluginmenu(wchar_t *type)
{
    if (wcscmp(type,PWM_MAIN)==0) {
        //add profiles to menu
        g_hideProfileNames = Scylla::LoadHideProfileNames(ScyllaHideIniPath);

        for (size_t i = 0; i < g_hideProfileNames.size(); i++)
        {
            profilemenu[i] = { &g_hideProfileNames[i][0], &g_hideProfileNames[i][0], K_NONE, Mprofiles, NULL, { i } };
        }
        t_menu menu_end = {NULL, NULL, K_NONE, NULL, NULL, 0};
        profilemenu[g_hideProfileNames.size()] = menu_end;

        return mainmenu;
    }
    else if(wcscmp(type, PWM_THREADS)==0)
        return threadmenu;

    return NULL;
};

//called for every debugloop pass
extc void ODBG2_Pluginmainloop(DEBUG_EVENT *debugevent)
{

    if(!debugevent)
        return;


    if (g_hideSettings.PEBHeapFlags)
    {
        if (specialPebFix)
        {
            StartFixBeingDebugged(ProcessId, false);
            specialPebFix = false;
        }

        if (debugevent->u.LoadDll.lpBaseOfDll == hNtdllModule)
        {
            StartFixBeingDebugged(ProcessId, true);
            specialPebFix = true;
        }
    }

    switch(debugevent->dwDebugEventCode)
    {
    case CREATE_PROCESS_DEBUG_EVENT:
    {
        ProcessId = debugevent->dwProcessId;
        bHooked = false;
        ZeroMemory(&DllExchangeLoader, sizeof(HOOK_DLL_EXCHANGE));

		if (debugevent->u.CreateProcessInfo.lpStartAddress == NULL)
		{
			//ATTACH
            if (g_hideSettings.killAntiAttach)
			{
				if (!ApplyAntiAntiAttach(ProcessId))
				{
					MessageBoxW(hwollymain, L"Anti-Anti-Attach failed", L"Error", MB_ICONERROR);
				}
			}
		}

        //change olly caption again !
        SetWindowTextW(hwollymain, g_hideSettings.ollyTitle.c_str());
    }
    break;
    case LOAD_DLL_DEBUG_EVENT:
    {
        if (bHooked)
        {
            startInjection(ProcessId, ScyllaHideDllPath, false);
        }
        break;
    }
    case EXCEPTION_DEBUG_EVENT:
    {
        switch(debugevent->u.Exception.ExceptionRecord.ExceptionCode)
        {
        case STATUS_BREAKPOINT:
        {
            if (!bHooked)
            {
                Message(0, L"[ScyllaHide] Reading NT API Information %s", NtApiIniPath);
                ReadNtApiInformation(NtApiIniPath, &DllExchangeLoader);

                bHooked = true;
                startInjection(ProcessId, ScyllaHideDllPath, true);
            }
        }
        break;
        }
    }
    break;
    }
}

//reset variables. new target started or restarted
extc void ODBG2_Pluginreset(void)
{
    bHooked = false;
    ProcessId = 0;
}

void LogErrorWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    Error(L"%s",text);
}

void LogWrapper(const WCHAR * format, ...)
{
    WCHAR text[2000];
    va_list va_alist;
    va_start(va_alist, format);

    wvsprintfW(text, format, va_alist);

    Message(0,L"%s", text);
}

void AttachProcess(DWORD dwPID)
{
	t_Attachtoactiveprocess _Attachtoactiveprocess = (t_Attachtoactiveprocess)OLLY201_Attachtoactiveprocess_VA;
	BYTE * pCheck = (BYTE *)OLLY201_Attachtoactiveprocess_VA;

	if (*pCheck == OLLY201_Attachtoactiveprocess_CHECKVALUE)
	{
		int result = _Attachtoactiveprocess((int)dwPID);
		if (result == 0)
		{
			Setstatus(STAT_ATTACHING);
		}
		else
		{
			//Olly displays an error message
			//MessageBoxW(hwollymain,
			//	L"Can't attach to that process !",
			//	L"ScyllaHide Plugin",MB_OK|MB_ICONERROR);
		}
	}
	else
	{
		MessageBoxW(hwollymain, L"Your Olly Version is not supported! Please use version 201 http://www.ollydbg.de/odbg201.zip", L"ERROR", MB_ICONERROR);
	}
}
