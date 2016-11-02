#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "resource.h"
#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include "..\PluginGeneric\Injector.h"
#include "ScyllaHideOlly2Plugin.h"
#include "..\InjectorCLI\ReadNtConfig.h"
#include "..\PluginGeneric\UpdateCheck.h"
#include "..\PluginGeneric\IniSettings.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "..\PluginGeneric\AttachDialog.h"
#include "..\InjectorCLI\OperatingSysInfo.h"

//scyllaHide definitions
struct HideOptions pHideOptions = {0};

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

extern WCHAR CurrentProfile[MAX_SECTION_NAME];
extern WCHAR ProfileNames[2048];
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
        if(wcscmp(CurrentProfile, name)==0)
            return MENU_CHECKED;

        return MENU_NORMAL;
    }
    else if (mode==MENU_EXECUTE)
    {
        int offset = 10;
        SetCurrentProfile(index+offset);
        ReadSettings();

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

//Menu->Update-Check
static int Mupdate(t_table *pt,wchar_t *name,ulong index,int mode)
{
    if (mode==MENU_VERIFY)
        return MENU_NORMAL;
    else if (mode==MENU_EXECUTE)
    {
        if(isNewVersionAvailable()) {
            MessageBoxA(hwollymain,
                        "There is a new version of ScyllaHide available !\n\n"
                        "Check out https://bitbucket.org/NtQuery/scyllahide/downloads \n"
                        "or some RCE forums !",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
        } else {
            MessageBoxA(hwollymain,
                        "You already have the latest version of ScyllaHide !",
                        "ScyllaHide Plugin",MB_OK|MB_ICONINFORMATION);
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
    ReadCurrentProfile();
    ReadSettings();

    Addtolist(0,0,L"ScyllaHide Plugin v" SCYLLA_HIDE_VERSION_STRING_W);
    Addtolist(0,2,L"  Copyright (C) 2014 Aguila / cypher");
    Addtolist(0,2,L"  Operating System: %S", GetWindowsVersionNameA());

    //change olly caption
    SetWindowTextW(hwollymain, pHideOptions.ollyTitle);

    if(pHideOptions.killAntiAttach) {
        InstallAntiAttachHook();
    }

    return 0;
}

//setup menus
extc t_menu* ODBG2_Pluginmenu(wchar_t *type)
{
    if (wcscmp(type,PWM_MAIN)==0) {
        //add profiles to menu
        GetPrivateProfileSectionNamesWithFilter();

        WCHAR* profile = ProfileNames;
        int i=0;
        while(*profile != 0x00 && i<MAX_PROFILES-1) {
            t_menu profile_entry = {profile, profile, K_NONE, Mprofiles, NULL, i};
            profilemenu[i] = profile_entry;
            i++;

            profile = profile + wcslen(profile) + 1;
        }
        t_menu menu_end = {NULL, NULL, K_NONE, NULL, NULL, 0};
        profilemenu[i] = menu_end;

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


    if (pHideOptions.PEBHeapFlags)
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
			if(pHideOptions.killAntiAttach)
			{
				if (!ApplyAntiAntiAttach(ProcessId))
				{
					MessageBoxW(hwollymain, L"Anti-Anti-Attach failed", L"Error", MB_ICONERROR);
				}
			}
		}

        //change olly caption again !
        SetWindowTextW(hwollymain, pHideOptions.ollyTitle);
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
                ReadNtApiInformation();

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