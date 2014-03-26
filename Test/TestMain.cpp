#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <commdlg.h>
#include <time.h> 
#include <Psapi.h>

#include "ntdll.h"
#include <string>

#pragma comment(lib,"psapi.lib")

#pragma comment(linker, "/ENTRY:WinMain")

void ShowMessageBox(const char * format, ...);
void Test_NtSetInformationThread();


int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
	Test_NtSetInformationThread();

	return 0;
}

void ShowMessageBox(const char * format, ...)
{
	char text[2000];
	va_list va_alist;
	va_start(va_alist, format);

	wvsprintfA(text, format, va_alist);

	va_end(va_alist);

	MessageBoxA(0, text, "Text", 0);
}

void Test_NtSetInformationThread()
{
	NTSTATUS ntStat;
	BOOLEAN check = FALSE;

	ntStat = NtSetInformationThread(NtCurrentThread, ThreadHideFromDebugger, &check, sizeof(ULONG));

	if (ntStat >= 0) //it must fail
	{
		ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
	}

	ntStat = NtSetInformationThread(NtCurrentThread, ThreadHideFromDebugger, 0, 0);

	if (ntStat >= 0)
	{
		ntStat = NtQueryInformationThread(NtCurrentThread, ThreadHideFromDebugger, &check, sizeof(BOOLEAN), 0);
		if (ntStat >= 0)
		{
			if (!check)
			{
				ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
			}
			else
			{
				ShowMessageBox("Everything ok!\n");
			}
		}
		else
		{
			ShowMessageBox("NtQueryInformationThread ThreadHideFromDebugger failed %X!\n", ntStat);
		}
	}
	else
	{
		ShowMessageBox("Anti-Anti-Debug Tool detected!\n");
	}
}