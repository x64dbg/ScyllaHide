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
void Test_RtlProcessFlsData();
void SuccessMethod();
void Test_OutputDebugString();
void Test_NtQueryObject();
DWORD GetProcessIdByThreadHandle(HANDLE hThread);


int CALLBACK WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
    //Test_NtSetInformationThread();
    //Test_RtlProcessFlsData();
    //Test_OutputDebugString();
    Test_NtQueryObject();
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

void Test_OutputDebugString()
{
    typedef DWORD(WINAPI * t_OutputDebugStringA)(LPCSTR lpOutputString); //Kernel32.dll
    typedef DWORD(WINAPI * t_OutputDebugStringW)(LPCWSTR lpOutputString); //Kernel32.dll

    t_OutputDebugStringA _OutputDebugStringA = (t_OutputDebugStringA)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OutputDebugStringA");
    t_OutputDebugStringW _OutputDebugStringW = (t_OutputDebugStringW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OutputDebugStringW");


    ShowMessageBox("OutputDebugStringA return value %X\n", _OutputDebugStringA("test"));
    ShowMessageBox("Last error %X\n", GetLastError());

}

DWORD GetProcessIdByThreadHandle(HANDLE hThread)
{
    THREAD_BASIC_INFORMATION tbi;

    if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0)))
    {
        return (DWORD)tbi.ClientId.UniqueProcess;
    }

    return 0;
}

DWORD alignAddressValue(PVOID badAddress)
{
    const int alignValue = sizeof(DWORD_PTR);
    DWORD moduloResult = (DWORD_PTR)badAddress % alignValue;

    if (moduloResult)
    {
        return (alignValue - moduloResult);
    }
    else
    {
        return 0;
    }
}

void Test_NtQueryObject()
{
    ULONG ret;
    POBJECT_TYPES_INFORMATION pObjTypes = (POBJECT_TYPES_INFORMATION)VirtualAlloc(0,0x3000, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    NTSTATUS ntStat = NtQueryObject(0, ObjectTypesInformation, pObjTypes, 0x3000, &ret);

    if (ntStat >= 0)
    {
        wchar_t DebugObject[] = L"DebugObject";
        int DebugObjectLength = lstrlenW(DebugObject)*sizeof(wchar_t);

        POBJECT_TYPE_INFORMATION pOb = pObjTypes->TypeInformation;
        for (ULONG i = 0; i < pObjTypes->NumberOfTypes; i++)
        {
            if (pOb->TypeName.Length == DebugObjectLength && !memcmp(pOb->TypeName.Buffer, DebugObject, DebugObjectLength))
            {
                ShowMessageBox("TotalNumberOfHandles %08X TotalNumberOfObjects %08X\n", pOb->TotalNumberOfHandles,pOb->TotalNumberOfObjects);
                break;
            }
            pOb = (POBJECT_TYPE_INFORMATION)(((PCHAR)(pOb + 1) + ALIGN_UP(pOb->TypeName.MaximumLength, ULONG_PTR)));
        }
    }

}

FLS_CALLBACK_INFO info = { 0 };

void Test_RtlProcessFlsData()
{
    info.unk1 = (LPVOID)(GetTickCount() + 1); //Random value
    info.address = SuccessMethod;
    info.unk4 = (LPVOID)1;
    PRTL_UNKNOWN_FLS_DATA pData = (PRTL_UNKNOWN_FLS_DATA)&info.unk2;

    DWORD_PTR pPeb = 0;
#ifdef _WIN64
#define PEB_FLS_CALLBACK_OFFSET 0x0320
#define PEB_FLS_HIGHINDEX_OFFSET 0x0350
    pPeb = (DWORD_PTR)__readgsqword(12 * sizeof(DWORD_PTR));
#else
#define PEB_FLS_CALLBACK_OFFSET 0x020C
#define PEB_FLS_HIGHINDEX_OFFSET 0x022C
    pPeb = (DWORD_PTR)__readfsdword(12 * sizeof(DWORD_PTR));
#endif

    ULONG * FlsHighIndex = (ULONG *)(pPeb + PEB_FLS_HIGHINDEX_OFFSET);
    DWORD_PTR * FlsCallback = (DWORD_PTR *)(pPeb + PEB_FLS_CALLBACK_OFFSET);
    *FlsCallback = (DWORD_PTR)&info;
    *FlsHighIndex = *FlsHighIndex + 1;

    RtlProcessFlsData(pData);
}

void SuccessMethod()
{
    ShowMessageBox("Target runs, nice!");
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
