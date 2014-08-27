#define _CRT_SECURE_NO_WARNINGS
#include "AttachDialog.h"
#include <Psapi.h>
#include <string>

#ifdef OLLY1
#include "..\ScyllaHideOlly1Plugin\resource.h"
#elif OLLY2
#include "..\ScyllaHideOlly2Plugin\resource.h"
#include "..\ScyllaHideOlly2Plugin\plugin.h"
#elif __IDP__
#include "..\ScyllaHideIDAProPlugin\resource.h"
#include "..\ScyllaHideIDAProPlugin\idasdk\idp.hpp"
#endif

#define BULLSEYE_CENTER_X_OFFSET		15
#define BULLSEYE_CENTER_Y_OFFSET		18

typedef void (__cdecl * t_AttachProcess)(DWORD dwPID);

t_AttachProcess _AttachProcess = 0;

extern HINSTANCE hinst;
#ifdef OLLY1
extern HWND hwmain; // Handle of main OllyDbg window
#elif OLLY2
HWND hwmain = hwollymain;
#elif __IDP__
HWND hwmain = (HWND)callui(ui_get_hwnd).vptr;
#endif
HBITMAP hBitmapFinderToolFilled = NULL;
HBITMAP hBitmapFinderToolEmpty = NULL;
HCURSOR hCursorPrevious = NULL;
HCURSOR hCursorSearchWindow = NULL;
BOOL bStartSearchWindow = FALSE;
HWND hwndFoundWindow = NULL;
wchar_t title[256];
wchar_t pidTextHex[9];
wchar_t pidTextDec[11];
wchar_t filepath[MAX_PATH];
DWORD pid = NULL;
HANDLE hProc = NULL;

//toggles the finder image
void SetFinderToolImage (HWND hwnd, BOOL bSet)
{
    HBITMAP hBmpToSet = NULL;

    if(bSet)
    {
        hBmpToSet = hBitmapFinderToolFilled;
    }
    else
    {
        hBmpToSet = hBitmapFinderToolEmpty;
    }

    SendDlgItemMessage(hwnd, IDC_ICON_FINDER, STM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)hBmpToSet);
}

//centers cursor in bullseye. adds to the illusion that the bullseye can be dragged out
void MoveCursorPositionToBullsEye (HWND hwnd)
{
    HWND hwndToolFinder = NULL;
    RECT rect;
    POINT screenpoint;

    hwndToolFinder = GetDlgItem(hwnd, IDC_ICON_FINDER);

    if(hwndToolFinder)
    {
        GetWindowRect (hwndToolFinder, &rect);
        screenpoint.x = rect.left + BULLSEYE_CENTER_X_OFFSET;
        screenpoint.y = rect.top + BULLSEYE_CENTER_Y_OFFSET;
        SetCursorPos (screenpoint.x, screenpoint.y);
    }
}

//does some sanity checks on a possible found window
BOOL CheckWindowValidity (HWND hwnd, HWND hwndToCheck)
{
    HWND hwndTemp = NULL;

    if(hwndToCheck == NULL)
    {
        return FALSE;
    }

    if(IsWindow(hwndToCheck) == FALSE)
    {
        return FALSE;
    }

    //same window as previous?
    if(hwndToCheck == hwndFoundWindow)
    {
        return FALSE;
    }

    //debugger window is not a valid one
    if(hwndToCheck == hwmain)
    {
        return FALSE;
    }

    // It also must not be the "Search Window" dialog box itself.
    if(hwndToCheck == hwnd)
    {
        return FALSE;
    }

    // It also must not be one of the dialog box's children...
    hwndTemp = GetParent(hwndToCheck);
    if((hwndTemp == hwnd) || (hwndTemp == hwmain))
    {
        return FALSE;
    }

    hwndFoundWindow = hwndToCheck;
    return TRUE;
}

//attach dialog proc
INT_PTR CALLBACK AttachProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        hBitmapFinderToolFilled = LoadBitmap(hinst, MAKEINTRESOURCE(IDB_FINDERFILLED));
        hBitmapFinderToolEmpty = LoadBitmap(hinst, MAKEINTRESOURCE(IDB_FINDEREMPTY));
        hCursorSearchWindow = LoadCursor(hinst, MAKEINTRESOURCE(IDC_CURSOR_SEARCH_WINDOW));

        break;
    }
    case WM_CLOSE:
    {
        EndDialog(hWnd, NULL);
    }
    break;

    case WM_COMMAND :
    {
        switch(LOWORD(wParam)) {
        case IDOK: { //attach
            if(pid!=NULL) {
                EndDialog(hWnd, NULL);

                if (_AttachProcess != 0)
                {
                    _AttachProcess(pid);
                }
                else
                {
                    MessageBoxW(0, L"Developer!!! You forgot something _AttachProcess!!!!!", L"ERROR", 0);
                }
            }
            break;
        }
        case IDCANCEL: {
            EndDialog(hWnd, NULL);
            break;
        }
        case IDC_PIDHEX: {
            wchar_t buf[9];
            if(0<GetDlgItemTextW(hWnd, IDC_PIDHEX, buf, sizeof(buf))) {
                if(wcscmp(buf, pidTextHex)!=0) {
                    wcscpy(pidTextHex, buf);
                    swscanf(pidTextHex, L"%X", &pid);
                    wsprintfW(pidTextDec, L"%d", pid);
                    SetDlgItemTextW(hWnd, IDC_PIDDEC, pidTextDec);
                }
            }
            break;
        }
        case IDC_PIDDEC:
        {
            wchar_t buf[11];
            if(0<GetDlgItemTextW(hWnd, IDC_PIDDEC, buf, sizeof(buf))) {
                if(wcscmp(buf, pidTextDec)!=0) {
                    wcscpy(pidTextDec, buf);
                    swscanf(pidTextDec, L"%d", &pid);
                    wsprintfW(pidTextHex, L"%X", pid);
                    SetDlgItemTextW(hWnd, IDC_PIDHEX, pidTextHex);
                }
            }
            break;
        }
        case IDC_ICON_FINDER: {
            bStartSearchWindow = TRUE;

            SetFinderToolImage(hWnd, FALSE);

            MoveCursorPositionToBullsEye(hWnd);

            // Set the screen cursor to the BullsEye cursor.
            if (hCursorSearchWindow)
            {
                hCursorPrevious = SetCursor(hCursorSearchWindow);
            }
            else
            {
                hCursorPrevious = NULL;
            }

            //redirect all mouse events to this AttachProc
            SetCapture(hWnd);

            ShowWindow(hwmain, SW_HIDE);
            break;
        }

        }

        break;
    }

    case WM_MOUSEMOVE :
    {
        if (bStartSearchWindow)
        {
            POINT screenpoint;
            HWND hwndCurrentWindow = NULL;

            GetCursorPos(&screenpoint);

            hwndCurrentWindow = WindowFromPoint(screenpoint);

            if (CheckWindowValidity(hWnd, hwndCurrentWindow))
            {
                //get some info about the window
                GetWindowThreadProcessId(hwndFoundWindow, &pid);
                hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProc)
                {
                    ZeroMemory(filepath, sizeof(filepath));
                    GetModuleFileNameExW(hProc, NULL, filepath, _countof(filepath));
                    CloseHandle(hProc);

                    if (wcslen(filepath) > 0)
                    {
                        SetDlgItemTextW(hWnd, IDC_EXEPATH, wcsrchr(filepath, L'\\')+1);
                    }
                    else
                    {
                        SetDlgItemTextW(hWnd, IDC_EXEPATH, L"UNKNOWN");
                    }
                }
                else
                {
                    SetDlgItemTextW(hWnd, IDC_EXEPATH, L"UNKNOWN");
                }

                if (GetWindowTextW(hwndCurrentWindow, title, _countof(title)) > 0)
                {
                    SetDlgItemTextW(hWnd, IDC_TITLE, title);
                }
                wsprintfW(pidTextHex, L"%X", pid);
                wsprintfW(pidTextDec, L"%d", pid);
                SetDlgItemTextW(hWnd, IDC_PIDHEX, pidTextHex);
                SetDlgItemTextW(hWnd, IDC_PIDDEC, pidTextDec);


            }
        }

        break;
    }

    case WM_LBUTTONUP :
    {
        if (bStartSearchWindow)
        {
            // restore cursor
            if (hCursorPrevious)
            {
                SetCursor(hCursorPrevious);
            }

            SetFinderToolImage(hWnd, TRUE);

            // release the mouse capture.
            ReleaseCapture();

            ShowWindow(hwmain, SW_SHOWNORMAL);

            bStartSearchWindow = FALSE;
        }

        break;
    }

    default:
    {
        return FALSE;
    }
    }

    return 0;
}