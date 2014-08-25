#define _CRT_SECURE_NO_WARNINGS
#include "AttachDialog.h"

#ifdef OLLY1
#include "..\ScyllaHideOlly1Plugin\resource.h"
#include "..\ScyllaHideOlly1Plugin\ollyplugindefinitions.h"
#endif

#define BULLSEYE_CENTER_X_OFFSET		15
#define BULLSEYE_CENTER_Y_OFFSET		18

extern HINSTANCE hinst;
extern HWND hwmain; // Handle of main OllyDbg window
HBITMAP hBitmapFinderToolFilled;
HBITMAP hBitmapFinderToolEmpty;
HCURSOR hCursorPrevious;
HCURSOR hCursorSearchWindow;
BOOL bStartSearchWindow;

//toggles the finder image
void SetFinderToolImage (HWND hwnd, BOOL bSet)
{
    HBITMAP hBmpToSet = NULL;

    if (bSet)
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

    hwndToolFinder = GetDlgItem (hwnd, IDC_ICON_FINDER);

    if (hwndToolFinder)
    {
        GetWindowRect (hwndToolFinder, &rect);
        screenpoint.x = rect.left + BULLSEYE_CENTER_X_OFFSET;
        screenpoint.y = rect.top + BULLSEYE_CENTER_Y_OFFSET;
        SetCursorPos (screenpoint.x, screenpoint.y);
    }
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
            break;
        }
        case IDCANCEL: {
            EndDialog(hWnd, NULL);
            break;
        }
        case IDC_ICON_FINDER: {
            bStartSearchWindow = TRUE;

            //display empty window icon
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

            // Hide the main window.
            ShowWindow(hwmain, SW_HIDE);
            break;
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
                SetCursor (hCursorPrevious);
            }

            // remove highlighting from window.
            //if (g_hwndFoundWindow)
            //{
            //    RefreshWindow (g_hwndFoundWindow);
            //}

            //display window icon with crosshair
            SetFinderToolImage (hWnd, TRUE);

            // release the mouse capture.
            ReleaseCapture ();

            // Make the main window appear normally.
            ShowWindow (hwmain, SW_SHOWNORMAL);

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