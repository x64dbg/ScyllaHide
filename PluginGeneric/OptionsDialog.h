#pragma once
#include <windows.h>
#include <Commctrl.h>

void ShowAbout(HWND hWnd);
bool GetFileDialog(TCHAR Buffer[MAX_PATH]);
void UpdateOptions(HWND hWnd);
void SaveOptions(HWND hWnd);
HWND CreateTooltips(HWND hwndDlg);
INT_PTR CALLBACK OptionsProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);