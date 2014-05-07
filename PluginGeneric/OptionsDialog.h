#pragma once
#include <windows.h>

void UpdateOptions(HWND hWnd);
void SaveOptions(HWND hWnd);
INT_PTR CALLBACK OptionsProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);