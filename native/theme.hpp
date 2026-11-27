#pragma once
#include <windows.h>

namespace xa::ui {
HBRUSH background();
HFONT font();
void themeWindow(HWND window);
void themeControl(HWND control);
bool themeMessage(HWND window, UINT message, WPARAM w, LPARAM l, LRESULT& result);
}
