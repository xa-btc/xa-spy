// Native presentation only. Controls retain their Windows input/accessibility behavior.
#include "theme.hpp"
#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <algorithm>
#include <array>

namespace xa::ui {
namespace {
constexpr COLORREF base = RGB(16, 22, 32), surface = RGB(24, 33, 47);
constexpr COLORREF control = RGB(31, 43, 60), hover = RGB(42, 58, 79);
constexpr COLORREF text = RGB(229, 236, 247), muted = RGB(148, 165, 188);
constexpr COLORREF border = RGB(57, 74, 97), accent = RGB(92, 170, 255);
constexpr COLORREF primary = RGB(32, 91, 158), selection = RGB(38, 72, 112);
constexpr UINT_PTR buttonKind = 1, comboKind = 2, headerKind = 3;
struct Resources {
    HBRUSH background = CreateSolidBrush(base);
    HBRUSH panel = CreateSolidBrush(surface);
    HFONT normal = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    ~Resources() { DeleteObject(normal); DeleteObject(panel); DeleteObject(background); }
};
Resources& resources() { static Resources value; return value; }
void fill(HDC dc, const RECT& bounds, COLORREF color) {
    SetDCBrushColor(dc, color); FillRect(dc, &bounds, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
}
void frame(HDC dc, const RECT& bounds, COLORREF color) {
    SetDCBrushColor(dc, color); FrameRect(dc, &bounds, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
}
void label(HDC dc, HWND window, RECT bounds, COLORREF color, UINT flags) {
    std::array<wchar_t, 1024> value{};
    GetWindowTextW(window, value.data(), static_cast<int>(value.size()));
    SelectObject(dc, font()); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, color);
    if (SendMessageW(window, WM_QUERYUISTATE, 0, 0) & UISF_HIDEACCEL) flags |= DT_HIDEPREFIX;
    DrawTextW(dc, value.data(), -1, &bounds, flags | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
}
void paintButton(HWND window, HDC dc, bool hot) {
    RECT bounds{}; GetClientRect(window, &bounds);
    const auto state = SendMessageW(window, BM_GETSTATE, 0, 0);
    const bool enabled = IsWindowEnabled(window) != FALSE;
    const bool pressed = (state & BST_PUSHED) != 0;
    const bool focused = GetFocus() == window && !(SendMessageW(window, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS);
    const auto style = GetWindowLongPtrW(window, GWL_STYLE);
    if ((style & BS_TYPEMASK) == BS_AUTOCHECKBOX) {
        fill(dc, bounds, base);
        RECT box{2, (bounds.bottom - 16) / 2, 18, (bounds.bottom + 16) / 2};
        const bool checked = SendMessageW(window, BM_GETCHECK, 0, 0) == BST_CHECKED;
        fill(dc, box, checked && enabled ? primary : surface);
        frame(dc, box, enabled && (hot || focused) ? accent : border);
        if (checked) {
            const auto pen = CreatePen(PS_SOLID, 2, enabled ? text : muted);
            const auto old = SelectObject(dc, pen);
            MoveToEx(dc, box.left + 3, box.top + 8, nullptr);
            LineTo(dc, box.left + 6, box.top + 11); LineTo(dc, box.left + 12, box.top + 4);
            SelectObject(dc, old); DeleteObject(pen);
        }
        bounds.left = 27; label(dc, window, bounds, enabled ? text : muted, DT_LEFT);
        if (focused) { InflateRect(&bounds, -1, -3); DrawFocusRect(dc, &bounds); }
        return;
    }
    const bool action = (style & BS_TYPEMASK) == BS_DEFPUSHBUTTON;
    fill(dc, bounds, !enabled ? surface : pressed ? selection : hot ? hover : action ? primary : control);
    frame(dc, bounds, focused ? accent : border);
    InflateRect(&bounds, -8, -2);
    if (pressed) OffsetRect(&bounds, 1, 1);
    label(dc, window, bounds, enabled ? text : muted, DT_CENTER);
    if (focused) { InflateRect(&bounds, 4, -2); DrawFocusRect(dc, &bounds); }
}
void paintCombo(HWND window, HDC dc) {
    RECT bounds{}; GetClientRect(window, &bounds);
    const bool enabled = IsWindowEnabled(window) != FALSE;
    fill(dc, bounds, surface);
    frame(dc, bounds, GetFocus() == window ? accent : border);
    RECT value = bounds; value.left += 9; value.right -= 30;
    label(dc, window, value, enabled ? text : muted, DT_LEFT);
    const int x = bounds.right - 16, y = bounds.bottom / 2;
    const auto pen = CreatePen(PS_SOLID, 2, enabled ? text : muted);
    const auto old = SelectObject(dc, pen);
    MoveToEx(dc, x - 4, y - 2, nullptr); LineTo(dc, x, y + 2); LineTo(dc, x + 4, y - 2);
    SelectObject(dc, old); DeleteObject(pen);
}
void paintHeader(HWND window, HDC dc) {
    RECT all{}; GetClientRect(window, &all); fill(dc, all, control);
    SelectObject(dc, font()); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, text);
    for (int index = 0; index < Header_GetItemCount(window); ++index) {
        RECT bounds{}; Header_GetItemRect(window, index, &bounds);
        std::array<wchar_t, 256> title{};
        HDITEMW item{}; item.mask = HDI_TEXT | HDI_FORMAT; item.pszText = title.data();
        item.cchTextMax = static_cast<int>(title.size()); Header_GetItem(window, index, &item);
        RECT line = bounds; line.left = line.right - 1; fill(dc, line, border);
        bounds.left += 8; bounds.right -= 6;
        DrawTextW(dc, title.data(), -1, &bounds, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    all.top = all.bottom - 1; fill(dc, all, border);
}
LRESULT CALLBACK controlProc(HWND window, UINT message, WPARAM w, LPARAM l, UINT_PTR kind, DWORD_PTR hot) {
    if (message == WM_PAINT || message == WM_PRINTCLIENT) {
        PAINTSTRUCT paint{};
        HDC dc = message == WM_PAINT ? BeginPaint(window, &paint) : reinterpret_cast<HDC>(w);
        const auto saved = SaveDC(dc);
        if (kind == buttonKind) paintButton(window, dc, hot != 0);
        else if (kind == comboKind) paintCombo(window, dc);
        else paintHeader(window, dc);
        RestoreDC(dc, saved);
        if (message == WM_PAINT) EndPaint(window, &paint);
        return 0;
    }
    if (message == WM_ERASEBKGND) return 1;
    if (message == WM_MOUSEMOVE && !hot) {
        SetWindowSubclass(window, controlProc, kind, 1);
        TRACKMOUSEEVENT tracking{sizeof tracking, TME_LEAVE, window, 0}; TrackMouseEvent(&tracking);
        InvalidateRect(window, nullptr, FALSE);
    }
    if (message == WM_MOUSELEAVE) { SetWindowSubclass(window, controlProc, kind, 0); InvalidateRect(window, nullptr, FALSE); }
    if (message == WM_NCDESTROY) RemoveWindowSubclass(window, controlProc, kind);
    const auto result = DefSubclassProc(window, message, w, l);
    switch (message) {
    case WM_ENABLE: case WM_SETFOCUS: case WM_KILLFOCUS: case WM_SETTEXT: case WM_UPDATEUISTATE:
    case BM_SETCHECK: case BM_SETSTATE: case BM_SETSTYLE: case CB_SETCURSEL: case CB_SHOWDROPDOWN:
    case WM_LBUTTONDOWN: case WM_LBUTTONUP: case WM_KEYDOWN: case WM_KEYUP:
        InvalidateRect(window, nullptr, FALSE); break;
    }
    return result;
}
}
HBRUSH background() { return resources().background; }
HFONT font() { return resources().normal; }
void themeWindow(HWND window) {
    BOOL dark = TRUE;
    if (FAILED(DwmSetWindowAttribute(window, 20, &dark, sizeof dark)))
        DwmSetWindowAttribute(window, 19, &dark, sizeof dark);
    // Windows 11 caption colors; older systems safely ignore unsupported attributes.
    DwmSetWindowAttribute(window, 35, &base, sizeof base);
    DwmSetWindowAttribute(window, 36, &text, sizeof text);
    DwmSetWindowAttribute(window, 34, &border, sizeof border);
}
void themeControl(HWND window) {
    if (!window) return;
    SendMessageW(window, WM_SETFONT, reinterpret_cast<WPARAM>(font()), TRUE);
    std::array<wchar_t, 64> klass{}; GetClassNameW(window, klass.data(), static_cast<int>(klass.size()));
    const bool button = lstrcmpiW(klass.data(), L"Button") == 0;
    // Buttons are fully custom-painted. Disable native visual-style animation,
    // including the default-button pulse, while retaining native input behavior.
    SetWindowTheme(window, button ? L"" : L"DarkMode_Explorer", button ? L"" : nullptr);
    if (button) SetWindowSubclass(window, controlProc, buttonKind, 0);
    else if (lstrcmpiW(klass.data(), L"ComboBox") == 0) {
        SetWindowTheme(window, L"DarkMode_CFD", nullptr);
        SetWindowSubclass(window, controlProc, comboKind, 0);
        SendMessageW(window, CB_SETITEMHEIGHT, 0, 24);
        SendMessageW(window, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1), 24);
    } else if (lstrcmpiW(klass.data(), WC_LISTVIEWW) == 0) {
        ListView_SetBkColor(window, surface); ListView_SetTextBkColor(window, surface); ListView_SetTextColor(window, text);
        const auto header = ListView_GetHeader(window);
        SendMessageW(header, WM_SETFONT, reinterpret_cast<WPARAM>(font()), TRUE);
        SetWindowSubclass(header, controlProc, headerKind, 0);
    }
}
bool themeMessage(HWND window, UINT message, WPARAM w, LPARAM l, LRESULT& result) {
    if (message == WM_ERASEBKGND) {
        RECT bounds{}; GetClientRect(window, &bounds);
        FillRect(reinterpret_cast<HDC>(w), &bounds, background()); result = 1; return true;
    }
    if (message == WM_CTLCOLOREDIT || message == WM_CTLCOLORSTATIC || message == WM_CTLCOLORLISTBOX || message == WM_CTLCOLORBTN) {
        const auto dc = reinterpret_cast<HDC>(w); const auto child = reinterpret_cast<HWND>(l);
        std::array<wchar_t, 64> klass{}; GetClassNameW(child, klass.data(), static_cast<int>(klass.size()));
        const bool panel = message != WM_CTLCOLORSTATIC || lstrcmpiW(klass.data(), L"Edit") == 0;
        SetTextColor(dc, IsWindowEnabled(child) ? text : muted); SetBkColor(dc, panel ? surface : base);
        result = reinterpret_cast<LRESULT>(panel ? resources().panel : background()); return true;
    }
    if (message == WM_MEASUREITEM) {
        auto* item = reinterpret_cast<MEASUREITEMSTRUCT*>(l);
        if (item && item->CtlType == ODT_COMBOBOX) { item->itemHeight = 24; result = TRUE; return true; }
    }
    if (message == WM_DRAWITEM) {
        const auto* item = reinterpret_cast<DRAWITEMSTRUCT*>(l);
        if (item && item->CtlType == ODT_COMBOBOX) {
            const auto saved = SaveDC(item->hDC);
            fill(item->hDC, item->rcItem, (item->itemState & ODS_SELECTED) ? selection : surface);
            std::array<wchar_t, 256> value{};
            if (item->itemID != static_cast<UINT>(-1) &&
                SendMessageW(item->hwndItem, CB_GETLBTEXTLEN, item->itemID, 0) < static_cast<LRESULT>(value.size()))
                SendMessageW(item->hwndItem, CB_GETLBTEXT, item->itemID, reinterpret_cast<LPARAM>(value.data()));
            RECT bounds = item->rcItem; bounds.left += 9; bounds.right -= 5;
            SetBkMode(item->hDC, TRANSPARENT); SetTextColor(item->hDC, (item->itemState & ODS_DISABLED) ? muted : text);
            SelectObject(item->hDC, font());
            DrawTextW(item->hDC, value.data(), -1, &bounds, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            if ((item->itemState & ODS_FOCUS) && !(item->itemState & ODS_NOFOCUSRECT)) DrawFocusRect(item->hDC, &bounds);
            RestoreDC(item->hDC, saved); result = TRUE; return true;
        }
    }
    return false;
}
}
