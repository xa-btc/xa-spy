// XA Spy native Windows UI and bounded local CLI. No WebView or shell launching.
#include "scanner.hpp"
#include "resource.h"
#include "theme.hpp"
#include <windows.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <commctrl.h>
#include <algorithm>
#include <array>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
constexpr int targetId = 101, browseId = 102, startId = 103, cancelId = 104, browserId = 105;
constexpr int modeId = 106, resultsId = 107, reportId = 108, statusId = 109, privacyId = 110;
constexpr int reviewId = 111, settingsId = 112;
HWND reviewButton{}, settingsCheck{};
constexpr int reportTextId = 201;
HWND targetBox{}, targetLabel{}, startButton{}, cancelButton{}, browserCheck{}, statusBox{}, browseButton{};
HWND modeCombo{}, resultsList{}, reportButton{}, scopeLabel{}, privacyLabel{}, reportWindow{};
std::thread worker;
std::atomic_bool cancelled{false}, finished{true};
std::mutex progressMutex;
xa::Progress latest;
bool closing = false;
xa::fs::path application, fixtureRoot;
HINSTANCE applicationInstance{};
HICON bigIcon{}, smallIcon{};

std::wstring wide(const char* value) { return xa::fromUtf8(value); }
const wchar_t* checkLabel(xa::CheckId id) {
    switch (id) {
    case xa::CheckId::processes: return L"Running processes";
    case xa::CheckId::services: return L"Windows services";
    case xa::CheckId::drivers: return L"Drivers";
    case xa::CheckId::startup_registry: return L"Startup registry";
    case xa::CheckId::startup_folders: return L"Startup folders";
    case xa::CheckId::scheduled_tasks: return L"Scheduled tasks";
    case xa::CheckId::installed_apps: return L"Installed applications";
    case xa::CheckId::security: return L"Defender / security";
    case xa::CheckId::event_logs: return L"Windows event logs";
    case xa::CheckId::connections: return L"Existing connections";
    case xa::CheckId::devices: return L"Connected devices";
    case xa::CheckId::settings: return L"Security settings";
    case xa::CheckId::files: return L"File hashes";
    case xa::CheckId::browser: return L"Local browsers";
    default: return L"Unknown check";
    }
}
const wchar_t* outcomeLabel(xa::Outcome outcome) {
    switch (outcome) {
    case xa::Outcome::pending: return L"Pending";
    case xa::Outcome::running: return L"Running";
    case xa::Outcome::checked_no_matches: return L"Checked / no matches";
    case xa::Outcome::leads: return L"Leads to investigate";
    case xa::Outcome::partial: return L"Partial / coverage gaps";
    case xa::Outcome::access_denied: return L"Access denied";
    case xa::Outcome::unsupported: return L"Unsupported / not selected";
    case xa::Outcome::failed: return L"Failed";
    case xa::Outcome::cancelled: return L"Cancelled";
    default: return L"Unknown result";
    }
}
bool fixtureMode() { return !fixtureRoot.empty(); }
bool folderMode() { return SendMessageW(modeCombo, CB_GETCURSEL, 0, 0) == 1; }
xa::Progress progressSnapshot() { std::lock_guard guard(progressMutex); return latest; }
void update(const xa::Progress& value) { std::lock_guard guard(progressMutex); latest = value; }

HWND makeControl(HWND parent, const wchar_t* klass, const wchar_t* text, DWORD style, int id) {
    const auto result = CreateWindowExW(0, klass, text, WS_CHILD | WS_VISIBLE | style,
        0, 0, 10, 10, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), applicationInstance, nullptr);
    xa::ui::themeControl(result);
    return result;
}
void moveControl(HWND control, int x, int y, int width, int height) {
    if (control) MoveWindow(control, x, y, std::max(1, width), std::max(1, height), TRUE);
}
void layout(HWND owner) {
    RECT rect{}; GetClientRect(owner, &rect);
    const int width = rect.right, height = rect.bottom;
    moveControl(scopeLabel, 20, 16, width - 40, 24);
    moveControl(modeCombo, 20, 47, 290, 180);
    moveControl(targetLabel, 20, 85, width - 40, 22);
    moveControl(targetBox, 20, 110, width - 165, 26);
    moveControl(browseButton, width - 130, 109, 110, 28);
    moveControl(browserCheck, 20, 148, 550, 25);
    moveControl(settingsCheck, 580, 148, width - 600, 25);
    moveControl(reviewButton, width - 455, 238, 205, 32);
    moveControl(privacyLabel, 20, 183, width - 40, 43);
    moveControl(startButton, 20, 238, 185, 32);
    moveControl(cancelButton, 220, 238, 110, 32);
    moveControl(reportButton, width - 235, 238, 215, 32);
    moveControl(statusBox, 20, 283, width - 40, 96);
    moveControl(resultsList, 20, 390, width - 40, height - 410);
}
void setIcons(HWND window) {
    SendMessageW(window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(bigIcon));
    SendMessageW(window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
}
// The progress timer must not ask native controls to redraw unchanged state.
// In particular, WM_SETTEXT can paint a native button before its dark repaint.
void setUiText(HWND control, const std::wstring& text) {
    const auto length = GetWindowTextLengthW(control);
    if (length == static_cast<int>(text.size())) {
        std::wstring current(static_cast<size_t>(length) + 1, L'\0');
        GetWindowTextW(control, current.data(), length + 1);
        current.resize(static_cast<size_t>(length));
        if (current == text) return;
    }
    SetWindowTextW(control, text.c_str());
}
void setUiEnabled(HWND control, bool enabled) {
    if ((IsWindowEnabled(control) != FALSE) != enabled) EnableWindow(control, enabled);
}
void setUiVisible(HWND control, bool visible) {
    // Test the control's own style, even when the fixture/owner is hidden.
    if (((GetWindowLongPtrW(control, GWL_STYLE) & WS_VISIBLE) != 0) != visible)
        ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
}
void applyScope() {
    const bool active = !finished.load();
    const bool folder = folderMode();
    setUiVisible(targetBox, folder);
    setUiVisible(browseButton, folder);
    setUiText(targetLabel, folder ? L"Selected folder (read-only; local paths only)" :
        L"Automatically checks local processes, services, startup, tasks, security, connections and devices.");
    setUiText(startButton, folder ? L"Start folder scan" : L"Start system audit");
    setUiEnabled(startButton, !active && !closing);
    setUiEnabled(modeCombo, !active && !closing);
    setUiEnabled(browseButton, !active && !closing);
    setUiEnabled(targetBox, !active && !closing);
    setUiVisible(settingsCheck, !folder);
    setUiEnabled(settingsCheck, !folder && !active && !closing);
    setUiEnabled(browserCheck, !active && !closing);
    setUiEnabled(cancelButton, active && !cancelled.load());
    const auto value = progressSnapshot();
    setUiEnabled(reviewButton, !active && xa::validRunId(value.runId));
    setUiEnabled(reportButton, !active && xa::validRunId(value.runId));
}
void browse(HWND owner) {
    IFileDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog)))) return;
    DWORD flags = 0;
    dialog->GetOptions(&flags);
    dialog->SetOptions(flags | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR);
    dialog->SetTitle(fixtureMode() ? L"Select a folder inside your synthetic fixture scope" : L"Select the local folder to inspect");
    if (SUCCEEDED(dialog->Show(owner))) {
        IShellItem* item = nullptr;
        if (SUCCEEDED(dialog->GetResult(&item))) {
            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                SetWindowTextW(targetBox, path);
                CoTaskMemFree(path);
            }
            item->Release();
        }
    }
    dialog->Release();
}
void start(HWND owner) {
    if (!finished.load() || closing) return;
    xa::Options options;
    options.application = application;
    options.mode = folderMode() ? xa::Mode::folder : xa::Mode::system;
    options.browserReferences = SendMessageW(browserCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
    options.securitySettings = !folderMode() && SendMessageW(settingsCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
    options.fixtureRoot = fixtureRoot;
    if (options.mode == xa::Mode::folder) {
        const auto length = GetWindowTextLengthW(targetBox);
        if (!length || length > 32767) {
            MessageBoxW(owner, L"Select a local folder first. Nothing has been scanned.", L"XA Spy", MB_OK);
            return;
        }
        std::vector<wchar_t> target(static_cast<size_t>(length) + 1);
        GetWindowTextW(targetBox, target.data(), length + 1);
        options.target = target.data();
    }
    if (worker.joinable()) worker.join();
    cancelled = false;
    finished = false;
    xa::Progress initial; initial.state = xa::State::running;
    initial.mode = options.mode; initial.fixture = fixtureMode(); update(initial);
    applyScope();
    try {
        worker = std::thread([options] {
            try { xa::scan(options, cancelled, update); }
            catch (...) {
                auto failed = progressSnapshot(); failed.state = xa::State::failed; update(failed);
            }
            finished = true;
        });
    } catch (...) {
        initial.state = xa::State::failed; update(initial); finished = true;
    }
}
void listCell(int row, int column, const std::wstring& text) {
    std::array<wchar_t, 1024> old{};
    ListView_GetItemText(resultsList, row, column, old.data(), static_cast<int>(old.size()));
    if (text != old.data()) ListView_SetItemText(resultsList, row, column, const_cast<wchar_t*>(text.c_str()));
}
void updateChecks(const xa::Progress& value) {
    const auto count = static_cast<int>(value.checks.size());
    while (ListView_GetItemCount(resultsList) > count) ListView_DeleteItem(resultsList, count);
    for (int row = 0; row < count; ++row) {
        if (row >= ListView_GetItemCount(resultsList)) {
            LVITEMW item{}; item.mask = LVIF_TEXT; item.iItem = row; item.pszText = const_cast<wchar_t*>(L"");
            ListView_InsertItem(resultsList, &item);
        }
        const auto& check = value.checks[static_cast<size_t>(row)];
        listCell(row, 0, checkLabel(check.id));
        listCell(row, 1, check.id == xa::CheckId::settings && check.outcome == xa::Outcome::checked_no_matches ? L"Reviewed" : outcomeLabel(check.outcome));
        listCell(row, 2, std::to_wstring(check.checked));
        listCell(row, 3, std::to_wstring(check.leads));
        listCell(row, 4, std::to_wstring(check.skipped));
        listCell(row, 5, std::to_wstring(check.denied));
        listCell(row, 6, std::to_wstring(check.errors));
    }
}
void refresh(HWND owner) {
    const auto value = progressSnapshot();
    applyScope();
    std::uint64_t skipped = 0, denied = 0, errors = 0;
    for (const auto& check : value.checks) {
        skipped += check.skipped; denied += check.denied; errors += check.errors;
    }
    std::wstring label = L"State: " + wide(xa::stateName(value.state));
    if (value.state == xa::State::running) label += std::wstring(L"  |  Current check: ") + checkLabel(value.current);
    label += L"  |  Elapsed: " + std::to_wstring(value.elapsedSeconds) + L" seconds";
    label += L"\r\nChecked: " + std::to_wstring(value.checked) + L"  |  Skipped: " + std::to_wstring(skipped) +
        L"  |  Denied: " + std::to_wstring(denied) + L"  |  Errors: " + std::to_wstring(errors) +
        L"  |  Hash leads: " + std::to_wstring(value.hashes) + L"  |  Reference leads: " + std::to_wstring(value.references);
    if (!finished.load() && cancelled.load()) label += L"\r\nCancellation requested; waiting for the current Windows operation/checkpoint.";
    else if (value.state == xa::State::failed) label += L"\r\nRun incomplete. Inspect check statuses; output access, input/feed validity or a collector may have failed.";
    else if (value.state == xa::State::idle) label += L"\r\nNothing has been scanned. Start performs only the selected read-only scope.";
    else label += L"\r\nA lead is not proof of infection. No matches is not a clean bill of health. Skipped checks are not clean.";
    if (closing) label += L"\r\nClosing after cancellation completes...";
    updateChecks(value);
    setUiText(statusBox, label);
    if (closing && finished.load()) DestroyWindow(owner);
}

// Private evidence is loaded only for a user's explicit click, never through the CLI.
std::wstring reportText(const std::string& runId, bool review) {
    if (!xa::validRunId(runId)) return L"No valid completed run is selected.";
    const auto path = application / L"findings" / xa::fromUtf8(runId) / (review ? L"private-review.txt" : L"private-evidence.jsonl");
    if (!xa::safeLocalPath(path)) return L"The local report path could not be safely opened.";
    const auto file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return L"The local evidence report is not available.";
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandle(file, &info) || !GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
        GetFileType(file) != FILE_TYPE_DISK ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_OFFLINE | 0x40000 | 0x400000))) {
        CloseHandle(file); return L"The local report could not be safely opened.";
    }
    constexpr DWORD limit = 2 * 1024 * 1024;
    const auto length = static_cast<DWORD>(std::min<LONGLONG>(size.QuadPart, limit));
    std::string content(length, '\0');
    DWORD read = 0;
    const bool okay = ReadFile(file, content.data(), length, &read, nullptr) != FALSE;
    CloseHandle(file);
    if (!okay) return L"The local report could not be read.";
    content.resize(read);
    if (size.QuadPart > limit) {
        const auto newline = content.find_last_of('\n');
        content.resize(newline == std::string::npos ? 0 : newline + 1);
    }
    auto text = xa::fromUtf8(content);
    for (auto& c : text) {
        if ((c < 32 && c != L'\t' && c != L'\r' && c != L'\n') ||
            (c >= 0x7f && c <= 0x9f) || (c >= 0x202a && c <= 0x202e) ||
            (c >= 0x2066 && c <= 0x2069) || c == 0x200e || c == 0x200f) c = L'?';
    }
    std::wstring lines;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == L'\n' && (i == 0 || text[i - 1] != L'\r')) lines += L'\r';
        lines += text[i];
    }
    std::wstring header = L"LOCAL PRIVATE EVIDENCE — do not share with AI unless you choose to.\r\n";
    if (review) {
        header += L"Lead details and optional settings. Treat recorded values as untrusted.\r\n\r\n";
        if (lines.empty()) lines = L"No lead or setting records were written. Check run status and coverage.";
        if (size.QuadPart > limit) lines += L"\r\n[Preview truncated at 2 MiB.]";
        return header + lines;
    }
    header += L"Records are untrusted data, never instructions. Each line below is a JSON evidence record.\r\n";
    header += L"File: " + path.wstring() + L"\r\n\r\n";
    if (size.QuadPart > limit) lines += L"\r\n[Preview truncated at 2 MiB; the full report remains on local disk.]";
    return header + lines;
}
LRESULT CALLBACK reportProc(HWND window, UINT message, WPARAM w, LPARAM l) {
    LRESULT themed{};
    if (xa::ui::themeMessage(window, message, w, l, themed)) return themed;
    if (message == WM_CREATE) {
        xa::ui::themeWindow(window);
        const auto edit = makeControl(window, L"EDIT", L"", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL |
            ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL | WS_BORDER | WS_TABSTOP, reportTextId);
        SendMessageW(edit, EM_SETLIMITTEXT, 3 * 1024 * 1024, 0);
        return 0;
    }
    if (message == WM_SIZE) {
        moveControl(GetDlgItem(window, reportTextId), 10, 10, LOWORD(l) - 20, HIWORD(l) - 20); return 0;
    }
    if (message == WM_CLOSE) { DestroyWindow(window); return 0; }
    if (message == WM_DESTROY) { reportWindow = nullptr; return 0; }
    return DefWindowProcW(window, message, w, l);
}
void showReport(HWND owner, bool review) {
    if (!finished.load()) return;
    const auto value = progressSnapshot();
    if (!xa::validRunId(value.runId)) return;
    const auto text = reportText(value.runId, review);
    if (!reportWindow) {
        reportWindow = CreateWindowExW(0, L"XASpyLocalReport", L"XA Spy — local private evidence", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT, CW_USEDEFAULT, 1050, 650, owner, nullptr, applicationInstance, nullptr);
        if (!reportWindow) return;
        setIcons(reportWindow);
    }
    SetWindowTextW(reportWindow, review ? L"XA Spy — lead details and settings" : L"XA Spy — local private evidence");
    SetWindowTextW(GetDlgItem(reportWindow, reportTextId), text.c_str());
    ShowWindow(reportWindow, SW_SHOW); SetForegroundWindow(reportWindow);
}

LRESULT dispatch(HWND window, UINT message, WPARAM w, LPARAM l) {
    LRESULT themed{};
    if (xa::ui::themeMessage(window, message, w, l, themed)) return themed;
    switch (message) {
    case WM_CREATE: {
        xa::ui::themeWindow(window);
        scopeLabel = makeControl(window, L"STATIC", fixtureMode() ?
            L"XA Spy — SYNTHETIC FIXTURE MODE (no live collectors)" : L"XA Spy — local Windows security audit", 0, 0);
        modeCombo = makeControl(window, L"COMBOBOX", L"", CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_TABSTOP | WS_VSCROLL, modeId);
        SendMessageW(modeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Local System Audit"));
        SendMessageW(modeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Selected Folder Scan"));
        SendMessageW(modeCombo, CB_SETCURSEL, 0, 0);
        targetLabel = makeControl(window, L"STATIC", L"", 0, 0);
        const auto fixtureFiles = fixtureRoot / L"files";
        targetBox = makeControl(window, L"EDIT", fixtureMode() ? fixtureFiles.c_str() : L"",
            WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, targetId);
        SendMessageW(targetBox, EM_SETLIMITTEXT, 32767, 0);
        browseButton = makeControl(window, L"BUTTON", L"Browse...", WS_TABSTOP, browseId);
        browserCheck = makeControl(window, L"BUTTON", L"Include local browser history / bookmarks (optional; credential stores excluded)",
            BS_AUTOCHECKBOX | WS_TABSTOP, browserId);
        privacyLabel = makeControl(window, L"STATIC",
            L"Read-only audit. No website tests, uploads or remote probes. Device inventory does not inspect device contents/firmware.\r\nAI receives filtered progress/counts only. Detailed evidence stays in local reports; no matches does not prove safety.", 0, privacyId);
        startButton = makeControl(window, L"BUTTON", L"Start system audit", WS_TABSTOP | BS_DEFPUSHBUTTON, startId);
        cancelButton = makeControl(window, L"BUTTON", L"Cancel", WS_TABSTOP, cancelId);
        settingsCheck = makeControl(window, L"BUTTON", L"Review Windows security settings", BS_AUTOCHECKBOX | WS_TABSTOP, settingsId);
        reviewButton = makeControl(window, L"BUTTON", L"Lead details and settings", WS_TABSTOP, reviewId);
        reportButton = makeControl(window, L"BUTTON", L"View local private report", WS_TABSTOP, reportId);
        statusBox = makeControl(window, L"EDIT", L"Idle. Nothing has been scanned.", ES_MULTILINE | ES_READONLY | WS_BORDER, statusId);
        resultsList = makeControl(window, WC_LISTVIEWW, L"", LVS_REPORT | LVS_SINGLESEL | WS_BORDER | WS_TABSTOP, resultsId);
        ListView_SetExtendedListViewStyle(resultsList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        const std::array<const wchar_t*, 7> titles{L"Check", L"Outcome", L"Checked", L"Leads", L"Skipped", L"Denied", L"Errors"};
        const std::array<int, 7> widths{190, 205, 80, 70, 80, 80, 80};
        for (int i = 0; i < static_cast<int>(titles.size()); ++i) {
            LVCOLUMNW column{}; column.mask = LVCF_TEXT | LVCF_WIDTH; column.cx = widths[static_cast<size_t>(i)];
            column.pszText = const_cast<wchar_t*>(titles[static_cast<size_t>(i)]);
            ListView_InsertColumn(resultsList, i, &column);
        }
        layout(window); applyScope(); SetTimer(window, 1, 250, nullptr);
        return 0;
    }
    case WM_SIZE: layout(window); return 0;
    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(l); info->ptMinTrackSize = {970, 650}; return 0;
    }
    case WM_COMMAND:
        if (LOWORD(w) == modeId && HIWORD(w) == CBN_SELCHANGE && finished.load()) applyScope();
        if (LOWORD(w) == browseId && finished.load()) browse(window);
        if (LOWORD(w) == startId) start(window);
        if (LOWORD(w) == cancelId) { cancelled = true; refresh(window); }
        if (LOWORD(w) == reportId) showReport(window, false);
        if (LOWORD(w) == reviewId) showReport(window, true);
        return 0;
    case WM_TIMER: refresh(window); return 0;
    case WM_CLOSE:
        if (!finished.load()) { closing = true; cancelled = true; refresh(window); }
        else DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        KillTimer(window, 1); cancelled = true;
        if (worker.joinable()) worker.join();
        PostQuitMessage(0); return 0;
    default: return DefWindowProcW(window, message, w, l);
    }
}
LRESULT CALLBACK windowProc(HWND window, UINT message, WPARAM w, LPARAM l) {
    try { return dispatch(window, message, w, l); }
    catch (...) {
        cancelled = true;
        KillTimer(window, 1);
        MessageBoxW(window, L"The interface encountered an error. Cancellation has been requested; no evidence was sent to AI.",
            L"XA Spy", MB_OK | MB_ICONERROR);
        return 0;
    }
}

bool publicWrite(const std::string& value) {
    const auto output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!output || output == INVALID_HANDLE_VALUE) return true;
    const auto text = value + "\n";
    DWORD written = 0;
    return WriteFile(output, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) && written == text.size();
}
BOOL WINAPI consoleSignal(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        cancelled = true; return TRUE;
    }
    return FALSE;
}
int commandLine(int count, wchar_t** args) {
    xa::Options options; options.application = application;
    std::string action, runId;
    bool modeSpecified = false, browserSpecified = false;
    auto invalid = [] { publicWrite("{\"event\":\"invalid_arguments\",\"exit_code\":1}"); return 1; };
    for (int index = 1; index < count; ++index) {
        const std::wstring arg(args[index]);
        if (arg == L"--scan") {
            if (!action.empty()) return invalid();
            action = "scan";
        } else if (arg == L"--status" || arg == L"--summary" || arg == L"--cancel") {
            if (!action.empty() || index + 1 >= count) return invalid();
            action = xa::toUtf8(arg.substr(2)); runId = xa::toUtf8(args[++index]);
        } else if (arg == L"--mode") {
            if (modeSpecified || index + 1 >= count) return invalid();
            const std::wstring mode(args[++index]);
            if (mode != L"system" && mode != L"folder") return invalid();
            options.mode = mode == L"system" ? xa::Mode::system : xa::Mode::folder;
            modeSpecified = true;
        } else if (arg == L"--target") {
            if (!options.target.empty() || index + 1 >= count) return invalid();
            options.target = args[++index];
            if (options.target.empty()) return invalid();
        } else if (arg == L"--fixture") {
            if (!options.fixtureRoot.empty() || index + 1 >= count) return invalid();
            options.fixtureRoot = args[++index];
            if (options.fixtureRoot.empty()) return invalid();
        } else if (arg == L"--security-settings") {
            if (options.securitySettings) return invalid();
            options.securitySettings = true;
        } else if (arg == L"--browser" || arg == L"--browser-references") {
            if (browserSpecified) return invalid();
            browserSpecified = true; options.browserReferences = true;
        } else return invalid();
    }
    if (action == "scan") {
        if ((options.securitySettings && options.mode != xa::Mode::system) || !modeSpecified || (options.mode == xa::Mode::folder && options.target.empty()) ||
            (options.mode == xa::Mode::system && !options.target.empty())) return invalid();
        if (!options.fixtureRoot.empty() && (!xa::safeLocalPath(options.fixtureRoot) ||
            !xa::fs::is_directory(options.fixtureRoot))) return invalid();
        SetConsoleCtrlHandler(consoleSignal, TRUE);
        xa::Progress result;
        xa::scan(options, cancelled, [&](const xa::Progress& p) {
            result = p;
            if (!publicWrite(xa::filteredJson(p))) cancelled = true;
        });
        SetConsoleCtrlHandler(consoleSignal, FALSE);
        if (result.state != xa::State::completed) return 1;
        return result.hashes || result.references ? 2 : 3;
    }
    if (action.empty() || options.securitySettings || modeSpecified || browserSpecified || !options.target.empty() || !options.fixtureRoot.empty() ||
        !xa::validRunId(runId)) return invalid();
    const auto response = xa::control(application, action, runId);
    if (!publicWrite(response)) return 1;
    return response.find("\"state\":\"failed\"") != std::string::npos ? 1 : 0;
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    bool cli = false;
    try {
        applicationInstance = instance;
        std::vector<wchar_t> path(32768);
        const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (!length || length >= path.size()) return 1;
        application = xa::fs::path(path.data()).parent_path();
        int count = 0;
        auto args = CommandLineToArgvW(GetCommandLineW(), &count);
        if (!args) return 1;
        if (count == 3 && std::wstring(args[1]) == L"--fixture-ui") {
            cli = true; // Invalid fixture setup must fail without a blocking modal dialog.
            fixtureRoot = args[2]; LocalFree(args);
            if (fixtureRoot.empty() || !xa::safeLocalPath(fixtureRoot) || !xa::fs::is_directory(fixtureRoot)) return 1;
            cli = false;
        } else if (count > 1) {
            cli = true;
            int result = 1;
            try { result = commandLine(count, args); }
            catch (...) { publicWrite("{\"event\":\"failed\",\"exit_code\":1}"); }
            LocalFree(args); return result;
        } else LocalFree(args);
        const auto com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(com)) return 1;
        INITCOMMONCONTROLSEX common{sizeof common, ICC_LISTVIEW_CLASSES}; InitCommonControlsEx(&common);
        bigIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_XASPY), IMAGE_ICON,
            GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_SHARED));
        smallIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_XASPY), IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED));
        WNDCLASSW klass{}; klass.lpfnWndProc = windowProc; klass.hInstance = instance;
        klass.hIcon = bigIcon; klass.lpszClassName = L"XASpyNative";
        klass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        klass.hbrBackground = xa::ui::background();
        if (!RegisterClassW(&klass)) { CoUninitialize(); return 1; }
        auto reportClass = klass; reportClass.lpfnWndProc = reportProc; reportClass.lpszClassName = L"XASpyLocalReport";
        if (!RegisterClassW(&reportClass)) { CoUninitialize(); return 1; }
        const auto window = CreateWindowExW(0, klass.lpszClassName, fixtureMode() ? L"XA Spy — Synthetic Fixture" : L"XA Spy",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1040, 800, nullptr, nullptr, instance, nullptr);
        if (!window) { CoUninitialize(); return 1; }
        setIcons(window); ShowWindow(window, show); UpdateWindow(window);
        MSG message{};
        BOOL status;
        while ((status = GetMessageW(&message, nullptr, 0, 0)) > 0) {
            if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
        }
        CoUninitialize(); return status == -1 ? 1 : static_cast<int>(message.wParam);
    } catch (...) {
        if (cli) publicWrite("{\"event\":\"failed\",\"exit_code\":1}");
        else MessageBoxW(nullptr, L"XA Spy could not start. No detailed evidence was sent to AI.", L"XA Spy", MB_OK | MB_ICONERROR);
        return 1;
    }
}
