// Read-only, local Windows metadata collectors. Command values are briefly read
// to extract executable paths; arguments are not retained. No child processes,
// endpoint probes, rendered message bodies, credential extraction or remediation.
#include "audit.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <taskschd.h>
#include <wbemidl.h>
#include <netfw.h>
#include <winevt.h>
#include <wrl/client.h>
#include <algorithm>
#include <array>
#include <cwctype>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace xa {
namespace {
using Microsoft::WRL::ComPtr;
constexpr size_t maxRecords = 10000;
constexpr DWORD maxBuffer = 4 * 1024 * 1024;
struct KernelHandle {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit KernelHandle(HANDLE value) : h(value) {}
    ~KernelHandle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
struct ServiceHandle {
    SC_HANDLE h = nullptr;
    explicit ServiceHandle(SC_HANDLE value) : h(value) {}
    ~ServiceHandle() { if (h) CloseServiceHandle(h); }
};
struct RegistryHandle {
    HKEY h = nullptr;
    ~RegistryHandle() { if (h) RegCloseKey(h); }
};
struct EventHandle {
    EVT_HANDLE h = nullptr;
    explicit EventHandle(EVT_HANDLE value) : h(value) {}
    ~EventHandle() { if (h) EvtClose(h); }
};
struct ComInit {
    HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ~ComInit() { if (SUCCEEDED(result)) CoUninitialize(); }
    bool okay() const { return SUCCEEDED(result) || result == RPC_E_CHANGED_MODE; }
};
struct Bstr {
    BSTR value = nullptr;
    explicit Bstr(const wchar_t* text = nullptr) : value(text ? SysAllocString(text) : nullptr) {}
    ~Bstr() { SysFreeString(value); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
};
struct Context {
    Collection out;
    std::atomic_bool& cancel;
    const Pulse& pulse;
    size_t visited = 0;
    bool step() {
        pulse();
        if (cancel.load()) return false;
        if (++visited > maxRecords) { ++out.skipped; return false; }
        return true;
    }
    void error(DWORD code) {
        if (code == ERROR_ACCESS_DENIED || code == ERROR_PRIVILEGE_NOT_HELD ||
            code == static_cast<DWORD>(E_ACCESSDENIED) || code == static_cast<DWORD>(WBEM_E_ACCESS_DENIED)) ++out.denied;
        else ++out.errors;
    }
    void add(Record record) {
        for (std::string* text : {&record.name, &record.detail, &record.address}) {
            if (text->size() > 4096) {
                size_t end = 4096;
                while (end && (static_cast<unsigned char>((*text)[end]) & 0xc0) == 0x80) --end;
                text->resize(end); ++out.skipped;
            }
        }
        if (out.records.size() < maxRecords) out.records.push_back(std::move(record)); else ++out.skipped;
    }
    Collection finish() {
        if (cancel.load()) out.outcome = Outcome::cancelled;
        else if (out.outcome == Outcome::unsupported && out.records.empty() && !out.denied && !out.errors) {}
        else if (out.denied || out.errors || out.skipped) {
            if (!out.records.empty()) out.outcome = Outcome::partial;
            else if (out.denied && !out.errors && !out.skipped) out.outcome = Outcome::access_denied;
            else if (out.errors && !out.denied && !out.skipped) out.outcome = Outcome::failed;
            else out.outcome = Outcome::partial;
        }
        return std::move(out);
    }
};
std::wstring regText(HKEY key, const wchar_t* name, Context* context);
std::wstring lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return value;
}
std::wstring trim(std::wstring value) {
    const auto begin = value.find_first_not_of(L" \t\r\n");
    if (begin == std::wstring::npos) return {};
    return value.substr(begin, value.find_last_not_of(L" \t\r\n") - begin + 1);
}
std::wstring expanded(const std::wstring& value) {
    DWORD size = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (!size || size > 32768) return {};
    std::vector<wchar_t> text(size);
    if (ExpandEnvironmentStringsW(value.c_str(), text.data(), size) != size) return {};
    return text.data();
}
// Extract a local executable spelling only. Never retain/execute its arguments.
fs::path executablePath(std::wstring value) {
    value = trim(expanded(value));
    if (value.empty()) return {};
    if (value.front() == L'"') {
        const auto end = value.find(L'"', 1);
        if (end == std::wstring::npos) return {};
        value = value.substr(1, end - 1);
    } else {
        const auto folded = lower(value);
        size_t ending = std::wstring::npos;
        for (const auto* extension : {L".exe", L".sys", L".dll", L".com", L".scr", L".bat", L".cmd", L".ps1", L".vbs"}) {
            size_t position = 0;
            const std::wstring ext(extension);
            while ((position = folded.find(ext, position)) != std::wstring::npos) {
                const auto end = position + ext.size();
                if (end == folded.size() || std::iswspace(folded[end]) || folded[end] == L',') { ending = std::min(ending, end); break; }
                ++position;
            }
        }
        if (ending == std::wstring::npos) return {};
        value.resize(ending);
    }
    if (value.starts_with(L"\\??\\")) value.erase(0, 4);
    if (lower(value).starts_with(L"\\systemroot\\") || lower(value).starts_with(L"system32\\")) {
        std::array<wchar_t, MAX_PATH> system{};
        const auto length = GetWindowsDirectoryW(system.data(), static_cast<UINT>(system.size()));
        if (!length || length >= system.size()) return {};
        value = std::wstring(system.data()) + L"\\" + (value.front() == L'\\' ? value.substr(12) : value);
    }
    fs::path result(value);
    return result.is_absolute() && !value.starts_with(L"\\\\") ? result : fs::path{};
}
std::string number(DWORD value) { return std::to_string(value); }
std::string processPath(DWORD pid, fs::path& path) {
    KernelHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.h || process.h == INVALID_HANDLE_VALUE) return {};
    std::array<wchar_t, 32768> text{};
    DWORD size = static_cast<DWORD>(text.size());
    if (!QueryFullProcessImageNameW(process.h, 0, text.data(), &size)) return {};
    path = std::wstring(text.data(), size);
    return toUtf8(path.filename().wstring());
}
void processes(Context& context) {
    KernelHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.h == INVALID_HANDLE_VALUE) { context.error(GetLastError()); return; }
    PROCESSENTRY32W item{}; item.dwSize = sizeof(item);
    if (!Process32FirstW(snapshot.h, &item)) { context.error(GetLastError()); return; }
    do {
        if (!context.step()) break;
        Record record; record.name = toUtf8(item.szExeFile); record.pid = item.th32ProcessID;
        record.detail = "parent_pid=" + number(item.th32ParentProcessID) + "; threads=" + number(item.cntThreads);
        KernelHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, item.th32ProcessID));
        if (process.h) {
            std::array<wchar_t, 32768> path{}; DWORD size = static_cast<DWORD>(path.size());
            if (QueryFullProcessImageNameW(process.h, 0, path.data(), &size)) record.executable = std::wstring(path.data(), size);
            else context.error(GetLastError());
        } else if (item.th32ProcessID != 0) context.error(GetLastError());
        context.add(std::move(record));
    } while (Process32NextW(snapshot.h, &item));
    if (!context.cancel.load() && GetLastError() != ERROR_NO_MORE_FILES && context.visited <= maxRecords) context.error(GetLastError());
    context.out.limitation = "Snapshot only; protected/terminated process paths may be unavailable. No process memory or command line is read.";
}
void services(Context& context, bool drivers) {
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT));
    if (!manager.h) { context.error(GetLastError()); return; }
    DWORD resume = 0;
    std::vector<BYTE> buffer(256 * 1024);
    for (unsigned page = 0; page < 100 && !context.cancel.load(); ++page) {
        DWORD needed = 0, returned = 0;
        const BOOL okay = EnumServicesStatusExW(manager.h, SC_ENUM_PROCESS_INFO,
            drivers ? SERVICE_DRIVER : SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(), static_cast<DWORD>(buffer.size()),
            &needed, &returned, &resume, nullptr);
        const DWORD error = okay ? ERROR_SUCCESS : GetLastError();
        if (!okay && error != ERROR_MORE_DATA) { context.error(error); break; }
        auto rows = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD index = 0; index < returned; ++index) {
            if (!context.step()) return;
            const auto& row = rows[index];
            Record record; record.name = toUtf8(row.lpServiceName); record.pid = row.ServiceStatusProcess.dwProcessId;
            record.detail = "state=" + number(row.ServiceStatusProcess.dwCurrentState) + "; type=" + number(row.ServiceStatusProcess.dwServiceType);
            ServiceHandle service(OpenServiceW(manager.h, row.lpServiceName, SERVICE_QUERY_CONFIG));
            if (!service.h) context.error(GetLastError());
            else {
                DWORD size = 0;
                QueryServiceConfigW(service.h, nullptr, 0, &size);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && size <= maxBuffer) {
                    std::vector<BYTE> config(size);
                    auto* data = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
                    if (QueryServiceConfigW(service.h, data, size, &size)) {
                        record.executable = executablePath(data->lpBinaryPathName ? data->lpBinaryPathName : L"");
                        record.detail += "; start_type=" + number(data->dwStartType);
                        if (record.executable.empty()) ++context.out.skipped;
                    } else context.error(GetLastError());
                } else context.error(GetLastError());
            }
            context.add(std::move(record));
            if (!drivers) {
                RegistryHandle parameters;
                const auto branch = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + row.lpServiceName + L"\\Parameters";
                const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, branch.c_str(), 0, KEY_QUERY_VALUE, &parameters.h);
                if (opened == ERROR_SUCCESS) {
                    const auto dll = regText(parameters.h, L"ServiceDll", &context);
                    if (!dll.empty()) {
                        Record serviceDll; serviceDll.name = toUtf8(row.lpServiceName);
                        serviceDll.detail = "registered_service_dll"; serviceDll.pid = row.ServiceStatusProcess.dwProcessId;
                        serviceDll.executable = executablePath(dll);
                        if (serviceDll.executable.empty()) ++context.out.skipped;
                        context.add(std::move(serviceDll));
                    }
                } else if (opened != ERROR_FILE_NOT_FOUND) context.error(opened);
            }
        }
        if (okay) break;
        if (!returned) { ++context.out.errors; break; }
        if (page == 99) ++context.out.skipped;
    }
    context.out.limitation = drivers ? "Registered kernel/filesystem drivers; registration/state does not prove firmware or driver integrity." :
        "Service registration and process state only. Arguments, accounts and credentials are not collected.";
}
std::wstring regText(HKEY key, const wchar_t* name, Context* context = nullptr) {
    DWORD type = 0, length = 0;
    LONG status = RegQueryValueExW(key, name, nullptr, &type, nullptr, &length);
    if (status == ERROR_FILE_NOT_FOUND) return {};
    if (status != ERROR_SUCCESS) { if (context) context->error(status); return {}; }
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || length > 65536 || length % sizeof(wchar_t)) {
        if (context) ++context->out.skipped;
        return {};
    }
    std::vector<wchar_t> buffer(length / sizeof(wchar_t) + 1, L'\0');
    status = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(buffer.data()), &length);
    if (status != ERROR_SUCCESS) { if (context) context->error(status); return {}; }
    return buffer.data();
}
void startupRegistry(Context& context) {
    for (HKEY hive : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        for (const auto* branch : {L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                                  L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"}) {
            if (context.cancel.load()) return;
            RegistryHandle key;
            const auto opened = RegOpenKeyExW(hive, branch, 0, KEY_QUERY_VALUE | view, &key.h);
            if (opened == ERROR_FILE_NOT_FOUND) continue;
            if (opened != ERROR_SUCCESS) { context.error(opened); continue; }
            for (DWORD index = 0; ; ++index) {
                if (!context.step()) return;
                std::array<wchar_t, 16384> name{};
                DWORD size = static_cast<DWORD>(name.size()), type = 0;
                LONG status = RegEnumValueW(key.h, index, name.data(), &size, nullptr, &type, nullptr, nullptr);
                if (status == ERROR_NO_MORE_ITEMS) break;
                if (status != ERROR_SUCCESS) { context.error(status); continue; }
                Record record; record.name = toUtf8(std::wstring(name.data(), size));
                record.detail = (hive == HKEY_CURRENT_USER ? "HKCU; " : "HKLM; ") + toUtf8(branch) + (view == KEY_WOW64_64KEY ? "; view=64" : "; view=32");
                record.executable = executablePath(regText(key.h, name.data(), &context));
                if (record.executable.empty()) ++context.out.skipped;
                context.add(std::move(record));
            }
        }
    }
    context.out.limitation = "Run, RunOnce and Explorer policy startup registrations in both registry views; command arguments omitted. Other persistence mechanisms remain outside this check.";
}
template<class Iterator, class Visit>
void directoryEntries(Iterator iterator, const Iterator& end, Context& context, Visit visit) {
    while (iterator != end) {
        if (!context.step()) return;
        visit(*iterator);
        if (context.cancel.load()) return;
        std::error_code error;
        iterator.increment(error);
        // A failed increment can already have changed iterator to end.
        if (error) { context.error(error.value()); return; }
    }
}
void startupFolders(Context& context) {
    ComInit com;
    for (const KNOWNFOLDERID* id : {&FOLDERID_Startup, &FOLDERID_CommonStartup}) {
        PWSTR raw = nullptr;
        const auto hr = SHGetKnownFolderPath(*id, KF_FLAG_DONT_VERIFY, nullptr, &raw);
        if (FAILED(hr)) { context.error(static_cast<DWORD>(hr)); continue; }
        fs::path root(raw); CoTaskMemFree(raw);
        if (!safeLocalPath(root)) { ++context.out.skipped; continue; }
        std::error_code error;
        fs::directory_iterator iterator(root, error), end;
        if (error) { context.error(error.value()); continue; }
        directoryEntries(std::move(iterator), end, context, [&](const auto& entry) {
            const auto path = entry.path();
            if (!safeLocalPath(path)) { ++context.out.skipped; return; }
            Record record; record.name = toUtf8(path.filename().wstring());
            record.detail = id == &FOLDERID_Startup ? "current_user_startup" : "common_startup";
            if (lower(path.extension().wstring()) == L".lnk") {
                if (!com.okay()) { context.error(static_cast<DWORD>(com.result)); return; }
                ComPtr<IShellLinkW> link; ComPtr<IPersistFile> persist;
                HRESULT result = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&link));
                if (SUCCEEDED(result)) result = link.As(&persist);
                if (SUCCEEDED(result)) result = persist->Load(path.c_str(), STGM_READ);
                std::array<wchar_t, 32768> target{};
                if (SUCCEEDED(result)) result = link->GetPath(target.data(), static_cast<int>(target.size()), nullptr, SLGP_RAWPATH);
                if (SUCCEEDED(result)) record.executable = executablePath(target.data());
                else context.error(static_cast<DWORD>(result));
                if (record.executable.empty()) ++context.out.skipped;
            } else {
                std::error_code entryError;
                const bool isDirectory = entry.is_directory(entryError);
                if (entryError) context.error(entryError.value());
                else if (!isDirectory) record.executable = executablePath(path.wstring());
                else ++context.out.skipped;
            }
            context.add(std::move(record));
        });
        if (context.cancel.load() || context.visited > maxRecords) return;
    }
    context.out.limitation = "Top-level Startup folder entries. Shortcut targets are read without resolving/launching them; no arguments or URL-file contents are read.";
}
void installedApps(Context& context) {
    constexpr const wchar_t* branch = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    for (HKEY hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        RegistryHandle key;
        const LONG opened = RegOpenKeyExW(hive, branch, 0, KEY_ENUMERATE_SUB_KEYS | view, &key.h);
        if (opened == ERROR_FILE_NOT_FOUND) continue;
        if (opened != ERROR_SUCCESS) { context.error(opened); continue; }
        for (DWORD index = 0; ; ++index) {
            if (!context.step()) return;
            std::array<wchar_t, 256> name{}; DWORD size = static_cast<DWORD>(name.size());
            const LONG status = RegEnumKeyExW(key.h, index, name.data(), &size, nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) { context.error(status); continue; }
            RegistryHandle app;
            const auto read = RegOpenKeyExW(key.h, name.data(), 0, KEY_QUERY_VALUE | view, &app.h);
            if (read != ERROR_SUCCESS) { context.error(read); continue; }
            const auto display = regText(app.h, L"DisplayName", &context);
            if (display.empty()) continue;
            Record record; record.name = toUtf8(display);
            record.detail = "version=" + toUtf8(regText(app.h, L"DisplayVersion", &context)) +
                "; publisher=" + toUtf8(regText(app.h, L"Publisher", &context)) +
                (hive == HKEY_CURRENT_USER ? "; scope=user" : "; scope=machine") + (view == KEY_WOW64_64KEY ? "; view=64" : "; view=32");
            context.add(std::move(record));
        }
    }
    context.out.limitation = "Registered desktop uninstall inventory only; portable applications and Store packages may not appear. No uninstall commands are read or executed.";
}
void scheduledTasks(Context& context) {
    ComInit com;
    if (!com.okay()) { context.error(static_cast<DWORD>(com.result)); return; }
    ComPtr<ITaskService> service;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&service));
    VARIANT empty; VariantInit(&empty);
    if (SUCCEEDED(hr)) hr = service->Connect(empty, empty, empty, empty); // Empty server = local machine.
    ComPtr<ITaskFolder> root;
    Bstr slash(L"\\");
    if (SUCCEEDED(hr)) hr = service->GetFolder(slash.value, &root);
    if (FAILED(hr)) { context.error(static_cast<DWORD>(hr)); return; }
    std::vector<std::pair<ComPtr<ITaskFolder>, unsigned>> pending{{root, 0}};
    while (!pending.empty() && !context.cancel.load()) {
        auto [folder, depth] = pending.back(); pending.pop_back();
        ComPtr<IRegisteredTaskCollection> tasks;
        hr = folder->GetTasks(TASK_ENUM_HIDDEN, &tasks);
        if (FAILED(hr)) context.error(static_cast<DWORD>(hr));
        else {
            LONG count = 0; hr = tasks->get_Count(&count);
            if (FAILED(hr)) context.error(static_cast<DWORD>(hr));
            for (LONG index = 1; index <= count; ++index) {
                if (!context.step()) return;
                VARIANT slot; VariantInit(&slot); slot.vt = VT_I4; slot.lVal = index;
                ComPtr<IRegisteredTask> task;
                if (FAILED(hr = tasks->get_Item(slot, &task))) { context.error(static_cast<DWORD>(hr)); continue; }
                Bstr name; TASK_STATE state = TASK_STATE_UNKNOWN; VARIANT_BOOL enabled = VARIANT_FALSE;
                for (HRESULT status : {task->get_Path(&name.value), task->get_State(&state), task->get_Enabled(&enabled)})
                    if (FAILED(status)) context.error(static_cast<DWORD>(status));
                Record record; record.name = name.value ? toUtf8(name.value) : "unnamed_task";
                record.detail = "state=" + std::to_string(state) + "; enabled=" + (enabled ? "true" : "false");
                ComPtr<ITaskDefinition> definition; ComPtr<IActionCollection> actions;
                hr = task->get_Definition(&definition);
                if (SUCCEEDED(hr)) hr = definition->get_Actions(&actions);
                if (FAILED(hr)) { context.error(static_cast<DWORD>(hr)); context.add(std::move(record)); continue; }
                LONG actionCount = 0;
                if (FAILED(hr = actions->get_Count(&actionCount))) { context.error(static_cast<DWORD>(hr)); context.add(std::move(record)); continue; }
                if (actionCount > 128) { actionCount = 128; ++context.out.skipped; }
                if (actionCount == 0) context.add(record);
                for (LONG actionIndex = 1; actionIndex <= actionCount; ++actionIndex) {
                    if (context.cancel.load()) return;
                    ComPtr<IAction> action; TASK_ACTION_TYPE type = TASK_ACTION_EXEC;
                    hr = actions->get_Item(actionIndex, &action);
                    if (SUCCEEDED(hr)) hr = action->get_Type(&type);
                    if (FAILED(hr)) { context.error(static_cast<DWORD>(hr)); continue; }
                    Record item = record;
                    item.detail += "; action_type=" + std::to_string(type);
                    if (type == TASK_ACTION_EXEC) {
                        ComPtr<IExecAction> exec; Bstr path;
                        hr = action.As(&exec);
                        if (SUCCEEDED(hr)) hr = exec->get_Path(&path.value);
                        if (SUCCEEDED(hr)) item.executable = executablePath(path.value ? path.value : L"");
                        else context.error(static_cast<DWORD>(hr));
                        if (item.executable.empty()) ++context.out.skipped;
                    } else { ++context.out.skipped; item.detail += "; non_executable_action_not_inspected"; }
                    context.add(std::move(item));
                }
            }
        }
        ComPtr<ITaskFolderCollection> folders;
        hr = folder->GetFolders(0, &folders);
        if (FAILED(hr)) { context.error(static_cast<DWORD>(hr)); continue; }
        LONG count = 0;
        if (FAILED(hr = folders->get_Count(&count))) { context.error(static_cast<DWORD>(hr)); continue; }
        if (depth >= 32) { if (count) ++context.out.skipped; continue; }
        for (LONG index = 1; index <= count; ++index) {
            if (!context.step()) return;
            if (pending.size() >= 1000) { ++context.out.skipped; break; }
            VARIANT slot; VariantInit(&slot); slot.vt = VT_I4; slot.lVal = index;
            ComPtr<ITaskFolder> child;
            hr = folders->get_Item(slot, &child);
            if (SUCCEEDED(hr)) pending.emplace_back(child, depth + 1);
            else context.error(static_cast<DWORD>(hr));
        }
    }
    context.out.limitation = "Local task metadata and executable action paths only; no task arguments, scripts, credentials or execution. COM calls may delay cancellation.";
}
std::string variantText(const VARIANT& value) {
    switch (value.vt) {
    case VT_BOOL: return value.boolVal ? "true" : "false";
    case VT_I4: return std::to_string(value.lVal);
    case VT_UI4: return std::to_string(value.ulVal);
    case VT_BSTR: return value.bstrVal ? toUtf8(value.bstrVal) : "unavailable";
    default: return "unavailable";
    }
}
void wmiQuery(Context& context, const wchar_t* nameSpace, const wchar_t* query,
              const std::vector<const wchar_t*>& fields, const char* recordName) {
    ComPtr<IWbemLocator> locator; ComPtr<IWbemServices> services;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator));
    Bstr location(nameSpace), language(L"WQL"), text(query);
    if (SUCCEEDED(hr)) hr = locator->ConnectServer(location.value, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &services);
    if (SUCCEEDED(hr)) hr = CoSetProxyBlanket(services.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    ComPtr<IEnumWbemClassObject> items;
    if (SUCCEEDED(hr)) hr = services->ExecQuery(language.value, text.value, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &items);
    if (FAILED(hr)) {
        if (hr == WBEM_E_INVALID_NAMESPACE || hr == WBEM_E_INVALID_CLASS) { ++context.out.skipped; context.out.outcome = Outcome::unsupported; }
        else context.error(static_cast<DWORD>(hr));
        return;
    }
    unsigned timeouts = 0;
    while (context.step()) {
        ComPtr<IWbemClassObject> item; ULONG received = 0;
        hr = items->Next(500, 1, &item, &received);
        if (FAILED(hr)) { context.error(static_cast<DWORD>(hr)); break; }
        if (!received) {
            if (hr == WBEM_S_TIMEDOUT && ++timeouts < 20) continue;
            if (hr == WBEM_S_TIMEDOUT) ++context.out.skipped;
            break;
        }
        Record record; record.name = recordName;
        for (const auto* field : fields) {
            VARIANT value; VariantInit(&value);
            const auto result = item->Get(field, 0, &value, nullptr, nullptr);
            if (FAILED(result)) context.error(static_cast<DWORD>(result));
            else record.detail += toUtf8(field) + "=" + variantText(value) + "; ";
            VariantClear(&value);
        }
        context.add(std::move(record));
    }
}
void security(Context& context) {
    ComInit com;
    if (!com.okay()) { context.error(static_cast<DWORD>(com.result)); return; }
    wmiQuery(context, L"ROOT\\Microsoft\\Windows\\Defender",
        L"SELECT AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureAge FROM MSFT_MpComputerStatus",
        {L"AMServiceEnabled", L"AntivirusEnabled", L"RealTimeProtectionEnabled", L"BehaviorMonitorEnabled", L"AntivirusSignatureAge"}, "defender_status");
    if (!context.cancel.load()) wmiQuery(context, L"ROOT\\SecurityCenter2",
        L"SELECT displayName,productState FROM AntiVirusProduct", {L"displayName", L"productState"}, "registered_antivirus");
    context.out.limitation = "Local provider-reported security status, not a malware scan. SecurityCenter2 may be absent on Windows Server. No settings changed; WMI connection may delay cancellation.";
}
void securitySettings(Context& context) {
    auto registryFlag = [&](const wchar_t* key, const wchar_t* value, const char* name,
                            const char* zero, const char* one) {
        DWORD data = 0, size = sizeof(data);
        const auto status = RegGetValueW(HKEY_LOCAL_MACHINE, key, value,
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &data, &size);
        std::string detail = "Unavailable";
        if (status == ERROR_SUCCESS && data <= 1) detail = data ? one : zero;
        else if (status == ERROR_ACCESS_DENIED) ++context.out.denied;
        else ++context.out.skipped;
        context.add({name, detail});
    };
    registryFlag(L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections",
        "Remote Desktop host setting", "Enabled; confirm that remote access is intended.", "Disabled");
    registryFlag(L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled",
        "UEFI Secure Boot", "Disabled; review firmware configuration.", "Enabled");
    if (context.cancel.load()) return;
    ComInit com;
    if (!com.okay()) { context.error(static_cast<DWORD>(com.result)); return; }
    ComPtr<INetFwPolicy2> firewall;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&firewall));
    if (FAILED(hr)) context.error(static_cast<DWORD>(hr));
    else {
        struct Profile { NET_FW_PROFILE_TYPE2 type; const char* name; };
        for (const Profile profile : {Profile{NET_FW_PROFILE2_DOMAIN, "Domain firewall"},
                Profile{NET_FW_PROFILE2_PRIVATE, "Private firewall"}, Profile{NET_FW_PROFILE2_PUBLIC, "Public firewall"}}) {
            VARIANT_BOOL enabled = VARIANT_FALSE;
            hr = firewall->get_FirewallEnabled(profile.type, &enabled);
            if (FAILED(hr)) context.error(static_cast<DWORD>(hr));
            context.add({profile.name, FAILED(hr) ? "Unavailable" : enabled ?
                "Enabled" : "Disabled; review the policy for this network profile."});
        }
    }
    if (context.cancel.load()) return;
    const auto before = context.out.records.size();
    wmiQuery(context, L"ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption",
        L"SELECT DriveLetter,ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter IS NOT NULL",
        {L"DriveLetter", L"ProtectionStatus"}, "BitLocker");
    if (context.out.records.size() == before) {
        ++context.out.skipped;
        context.add({"BitLocker", "No readable drive protection status."});
    }
    for (size_t i = before; i < context.out.records.size(); ++i) {
        auto& detail = context.out.records[i].detail;
        if (detail.find("ProtectionStatus=1;") != std::string::npos) detail += "Protection on.";
        else if (detail.find("ProtectionStatus=0;") != std::string::npos)
            detail += "Protection off; check whether encryption is suspended or disabled.";
        else if (detail.find("ProtectionStatus=") != std::string::npos) {
            ++context.out.skipped;
            detail += "Protection unknown.";
        }
    }
    context.out.limitation = "Read-only configuration snapshot. Firewall profiles may be inactive. Remote Desktop configuration does not establish reachability.";
}
void eventLogs(Context& context) {
    struct Source { const wchar_t* channel; const wchar_t* expression; };
    constexpr Source sources[] = {
        {L"System", L"*[System[(EventID=7045 or EventID=7040) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"},
        {L"Microsoft-Windows-Windows Defender/Operational", L"*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"},
        {L"Microsoft-Windows-PowerShell/Operational", L"*[System[(EventID=4103 or EventID=4104) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"},
        {L"Security", L"*[System[(EventID=4688 or EventID=4697 or EventID=4698) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"},
        {L"Microsoft-Windows-CodeIntegrity/Operational", L"*[System[(EventID=3033 or EventID=3077) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"},
    };
    EventHandle render(EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem));
    if (!render.h) { context.error(GetLastError()); return; }
    for (const auto& source : sources) {
        if (context.cancel.load()) return;
        EventHandle query(EvtQuery(nullptr, source.channel, source.expression, EvtQueryChannelPath | EvtQueryReverseDirection));
        if (!query.h) {
            const auto error = GetLastError();
            if (error == ERROR_EVT_CHANNEL_NOT_FOUND) ++context.out.skipped;
            else context.error(error);
            continue;
        }
        unsigned count = 0;
        while (count < 1000 && context.step()) {
            EVT_HANDLE raw = nullptr; DWORD received = 0;
            if (!EvtNext(query.h, 1, &raw, 500, 0, &received)) {
                const auto error = GetLastError();
                if (error != ERROR_NO_MORE_ITEMS) context.error(error);
                break;
            }
            EventHandle event(raw); ++count;
            DWORD needed = 0, properties = 0;
            EvtRender(render.h, event.h, EvtRenderEventValues, 0, nullptr, &needed, &properties);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed > maxBuffer) { context.error(GetLastError()); continue; }
            std::vector<BYTE> buffer(needed);
            if (!EvtRender(render.h, event.h, EvtRenderEventValues, needed, buffer.data(), &needed, &properties)) { context.error(GetLastError()); continue; }
            if (properties <= EvtSystemEventID) { ++context.out.errors; continue; }
            auto values = reinterpret_cast<EVT_VARIANT*>(buffer.data());
            Record record; record.name = toUtf8(source.channel);
            record.detail = "event_id=" + std::to_string(values[EvtSystemEventID].UInt16Val);
            if (properties > EvtSystemProviderName && values[EvtSystemProviderName].Type == EvtVarTypeString && values[EvtSystemProviderName].StringVal)
                record.detail += "; provider=" + toUtf8(values[EvtSystemProviderName].StringVal);
            if (properties > EvtSystemTimeCreated && values[EvtSystemTimeCreated].Type == EvtVarTypeFileTime)
                record.detail += "; filetime=" + std::to_string(values[EvtSystemTimeCreated].FileTimeVal);
            context.add(std::move(record));
        }
        if (count == 1000) ++context.out.skipped;
    }
    context.out.limitation = "Last seven days, at most 1000 selected events per channel. System fields only; message/script/command data is never rendered. Log presence is not proof of compromise.";
}
template<class Table, class Row, class Fetch, class Render>
void connectionTable(Context& context, Fetch fetch, Render render) {
    DWORD length = 0;
    DWORD code = fetch(nullptr, &length);
    if (code != ERROR_INSUFFICIENT_BUFFER && code != NO_ERROR) { context.error(code); return; }
    for (unsigned attempt = 0; attempt < 3 && !context.cancel.load(); ++attempt) {
        if (length > maxBuffer || length < sizeof(DWORD)) { ++context.out.skipped; return; }
        std::vector<BYTE> buffer(length);
        code = fetch(buffer.data(), &length);
        if (code == ERROR_INSUFFICIENT_BUFFER) continue;
        if (code != NO_ERROR) { context.error(code); return; }
        const auto* table = reinterpret_cast<const Table*>(buffer.data());
        const size_t capacity = (buffer.size() - offsetof(Table, table)) / sizeof(Row);
        if (table->dwNumEntries > capacity) { ++context.out.errors; return; }
        for (DWORD index = 0; index < table->dwNumEntries; ++index) {
            if (!context.step()) return;
            auto record = render(table->table[index]);
            processPath(record.pid, record.executable);
            context.add(std::move(record));
        }
        return;
    }
    ++context.out.skipped;
}
std::string ip4(DWORD value) {
    IN_ADDR address{}; address.S_un.S_addr = value;
    std::array<char, INET_ADDRSTRLEN> text{};
    return InetNtopA(AF_INET, &address, text.data(), static_cast<DWORD>(text.size())) ? text.data() : "unavailable";
}
std::string ip6(const UCHAR* value) {
    IN6_ADDR address{}; std::copy_n(value, 16, address.u.Byte);
    std::array<char, INET6_ADDRSTRLEN> text{};
    return InetNtopA(AF_INET6, &address, text.data(), static_cast<DWORD>(text.size())) ? text.data() : "unavailable";
}
Record connectionRecord(DWORD pid, const char* protocol, const std::string& local, DWORD localPort,
                        const std::string& remote = {}, DWORD remotePort = 0, DWORD state = 0) {
    Record record; record.pid = pid; record.name = protocol; record.address = remote;
    record.detail = "local=" + local + "; local_port=" + number(ntohs(static_cast<u_short>(localPort))) +
        "; remote_port=" + number(ntohs(static_cast<u_short>(remotePort))) + "; state=" + number(state);
    return record;
}
void connections(Context& context) {
    connectionTable<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(context,
        [](void* data, DWORD* size) { return GetExtendedTcpTable(data, size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); },
        [](const MIB_TCPROW_OWNER_PID& row) { return connectionRecord(row.dwOwningPid, "tcp4", ip4(row.dwLocalAddr), row.dwLocalPort, ip4(row.dwRemoteAddr), row.dwRemotePort, row.dwState); });
    connectionTable<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(context,
        [](void* data, DWORD* size) { return GetExtendedTcpTable(data, size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0); },
        [](const MIB_TCP6ROW_OWNER_PID& row) { return connectionRecord(row.dwOwningPid, "tcp6", ip6(row.ucLocalAddr), row.dwLocalPort, ip6(row.ucRemoteAddr), row.dwRemotePort, row.dwState); });
    connectionTable<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(context,
        [](void* data, DWORD* size) { return GetExtendedUdpTable(data, size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0); },
        [](const MIB_UDPROW_OWNER_PID& row) { return connectionRecord(row.dwOwningPid, "udp4", ip4(row.dwLocalAddr), row.dwLocalPort); });
    connectionTable<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(context,
        [](void* data, DWORD* size) { return GetExtendedUdpTable(data, size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0); },
        [](const MIB_UDP6ROW_OWNER_PID& row) { return connectionRecord(row.dwOwningPid, "udp6", ip6(row.ucLocalAddr), row.dwLocalPort); });
    context.out.limitation = "Current TCP connections/listeners and UDP bindings with owning PID; process paths are best effort. UDP tables have no remote peer. Addresses are formatted numerically, never resolved or contacted.";
}
std::wstring deviceProperty(HDEVINFO devices, SP_DEVINFO_DATA& device, DWORD property, Context& context) {
    DWORD type = 0, needed = 0;
    SetupDiGetDeviceRegistryPropertyW(devices, &device, property, &type, nullptr, 0, &needed);
    if (!needed) {
        const auto error = GetLastError();
        if (error != ERROR_INVALID_DATA && error != ERROR_NOT_FOUND) context.error(error);
        return {};
    }
    if (needed > 65536) { ++context.out.skipped; return {}; }
    std::vector<wchar_t> buffer(needed / sizeof(wchar_t) + 1, L'\0');
    if (!SetupDiGetDeviceRegistryPropertyW(devices, &device, property, &type, reinterpret_cast<BYTE*>(buffer.data()), needed, nullptr)) { context.error(GetLastError()); return {}; }
    if (type != REG_SZ && type != REG_EXPAND_SZ) { ++context.out.skipped; return {}; }
    return buffer.data();
}
void devices(Context& context) {
    HDEVINFO list = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (list == INVALID_HANDLE_VALUE) { context.error(GetLastError()); return; }
    struct Cleanup { HDEVINFO value; ~Cleanup() { SetupDiDestroyDeviceInfoList(value); } } cleanup{list};
    for (DWORD index = 0; ; ++index) {
        if (!context.step()) return;
        SP_DEVINFO_DATA device{}; device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(list, index, &device)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) context.error(GetLastError());
            break;
        }
        Record record;
        auto name = deviceProperty(list, device, SPDRP_FRIENDLYNAME, context);
        if (name.empty()) name = deviceProperty(list, device, SPDRP_DEVICEDESC, context);
        record.name = name.empty() ? "unnamed_device" : toUtf8(name);
        record.detail = "class=" + toUtf8(deviceProperty(list, device, SPDRP_CLASS, context)) +
            "; manufacturer=" + toUtf8(deviceProperty(list, device, SPDRP_MFG, context));
        ULONG status = 0, problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, device.DevInst, 0) == CR_SUCCESS)
            record.detail += "; status=" + std::to_string(status) + "; problem=" + std::to_string(problem);
        else ++context.out.skipped;
        const auto driver = deviceProperty(list, device, SPDRP_DRIVER, context);
        if (!driver.empty() && driver.find(L"..") == std::wstring::npos && driver.front() != L'\\') {
            RegistryHandle key;
            const auto branch = std::wstring(L"SYSTEM\\CurrentControlSet\\Control\\Class\\") + driver;
            const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, branch.c_str(), 0, KEY_QUERY_VALUE, &key.h);
            if (opened == ERROR_SUCCESS) record.detail += "; driver_provider=" + toUtf8(regText(key.h, L"ProviderName", &context)) +
                "; driver_version=" + toUtf8(regText(key.h, L"DriverVersion", &context)) + "; inf=" + toUtf8(regText(key.h, L"InfPath", &context));
            else context.error(opened);
        }
        const auto service = deviceProperty(list, device, SPDRP_SERVICE, context);
        if (!service.empty() && service.find_first_of(L"\\/") == std::wstring::npos) {
            RegistryHandle key;
            const auto branch = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + service;
            const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, branch.c_str(), 0, KEY_QUERY_VALUE, &key.h);
            if (opened == ERROR_SUCCESS)
                record.executable = executablePath(regText(key.h, L"ImagePath", &context));
            else if (opened != ERROR_FILE_NOT_FOUND) context.error(opened);
        }
        context.add(std::move(record));
    }
    context.out.limitation = "Present Plug and Play devices and registered driver metadata only. No serial/instance identifiers, device contents, phone acquisition or firmware integrity assessment.";
}
} // namespace

Collection collectWindows(CheckId id, std::atomic_bool& cancel, const Pulse& pulse) {
    Context context{{}, cancel, pulse};
    if (cancel.load()) { context.out.outcome = Outcome::cancelled; return context.finish(); }
    try {
        switch (id) {
        case CheckId::processes: processes(context); break;
        case CheckId::services: services(context, false); break;
        case CheckId::drivers: services(context, true); break;
        case CheckId::startup_registry: startupRegistry(context); break;
        case CheckId::startup_folders: startupFolders(context); break;
        case CheckId::scheduled_tasks: scheduledTasks(context); break;
        case CheckId::installed_apps: installedApps(context); break;
        case CheckId::security: security(context); break;
        case CheckId::settings: securitySettings(context); break;
        case CheckId::event_logs: eventLogs(context); break;
        case CheckId::connections: connections(context); break;
        case CheckId::devices: devices(context); break;
        default: context.out.outcome = Outcome::unsupported; context.out.limitation = "Not a Windows metadata collector."; break;
        }
    } catch (...) { ++context.out.errors; }
    return context.finish();
}

#ifdef XA_SPY_TESTING
// Pure transformation/state fixtures. Never invoke collectWindows or any live
// enumeration API. The parent test target must define XA_SPY_TESTING explicitly.
int collectorFixtureChecks() {
    int passed = 0;
    auto check = [&](bool condition) { if (!condition) throw std::runtime_error("collector fixture failed"); ++passed; };
    check(executablePath(L"\"C:\\Program Files\\Fixture\\safe.exe\" --password SECRET") == fs::path(L"C:\\Program Files\\Fixture\\safe.exe"));
    check(executablePath(L"C:\\Program Files\\Fixture\\safe.exe --token SECRET") == fs::path(L"C:\\Program Files\\Fixture\\safe.exe"));
    check(executablePath(L"C:\\folder.exe\\safe.sys arg") == fs::path(L"C:\\folder.exe\\safe.sys"));
    check(executablePath(L"\\??\\C:\\safe.sys arg") == fs::path(L"C:\\safe.sys"));
    check(executablePath(L"\"unterminated").empty());
    check(executablePath(L"relative.exe arg").empty());
    check(executablePath(L"\\\\example.invalid\\share\\bad.exe arg").empty());
    check(executablePath(L"powershell -enc SECRET").empty());
    check(executablePath(L"C:\\safe.exe --token SECRET").wstring().find(L"SECRET") == std::wstring::npos);
    std::atomic_bool cancelled{false};
    unsigned ticks = 0;
    Pulse pulse = [&] { ++ticks; };
    { Context c{{}, cancelled, pulse}; check(c.finish().outcome == Outcome::checked_no_matches); }
    { Context c{{}, cancelled, pulse}; c.error(ERROR_ACCESS_DENIED); const auto out = c.finish(); check(out.outcome == Outcome::access_denied && out.denied == 1); }
    { Context c{{}, cancelled, pulse}; c.error(static_cast<DWORD>(WBEM_E_ACCESS_DENIED)); check(c.finish().outcome == Outcome::access_denied); }
    { Context c{{}, cancelled, pulse}; c.error(ERROR_INVALID_DATA); check(c.finish().outcome == Outcome::failed); }
    { Context c{{}, cancelled, pulse}; c.add(Record{"fixture"}); c.error(ERROR_ACCESS_DENIED); const auto out = c.finish(); check(out.outcome == Outcome::partial && out.records.size() == 1); }
    { Context c{{}, cancelled, pulse}; c.out.skipped = 1; check(c.finish().outcome == Outcome::partial); }
    { Context c{{}, cancelled, pulse}; c.out.outcome = Outcome::unsupported; c.out.skipped = 1; check(c.finish().outcome == Outcome::unsupported); }
    { Context c{{}, cancelled, pulse}; cancelled = true; check(!c.step()); check(c.finish().outcome == Outcome::cancelled); cancelled = false; }
    { Context c{{}, cancelled, pulse}; c.visited = maxRecords; check(!c.step()); check(c.finish().skipped == 1); }
    { Context c{{}, cancelled, pulse}; c.add(Record{std::string(5000, 'a')}); const auto out = c.finish(); check(out.records[0].name.size() == 4096 && out.skipped == 1); }
    { Context c{{}, cancelled, pulse}; c.out.records.resize(maxRecords); c.add(Record{"overflow"}); const auto out = c.finish(); check(out.records.size() == maxRecords && out.skipped == 1); }
    const auto tcp = connectionRecord(1234, "tcp4", "127.0.0.1", htons(12345), "192.0.2.1", htons(443), 5);
    check(tcp.pid == 1234 && tcp.address == "192.0.2.1" && tcp.executable.empty());
    check(tcp.detail.find("local_port=12345") != std::string::npos && tcp.detail.find("remote_port=443") != std::string::npos);
    const auto udp = connectionRecord(2345, "udp6", "::1", htons(53));
    check(udp.address.empty() && udp.name == "udp6");
    VARIANT value; VariantInit(&value); value.vt = VT_BOOL; value.boolVal = VARIANT_TRUE;
    check(variantText(value) == "true"); value.vt = VT_UI4; value.ulVal = 7; check(variantText(value) == "7");
    value.vt = VT_EMPTY; check(variantText(value) == "unavailable");
    check(ticks == 2);
    struct FixtureIterator {
        unsigned position = 0;
        std::error_code failure;
        unsigned* increments = nullptr;
        unsigned operator*() const { return position; }
        bool operator!=(const FixtureIterator& other) const { return position != other.position; }
        void increment(std::error_code& error) {
            if (increments) ++*increments;
            position = 1;
            error = failure;
        }
    };
    const FixtureIterator end{1};
    const Pulse quiet = [] {};
    {
        Context c{{}, cancelled, quiet};
        directoryEntries(FixtureIterator{0, {ERROR_ACCESS_DENIED, std::system_category()}}, end, c,
            [&](unsigned) { c.add(Record{"fixture"}); });
        const auto out = c.finish();
        check(out.outcome == Outcome::partial && out.denied == 1 && out.records.size() == 1);
    }
    {
        Context c{{}, cancelled, quiet};
        directoryEntries(FixtureIterator{}, end, c, [&](unsigned) { c.add(Record{"fixture"}); });
        const auto out = c.finish();
        check(out.outcome == Outcome::checked_no_matches && !out.denied && !out.errors && out.records.size() == 1);
    }
    {
        Context c{{}, cancelled, quiet};
        directoryEntries(FixtureIterator{0, {ERROR_INVALID_DATA, std::system_category()}}, end, c, [](unsigned) {});
        const auto out = c.finish();
        check(out.outcome == Outcome::failed && out.errors == 1);
    }
    {
        Context c{{}, cancelled, quiet};
        unsigned increments = 0;
        directoryEntries(FixtureIterator{0, {}, &increments}, end, c, [&](unsigned) { cancelled = true; });
        check(c.finish().outcome == Outcome::cancelled && increments == 0);
        cancelled = false;
    }
    return passed;
}
#endif
} // namespace xa
