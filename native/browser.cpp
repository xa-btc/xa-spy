// Structured, read-only browser evidence. No URLs leave this module: only hosts.
#include "browser.hpp"
#include "json.hpp"
#include <windows.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace xa {
namespace {
constexpr std::uint64_t databaseLimit = 120ull * 1024 * 1024;
constexpr std::uint64_t bookmarkLimit = 8ull * 1024 * 1024;
constexpr std::size_t recordLimit = 50000;
constexpr DWORD rejectedAttributes = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | 0x40000 | 0x400000;

class ReadGuard {
public:
    HANDLE handle = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION initial{};
    explicit ReadGuard(const fs::path& path) {
        handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (handle != INVALID_HANDLE_VALUE && (!GetFileInformationByHandle(handle, &initial) ||
            GetFileType(handle) != FILE_TYPE_DISK || (initial.dwFileAttributes & (rejectedAttributes | FILE_ATTRIBUTE_DIRECTORY)))) {
            CloseHandle(handle); handle = INVALID_HANDLE_VALUE; SetLastError(ERROR_ACCESS_DENIED);
        }
    }
    ~ReadGuard() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    ReadGuard(const ReadGuard&) = delete;
    ReadGuard& operator=(const ReadGuard&) = delete;
    std::uint64_t size() const { return (std::uint64_t(initial.nFileSizeHigh) << 32) | initial.nFileSizeLow; }
    bool stable() const {
        BY_HANDLE_FILE_INFORMATION now{};
        return GetFileInformationByHandle(handle, &now) &&
            now.nFileSizeHigh == initial.nFileSizeHigh && now.nFileSizeLow == initial.nFileSizeLow &&
            CompareFileTime(&now.ftLastWriteTime, &initial.ftLastWriteTime) == 0;
    }
};

std::wstring lower(std::wstring value) {
    for (auto& c : value) c = static_cast<wchar_t>(std::towlower(c));
    return value;
}

// Parse only HTTP(S) authorities. Ignore userinfo, port, path, query and fragment.
// ASCII DNS labels and numeric IP spellings only; unsupported IDNs stay gaps.
std::string hostOf(std::string_view value) {
    if (value.size() > 32768) return {};
    const auto schemeEnd = value.find("://");
    if (schemeEnd == std::string_view::npos) return {};
    std::string scheme(value.substr(0, schemeEnd));
    for (auto& c : scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (scheme != "http" && scheme != "https") return {};
    auto authority = value.substr(schemeEnd + 3);
    authority = authority.substr(0, authority.find_first_of("/?#\\"));
    const auto userEnd = authority.rfind('@');
    if (userEnd != std::string_view::npos) authority.remove_prefix(userEnd + 1);
    if (authority.empty()) return {};
    std::string host;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) return {};
        const auto tail = authority.substr(close + 1);
        if (!tail.empty() && (tail.front() != ':' || tail.size() == 1 ||
            !std::all_of(tail.begin() + 1, tail.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }))) return {};
        host = std::string(authority.substr(1, close - 1));
        if (host.find(':') == std::string::npos || !std::all_of(host.begin(), host.end(), [](unsigned char c) {
            return std::isxdigit(c) || c == ':' || c == '.';
        })) return {};
    } else {
        const auto port = authority.rfind(':');
        if (port != std::string_view::npos) {
            const auto digits = authority.substr(port + 1);
            if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) return {};
            authority = authority.substr(0, port);
        }
        host = std::string(authority);
        if (!host.empty() && host.back() == '.') host.pop_back();
        if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.' ||
            host.find("..") != std::string::npos || !std::all_of(host.begin(), host.end(), [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
            })) return {};
        std::size_t begin = 0;
        while (begin < host.size()) {
            const auto end = host.find('.', begin);
            const auto length = (end == std::string::npos ? host.size() : end) - begin;
            if (!length || length > 63 || host[begin] == '-' || host[begin + length - 1] == '-') return {};
            if (end == std::string::npos) break;
            begin = end + 1;
        }
    }
    for (auto& c : host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return host;
}

struct Work {
    std::atomic_bool& cancel;
    const Pulse& pulse;
    ULONGLONG deadline = GetTickCount64() + 15000;
    bool timeout = false;
    std::set<std::string> seen;
    bool checkpoint() {
        pulse();
        if (GetTickCount64() >= deadline) timeout = true;
        return !cancel.load() && !timeout;
    }
    bool add(BrowserResult& result, std::string_view url, const char* source, const char* kind) {
        const auto host = hostOf(url);
        if (host.empty()) { ++result.skipped; return true; }
        const auto key = host + "\t" + source + "\t" + kind;
        if (seen.insert(key).second) {
            if (result.records.size() >= recordLimit) { ++result.skipped; result.limitation = "Browser record limit reached."; return false; }
            result.records.push_back({host, source, kind});
        }
        return true;
    }
};

using Json = json::Value;

bool bookmarks(const Json& node, BrowserResult& result, Work& work) {
    if (!work.checkpoint()) return false;
    if (node.type != Json::Type::object) { ++result.skipped; return true; }
    const auto type = node.members.find("type");
    if (type == node.members.end() || type->second.type != Json::Type::string) { ++result.skipped; return true; }
    if (type->second.text == "url") {
        const auto url = node.members.find("url");
        if (url == node.members.end() || url->second.type != Json::Type::string) ++result.skipped;
        else if (!work.add(result, url->second.text, "chromium_bookmarks", "bookmark_reference")) return false;
    } else if (type->second.text == "folder") {
        const auto children = node.members.find("children");
        if (children == node.members.end() || children->second.type != Json::Type::array) { ++result.skipped; return true; }
        for (const auto& child : children->second.items) if (!bookmarks(child, result, work)) return false;
    } else ++result.skipped;
    return true;
}

struct sqlite3;
struct sqlite3_stmt;
struct Sqlite {
    HMODULE library = nullptr;
    int (__cdecl* open)(const char*, sqlite3**, int, const char*) = nullptr;
    int (__cdecl* close)(sqlite3*) = nullptr;
    int (__cdecl* prepare)(sqlite3*, const char*, int, sqlite3_stmt**, const char**) = nullptr;
    int (__cdecl* step)(sqlite3_stmt*) = nullptr;
    int (__cdecl* finalize)(sqlite3_stmt*) = nullptr;
    const unsigned char* (__cdecl* text)(sqlite3_stmt*, int) = nullptr;
    int (__cdecl* bytes)(sqlite3_stmt*, int) = nullptr;
    int (__cdecl* type)(sqlite3_stmt*, int) = nullptr;
    int (__cdecl* limit)(sqlite3*, int, int) = nullptr;
    void (__cdecl* progress)(sqlite3*, int, int (__cdecl*)(void*), void*) = nullptr;
    int (__cdecl* authorizer)(sqlite3*, int (__cdecl*)(void*, int, const char*, const char*, const char*, const char*), void*) = nullptr;
    template<class T> bool load(T& target, const char* name) { target = reinterpret_cast<T>(GetProcAddress(library, name)); return target != nullptr; }
    Sqlite() {
        library = LoadLibraryExW(L"winsqlite3.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) return;
        if (!(load(open, "sqlite3_open_v2") && load(close, "sqlite3_close_v2") && load(prepare, "sqlite3_prepare_v2") &&
            load(step, "sqlite3_step") && load(finalize, "sqlite3_finalize") && load(text, "sqlite3_column_text") &&
            load(bytes, "sqlite3_column_bytes") && load(type, "sqlite3_column_type") && load(limit, "sqlite3_limit") &&
            load(progress, "sqlite3_progress_handler") && load(authorizer, "sqlite3_set_authorizer"))) {
            FreeLibrary(library); library = nullptr;
        }
    }
    ~Sqlite() { if (library) FreeLibrary(library); }
};
struct Db {
    Sqlite& api; sqlite3* handle = nullptr;
    explicit Db(Sqlite& sql) : api(sql) {}
    ~Db() { if (handle) api.close(handle); }
};
struct Statement {
    Sqlite& api; sqlite3_stmt* handle = nullptr;
    explicit Statement(Sqlite& sql) : api(sql) {}
    ~Statement() { if (handle) api.finalize(handle); }
};
constexpr int sqlOk = 0, sqlRow = 100, sqlDone = 101, sqlText = 3;
int __cdecl sqlProgress(void* value) {
    auto& work = *static_cast<Work*>(value);
    try { return work.checkpoint() ? 0 : 1; } catch (...) { work.timeout = true; return 1; }
}
int __cdecl sqlAuthorize(void*, int action, const char* table, const char*, const char*, const char* origin) {
    if (origin) return 1; // No views/triggers, including attacker-defined schema.
    if (action == 21) return 0; // SELECT
    if (action == 20 && table) { // READ
        const std::string_view name(table);
        if (name == "sqlite_master" || name == "sqlite_schema" || name == "urls" || name == "downloads_url_chains" || name == "moz_places") return 0;
    }
    return 1;
}
int tableState(Sqlite& api, sqlite3* db, const char* table) {
    // table is a fixed source-code constant, never evidence-derived SQL.
    const std::string sql = "SELECT type,sql FROM sqlite_master WHERE name='" + std::string(table) + "'";
    Statement query(api);
    if (api.prepare(db, sql.c_str(), -1, &query.handle, nullptr) != sqlOk) return -1;
    const auto code = api.step(query.handle);
    if (code == sqlDone) return 0;
    if (code != sqlRow) return -1;
    const auto* text = api.text(query.handle, 0);
    if (!text || api.bytes(query.handle, 0) != 5 || std::string_view(reinterpret_cast<const char*>(text), 5) != "table") return 0;
    const auto* definition = api.text(query.handle, 1);
    const auto size = api.bytes(query.handle, 1);
    if (!definition || size < 12 || size > 32768) return 0;
    std::string prefix(reinterpret_cast<const char*>(definition), 12);
    for (auto& c : prefix) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    // Reject virtual-table module invocation as well as views. Browser schema is ordinary CREATE TABLE.
    return prefix == "create table";
}
bool queryHosts(Sqlite& api, sqlite3* db, const char* sql, const char* source, const char* kind, BrowserResult& result, Work& work) {
    Statement query(api);
    if (api.prepare(db, sql, -1, &query.handle, nullptr) != sqlOk) {
        ++result.skipped;
        if (result.records.empty()) result.outcome = Outcome::unsupported;
        return false;
    }
    std::size_t rows = 0;
    while (work.checkpoint()) {
        const int code = api.step(query.handle);
        if (code == sqlDone) return true;
        if (code != sqlRow) { ++result.errors; return false; }
        if (++rows > recordLimit) { ++result.skipped; result.limitation = "Browser query row limit reached."; return false; }
        if (api.type(query.handle, 0) != sqlText) { ++result.skipped; continue; }
        const auto count = api.bytes(query.handle, 0);
        const auto* text = api.text(query.handle, 0);
        if (!text || count <= 0 || count > 32768) { ++result.skipped; continue; }
        if (!work.add(result, std::string_view(reinterpret_cast<const char*>(text), count), source, kind)) return false;
    }
    return false;
}
bool noSidecars(const fs::path& path) {
    for (const auto* suffix : {L"-wal", L"-shm", L"-journal"}) {
        const fs::path side(path.wstring() + suffix);
        if (!safeLocalPath(side, true)) return false;
        const auto attributes = GetFileAttributesW(side.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) return false;
        const auto error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return false;
    }
    return true;
}
void sqliteHosts(const fs::path& path, bool firefox, BrowserResult& result, Work& work) {
    if (!noSidecars(path)) {
        result.outcome = Outcome::unsupported; ++result.skipped;
        result.limitation = "Live WAL/SHM/journal or unsafe sidecar: close the browser before checking; no snapshot was copied.";
        return;
    }
    Sqlite api;
    if (!api.library) {
        result.outcome = Outcome::unsupported; ++result.skipped;
        result.limitation = "Windows SQLite library unavailable; no dependency was downloaded."; return;
    }
    Db db(api);
    const auto filename = toUtf8(path.wstring());
    if (api.open(filename.c_str(), &db.handle, 0x00000001 /* READONLY */ | 0x00008000 /* NOMUTEX */, nullptr) != sqlOk) {
        result.outcome = Outcome::failed; ++result.errors; result.limitation = "Read-only database open failed."; return;
    }
    api.limit(db.handle, 0, 65536); api.limit(db.handle, 1, 4096); api.limit(db.handle, 2, 128);
    api.limit(db.handle, 3, 64); api.limit(db.handle, 5, 100000); api.limit(db.handle, 7, 0);
    api.limit(db.handle, 9, 64); api.limit(db.handle, 10, 0);
    api.progress(db.handle, 1000, sqlProgress, &work);
    for (const char* sql : {"PRAGMA trusted_schema=OFF", "PRAGMA query_only=ON", "PRAGMA mmap_size=0", "BEGIN"}) {
        Statement statement(api);
        if (api.prepare(db.handle, sql, -1, &statement.handle, nullptr) != sqlOk) { ++result.errors; return; }
        const auto code = api.step(statement.handle);
        if (code != sqlDone && code != sqlRow) { ++result.errors; return; }
    }
    api.authorizer(db.handle, sqlAuthorize, nullptr);
    auto hasTable = [&](const char* name) {
        const auto state = tableState(api, db.handle, name);
        if (state < 0) ++result.errors;
        else if (state == 0) ++result.skipped;
        return state == 1;
    };
    if (firefox) {
        if (!hasTable("moz_places")) result.outcome = Outcome::unsupported;
        else queryHosts(api, db.handle, "SELECT url FROM moz_places WHERE visit_count > 0 LIMIT 50001", "firefox_places", "history_record", result, work);
    } else {
        if (!hasTable("urls")) result.outcome = Outcome::unsupported;
        else queryHosts(api, db.handle, "SELECT url FROM urls WHERE visit_count > 0 LIMIT 50001", "chromium_history", "history_record", result, work);
        if (work.checkpoint()) {
            if (hasTable("downloads_url_chains")) queryHosts(api, db.handle, "SELECT url FROM downloads_url_chains LIMIT 50001", "chromium_downloads", "download_reference", result, work);
        }
    }
    if (!noSidecars(path)) { ++result.errors; result.limitation = "Database sidecars changed during read; evidence is partial."; }
}

std::wstring environment(const wchar_t* name) {
    const auto size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size || size > 32768) return {};
    std::wstring value(size, L'\0');
    const auto count = GetEnvironmentVariableW(name, value.data(), size);
    if (!count || count >= size) return {};
    value.resize(count); return value;
}
}

BrowserResult readBrowserArtifact(const fs::path& path, std::atomic_bool& cancel, const Pulse& pulse) {
    BrowserResult result;
    Work work{cancel, pulse};
    try {
        if (!work.checkpoint()) { result.outcome = cancel ? Outcome::cancelled : Outcome::partial; return result; }
        const auto filename = lower(path.filename().wstring());
        if (filename != L"history" && filename != L"places.sqlite" && filename != L"bookmarks") {
            result.outcome = Outcome::unsupported; ++result.skipped; result.limitation = "Unsupported browser artifact or refused local path."; return result;
        }
        if (!safeLocalPath(path)) {
            if (GetLastError() == ERROR_ACCESS_DENIED) { result.outcome = Outcome::access_denied; ++result.denied; }
            else { result.outcome = Outcome::unsupported; ++result.skipped; }
            result.limitation = "Browser path could not be safely opened."; return result;
        }
        ReadGuard input(path);
        if (input.handle == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) { result.outcome = Outcome::access_denied; ++result.denied; }
            else { result.outcome = Outcome::failed; ++result.errors; }
            result.limitation = "Artifact unavailable or open for writing; close the browser before checking.";
            return result;
        }
        const auto limit = filename == L"bookmarks" ? bookmarkLimit : databaseLimit;
        if (input.size() > limit) { result.outcome = Outcome::unsupported; ++result.skipped; result.limitation = "Browser artifact size limit reached."; return result; }
        if (filename == L"bookmarks") {
            std::string text;
            std::array<char, 65536> block{};
            while (work.checkpoint()) {
                DWORD count = 0;
                if (!ReadFile(input.handle, block.data(), static_cast<DWORD>(block.size()), &count, nullptr)) throw std::runtime_error("bookmark read");
                if (!count) break;
                text.append(block.data(), count);
                if (text.size() > bookmarkLimit) throw std::runtime_error("bookmark bound");
            }
            if (cancel.load() || work.timeout) throw std::runtime_error("interrupted");
            if (text.size() != input.size()) throw std::runtime_error("bookmark changed");
            // Chromium writes UTF-8; reject malformed byte sequences before JSON parsing.
            if (!text.empty() && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0))
                throw std::runtime_error("bookmark encoding");
            auto document = json::parse(text);
            const auto roots = document.members.find("roots");
            if (document.type != Json::Type::object || roots == document.members.end() || roots->second.type != Json::Type::object) {
                result.outcome = Outcome::unsupported; ++result.skipped; result.limitation = "Unsupported Chromium bookmark schema.";
            } else for (const auto& [name, root] : roots->second.members) { (void)name; if (!bookmarks(root, result, work)) break; }
        } else sqliteHosts(path, filename == L"places.sqlite", result, work);
        if (!input.stable()) { ++result.errors; result.limitation = "Artifact changed during read; evidence is partial."; }
    } catch (...) {
        if (!cancel.load() && !work.timeout) ++result.errors;
        result.limitation = "Malformed, unavailable or bounded browser evidence; no executable content was run.";
    }
    if (cancel.load()) result.outcome = Outcome::cancelled;
    else if (work.timeout) { ++result.skipped; result.outcome = Outcome::partial; result.limitation = "Browser reading time limit reached."; }
    else if (result.errors) result.outcome = result.records.empty() ? Outcome::failed : Outcome::partial;
    else if (result.denied) result.outcome = result.records.empty() ? Outcome::access_denied : Outcome::partial;
    else if (result.skipped && (result.outcome != Outcome::unsupported || !result.records.empty())) result.outcome = Outcome::partial;
    // Presence of browser records is not itself a lead; parent performs indicator matching.
    return result;
}

std::vector<fs::path> discoverBrowserRoots() {
    std::vector<fs::path> roots;
    const auto local = environment(L"LOCALAPPDATA"), roaming = environment(L"APPDATA");
    auto append = [&](const fs::path& root) { if (!root.empty() && safeLocalPath(root)) roots.push_back(root); };
    if (!local.empty()) {
        append(fs::path(local) / L"Google/Chrome/User Data");
        append(fs::path(local) / L"Microsoft/Edge/User Data");
        append(fs::path(local) / L"BraveSoftware/Brave-Browser/User Data");
        append(fs::path(local) / L"Chromium/User Data");
    }
    if (!roaming.empty()) append(fs::path(roaming) / L"Mozilla/Firefox/Profiles");
    return roots;
}
}
