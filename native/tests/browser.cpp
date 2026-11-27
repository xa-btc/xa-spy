// Synthetic browser artifacts only. Never calls discoverBrowserRoots or reads profiles.
#include "../browser.hpp"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
void require(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}
struct sqlite3;
class FixtureDb {
    HMODULE library = nullptr;
    sqlite3* db = nullptr;
    int (__cdecl* closeDb)(sqlite3*) = nullptr;
    int (__cdecl* execute)(sqlite3*, const char*, int (__cdecl*)(void*, int, char**, char**), void*, char**) = nullptr;
public:
    explicit FixtureDb(const xa::fs::path& path) {
        library = LoadLibraryExW(L"winsqlite3.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        require(library != nullptr, "Fixture SQLite is unavailable");
        auto open = reinterpret_cast<int (__cdecl*)(const char*, sqlite3**, int, const char*)>(GetProcAddress(library, "sqlite3_open_v2"));
        closeDb = reinterpret_cast<decltype(closeDb)>(GetProcAddress(library, "sqlite3_close_v2"));
        execute = reinterpret_cast<decltype(execute)>(GetProcAddress(library, "sqlite3_exec"));
        require(open && closeDb && execute, "Fixture SQLite exports unavailable");
        require(open(xa::toUtf8(path.wstring()).c_str(), &db, 2 | 4, nullptr) == 0, "Fixture database creation failed");
    }
    ~FixtureDb() { if (db && closeDb) closeDb(db); if (library) FreeLibrary(library); }
    void sql(const char* text) { require(execute(db, text, nullptr, nullptr, nullptr) == 0, "Fixture SQL failed"); }
};
void write(const xa::fs::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary); output << text;
    require(bool(output), "Fixture file creation failed");
}
bool contains(const xa::BrowserResult& result, const char* host, const char* kind) {
    for (const auto& record : result.records) if (record.host == host && record.kind == kind) return true;
    return false;
}
void privacy(const xa::BrowserResult& result) {
    for (const auto& record : result.records) {
        const auto text = record.host + record.source + record.kind;
        require(text.find("SENSITIVE_SENTINEL") == std::string::npos, "Sensitive URL component escaped reader");
        require(text.find('@') == std::string::npos && text.find('?') == std::string::npos && text.find('/') == std::string::npos,
                "Returned browser record is not host-only");
    }
}
}

int main() {
    try {
        wchar_t temp[32768]{};
        require(GetTempPathW(32768, temp) != 0, "Temporary fixture root unavailable");
        const auto root = xa::fs::path(temp) / (L"xa-spy-browser-fixtures-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        require(xa::fs::create_directory(root), "Could not create new fixture directory");
        std::atomic_bool cancel{false};
        const xa::Pulse pulse = [] {};
        unsigned assertions = 0;
        auto folder = [&](const wchar_t* name) { auto path = root / name; require(xa::fs::create_directory(path), "Fixture subdirectory failed"); return path; };

        const auto chrome = folder(L"chromium") / L"History";
        {
            FixtureDb db(chrome);
            db.sql("CREATE TABLE urls(url TEXT,visit_count INTEGER); CREATE TABLE downloads_url_chains(url TEXT);"
                   "INSERT INTO urls VALUES('https://SENSITIVE_SENTINEL:pass@Example.Test/path?token=SENSITIVE_SENTINEL#fragment',3),"
                   "('https://ignored.test/',0),('chrome://settings/',1),('https://sub.example.test.:443/',1);"
                   "INSERT INTO downloads_url_chains VALUES('https://download.test/file.exe?secret=SENSITIVE_SENTINEL');");
        }
        auto result = xa::readBrowserArtifact(chrome, cancel, pulse);
        require(result.outcome == xa::Outcome::partial, "Unsupported URL should be a recorded gap"); ++assertions;
        require(contains(result, "example.test", "history_record"), "Chromium history host missing"); ++assertions;
        require(contains(result, "sub.example.test", "history_record"), "Trailing-dot/port normalization failed"); ++assertions;
        require(contains(result, "download.test", "download_reference"), "Download chain reference missing"); ++assertions;
        require(!contains(result, "ignored.test", "history_record"), "Unvisited URL misreported as history"); ++assertions;
        privacy(result); ++assertions;

        const auto firefox = folder(L"firefox") / L"places.sqlite";
        {
            FixtureDb db(firefox);
            db.sql("CREATE TABLE moz_places(url TEXT,visit_count INTEGER);"
                   "INSERT INTO moz_places VALUES('https://firefox.test/?secret=SENSITIVE_SENTINEL',2),('https://notvisited.test/',0);");
        }
        result = xa::readBrowserArtifact(firefox, cancel, pulse);
        require(result.outcome == xa::Outcome::checked_no_matches && result.records.size() == 1, "Firefox structured history failed"); ++assertions;
        require(contains(result, "firefox.test", "history_record"), "Firefox host missing"); privacy(result); ++assertions;

        const auto bookmark = folder(L"bookmarks") / L"Bookmarks";
        write(bookmark, R"({"roots":{"bookmark_bar":{"type":"folder","children":[{"type":"url","url":"https://user:SENSITIVE_SENTINEL@Bookmark.Test/a?token=SENSITIVE_SENTINEL"},{"type":"folder","children":[{"type":"url","url":"https://nested\u002etest/"}]}]}},"irrelevant":{"url":"https://must-not-match.test/"}})");
        result = xa::readBrowserArtifact(bookmark, cancel, pulse);
        require(result.outcome == xa::Outcome::checked_no_matches && result.records.size() == 2, "Bookmark schema traversal failed"); ++assertions;
        require(contains(result, "bookmark.test", "bookmark_reference") && contains(result, "nested.test", "bookmark_reference"), "Bookmark host parsing failed"); privacy(result); ++assertions;
        require(!contains(result, "must-not-match.test", "bookmark_reference"), "Non-bookmark URL treated as evidence"); ++assertions;

        write(bookmark, R"({"roots":{},"roots":{"wrong":{}}})");
        result = xa::readBrowserArtifact(bookmark, cancel, pulse);
        require(result.outcome == xa::Outcome::failed && result.records.empty(), "Duplicate JSON keys accepted"); ++assertions;
        write(bookmark, R"({"roots":{"bad":{"type":"url","url":"https://evil.test/path"}}} trailing)");
        require(xa::readBrowserArtifact(bookmark, cancel, pulse).outcome == xa::Outcome::failed, "Trailing JSON accepted"); ++assertions;
        write(bookmark, R"({"not_roots":{}})");
        require(xa::readBrowserArtifact(bookmark, cancel, pulse).outcome == xa::Outcome::unsupported, "Unknown bookmark schema reported checked"); ++assertions;

        const auto view = folder(L"view") / L"History";
        { FixtureDb db(view); db.sql("CREATE VIEW urls AS SELECT 'https://evil.test/' AS url, 1 AS visit_count;"); }
        result = xa::readBrowserArtifact(view, cancel, pulse);
        require(result.records.empty() && result.outcome == xa::Outcome::unsupported, "Attacker-defined view accepted as history table"); ++assertions;
        const auto malformed = folder(L"malformed") / L"History";
        write(malformed, "not a SQLite database SENSITIVE_SENTINEL");
        result = xa::readBrowserArtifact(malformed, cancel, pulse);
        require(result.records.empty() && result.outcome == xa::Outcome::failed, "Malformed database did not report failure"); ++assertions;
        const auto schema = folder(L"unsupported-schema") / L"places.sqlite";
        { FixtureDb db(schema); db.sql("CREATE TABLE moz_places(url TEXT,unsupported_counter INTEGER);"); }
        require(xa::readBrowserArtifact(schema, cancel, pulse).outcome == xa::Outcome::unsupported, "Unsupported SQL schema reported checked"); ++assertions;

        write(xa::fs::path(chrome.wstring() + L"-wal"), "synthetic sidecar");
        result = xa::readBrowserArtifact(chrome, cancel, pulse);
        require(result.outcome == xa::Outcome::unsupported && result.records.empty(), "WAL database was read"); ++assertions;
        const auto locked = folder(L"locked") / L"History";
        { FixtureDb db(locked); db.sql("CREATE TABLE urls(url TEXT,visit_count INTEGER);"); }
        HANDLE lock = CreateFileW(locked.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        require(lock != INVALID_HANDLE_VALUE, "Fixture lock failed");
        result = xa::readBrowserArtifact(locked, cancel, pulse);
        CloseHandle(lock);
        require(result.outcome == xa::Outcome::access_denied && result.denied == 1, "Locked database did not report access denied"); ++assertions;

        const auto forbidden = folder(L"forbidden") / L"Login Data";
        write(forbidden, "SENSITIVE_SENTINEL");
        result = xa::readBrowserArtifact(forbidden, cancel, pulse);
        require(result.outcome == xa::Outcome::unsupported && result.records.empty(), "Credential-store artifact accepted"); ++assertions;
        cancel = true;
        result = xa::readBrowserArtifact(firefox, cancel, pulse);
        require(result.outcome == xa::Outcome::cancelled && result.records.empty(), "Pre-cancel read did not stop"); ++assertions;
        cancel = false;
        unsigned ticks = 0;
        result = xa::readBrowserArtifact(firefox, cancel, [&] { if (++ticks >= 2) cancel = true; });
        require(result.outcome == xa::Outcome::cancelled, "Cooperative cancellation did not propagate"); ++assertions;
        cancel = false;

        const auto many = folder(L"bounded") / L"places.sqlite";
        { FixtureDb db(many); db.sql("CREATE TABLE moz_places(url TEXT,visit_count INTEGER);"
              "WITH RECURSIVE counter(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM counter WHERE x<50002)"
              "INSERT INTO moz_places SELECT 'https://bounded.test/',1 FROM counter;"); }
        result = xa::readBrowserArtifact(many, cancel, pulse);
        require(result.outcome == xa::Outcome::partial && result.skipped > 0 && result.records.size() == 1, "SQLite row limit did not retain partial evidence"); ++assertions;

        std::cout << "PASS: " << assertions << " synthetic browser assertions; fixtures retained locally.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
