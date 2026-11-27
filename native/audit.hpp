#pragma once
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace xa {
namespace fs = std::filesystem;
enum class CheckId { processes, services, drivers, startup_registry, startup_folders,
    scheduled_tasks, installed_apps, security, event_logs, connections, devices, files, browser, settings };
enum class Outcome { pending, running, checked_no_matches, leads, partial, access_denied, unsupported, failed, cancelled };
const char* checkName(CheckId id);
const char* outcomeName(Outcome outcome);
std::vector<CheckId> systemChecks();
// Private records never cross the AI output boundary. No command arguments, event
// messages, credentials, cookies or device contents belong in these records.
struct Record {
    std::string name, detail, address;
    fs::path executable;
    std::uint32_t pid = 0;
};
struct Collection {
    Outcome outcome = Outcome::checked_no_matches;
    std::vector<Record> records;
    std::uint64_t denied = 0, skipped = 0, errors = 0;
    std::string limitation;
};
using Pulse = std::function<void()>;
Collection collectWindows(CheckId id, std::atomic_bool& cancel, const Pulse& pulse);
// Shared file policy. This does not provide an operating-system sandbox.
bool safeLocalPath(const fs::path& path, bool allowMissing = false);
std::string toUtf8(const std::wstring& text);
std::wstring fromUtf8(const std::string& text);
std::string jsonQuote(const std::string& text);
}
