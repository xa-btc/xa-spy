#pragma once
#include "audit.hpp"

namespace xa {
enum class State { idle, running, completed, cancelled, failed };
enum class Mode { system, folder };
struct CheckProgress {
    CheckId id = CheckId::files;
    Outcome outcome = Outcome::pending;
    std::uint64_t checked = 0, leads = 0, skipped = 0, denied = 0, errors = 0;
};
struct Progress {
    State state = State::idle;
    std::uint64_t checked = 0, skipped = 0, references = 0, hashes = 0, bytes = 0;
    std::uint64_t elapsedSeconds = 0;
    std::string runId; // Generated GUID only; validated again before serialization.
    Mode mode = Mode::system;
    CheckId current = CheckId::processes;
    std::vector<CheckProgress> checks;
    bool fixture = false;
    // This deliberately contains no path, evidence text, username or URL.
};
struct Options {
    fs::path target, application;
    bool browserReferences = false;
    bool securitySettings = false;
    Mode mode = Mode::system;
    // Explicit synthetic backend: never fall back to live collectors if nonempty.
    fs::path fixtureRoot;
};
using Observer = std::function<void(const Progress&)>;
const char* stateName(State state);
std::string filteredJson(const Progress& value);
void scan(const Options& options, std::atomic_bool& cancel, const Observer& observer);
bool validRunId(const std::string& id);
// Local status/summary/cancel commands use fixed filenames and validate/reproject JSON.
std::string control(const fs::path& application, const std::string& action, const std::string& runId);
}
