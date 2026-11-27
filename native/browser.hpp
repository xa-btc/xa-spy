#pragma once
#include "audit.hpp"
namespace xa {
struct BrowserRecord { std::string host, source, kind; };
struct BrowserResult {
    Outcome outcome = Outcome::checked_no_matches;
    std::vector<BrowserRecord> records;
    std::uint64_t denied = 0, skipped = 0, errors = 0;
    std::string limitation;
};
// Reads only approved artifacts; return host only, never complete URLs or tokens.
BrowserResult readBrowserArtifact(const fs::path& path, std::atomic_bool& cancel, const Pulse& pulse);
std::vector<fs::path> discoverBrowserRoots();
}
