// Synthetic boundary fixtures only. Not executed in the source-only setup session.
#include "../scanner.hpp"
#include "../json.hpp"
#include <iostream>
#include <stdexcept>
namespace xa { int collectorFixtureChecks(); }

static void require(bool condition) {
    if (!condition) throw std::runtime_error("privacy fixture failed");
}
int main() {
    try {
        xa::Progress value;
        value.runId = "secret-profile\"},\"password\":\"SENSITIVE_SENTINEL";
        value.checked = 12;
        const auto text = xa::filteredJson(value);
        require(text.find("SENSITIVE_SENTINEL") == std::string::npos);
        require(text.find("secret-profile") == std::string::npos);
        require(text.find("run_id") == std::string::npos);
        require(text.find("\"checked\":12") != std::string::npos);
        require(text.find("\"clean_bill_of_health\":false") != std::string::npos);
        value.runId = "{01234567-89AB-CDEF-0123-456789ABCDEF}";
        require(xa::filteredJson(value).find(value.runId) != std::string::npos);
        value.state = static_cast<xa::State>(1234);
        require(xa::filteredJson(value).find("\"state\":\"failed\"") != std::string::npos);
        xa::Options options; // No target; must refuse before feed/evidence access.
        std::atomic_bool cancel{false};
        xa::Progress result;
        xa::scan(options, cancel, [&](const xa::Progress& p) { result = p; });
        require(result.state == xa::State::failed && result.checked == 0 && result.bytes == 0);
        require(xa::collectorFixtureChecks() > 0);
        for (const auto* malformed : {"{\"state\":1,\"state\":2}", "[01]", "\"\\uD800\"", "{\"x\":1e}", "[true] garbage"}) {
            bool rejected = false;
            try { xa::json::parse(malformed); } catch (...) { rejected = true; }
            require(rejected);
        }
        require(xa::json::parse("{\"value\":18446744073709551615}").at("value").uint() == UINT64_MAX);
        require(!xa::validRunId("{01234567_89AB-CDEF-0123-456789ABCDEF}"));
        require(xa::control({}, "status", "../../secret").find("control_request_refused") != std::string::npos);
        std::cout << "Native privacy/parser and collector transformation fixtures passed\n";
        return 0;
    } catch (...) {
        std::cerr << "Native privacy fixture failed\n";
        return 1;
    }
}
