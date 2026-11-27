// Native, local-only evidence triage. No Python, network API or process launching.
#include "scanner.hpp"
#include "browser.hpp"
#include "json.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <objbase.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <limits>

namespace xa {
namespace {
constexpr std::uint64_t maxFile = 120ull * 1024 * 1024;
constexpr std::uint64_t maxEntries = 100000;
constexpr DWORD refusedAttributes = FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE |
    0x00040000 /* RECALL_ON_OPEN */ | 0x00400000 /* RECALL_ON_DATA_ACCESS */;
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};
std::wstring lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return std::towlower(c); });
    return s;
}
std::string asciiLower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return s;
}
bool privateName(const fs::path& path) {
    auto name = lower(path.filename().wstring());
    for (const auto* suffix : {L"-wal", L"-shm", L"-journal"}) {
        const std::wstring tail(suffix);
        if (name.ends_with(tail)) { name.resize(name.size() - tail.size()); break; }
    }
    static const std::set<std::wstring> names = {L"login data", L"login data for account",
        L"logins.json", L"key3.db", L"key4.db", L"signons.sqlite", L"cookies",
        L"cookies.sqlite", L"cookies.binarycookies"};
    return names.contains(name);
}
bool safePath(const fs::path& path, bool allowMissing = false) {
    SetLastError(ERROR_SUCCESS);
    const auto raw = path.wstring();
    if (!path.is_absolute() || raw.size() < 3 || raw[1] != L':' || raw.starts_with(L"\\\\") ||
        raw.find(L':', 2) != std::wstring::npos) return false;
    if (GetDriveTypeW(path.root_path().c_str()) != DRIVE_FIXED) return false;
    fs::path cursor = path.root_path();
    for (const auto& part : path.relative_path()) {
        if (part == L".." || part == L"." || privateName(part)) return false;
        const auto name = part.wstring();
        if (name.empty() || name.back() == L'.' || name.back() == L' ') return false;
        cursor /= part;
        const DWORD attrs = GetFileAttributesW(cursor.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            const auto error = GetLastError();
            if (allowMissing && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) continue;
            return false;
        }
        if (attrs & refusedAttributes) return false;
    }
    return true;
}
// Protect the opened final object too. Parent-directory races remain a documented limit.
bool safeHandle(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    return handle != INVALID_HANDLE_VALUE && GetFileType(handle) == FILE_TYPE_DISK &&
        GetFileInformationByHandle(handle, &info) &&
        !(info.dwFileAttributes & (refusedAttributes | FILE_ATTRIBUTE_DIRECTORY));
}
std::string utf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    return result;
}
std::string quote(const std::string& s) {
    std::ostringstream out; out << '"';
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec;
        else out << c;
    }
    out << '"'; return out.str();
}
class Output {
    Handle handle;
public:
    explicit Output(const fs::path& path) : handle(safePath(path, true) ?
        CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) : INVALID_HANDLE_VALUE) {
        if (!safeHandle(handle.value)) throw std::runtime_error("output refused");
    }
    void line(const std::string& text) {
        const auto value = text + "\n";
        DWORD written = 0;
        if (!WriteFile(handle.value, value.data(), static_cast<DWORD>(value.size()), &written, nullptr) ||
            written != value.size()) throw std::runtime_error("output failed");
    }
};
struct Indicator { std::string value, tier, source; };
struct Feed { std::map<std::string, Indicator> hashes; std::vector<Indicator> domains; };
bool hexHash(const std::string& s) {
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); });
}
Feed loadFeed(const fs::path& app) {
    Feed feed;
    for (const auto* name : {L"adfection_iocs.txt", L"curated_mercenary.txt"}) {
        const auto path = app / L"iocs" / name;
        if (!safePath(path) || fs::file_size(path) > 8 * 1024 * 1024) throw std::runtime_error("feed refused");
        std::ifstream input(path);
        if (!input) throw std::runtime_error("feed unavailable");
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty() || line[0] == '#') continue;
            if (line.back() == '\r') line.pop_back();
            std::istringstream fields(line);
            Indicator entry; std::string confidence;
            if (!std::getline(fields, entry.value, '\t') || !std::getline(fields, entry.tier, '\t') ||
                !std::getline(fields, confidence, '\t') || !std::getline(fields, entry.source, '\t')) continue;
            entry.value = asciiLower(entry.value);
            if(entry.source.empty()||(confidence!="primary"&&confidence!="secondary"))continue;
            IN6_ADDR ipv6{};
            if(entry.value.find(':')!=std::string::npos&&InetPtonA(AF_INET6,entry.value.c_str(),&ipv6)==1&&entry.tier!="artifact"){
                std::array<char,INET6_ADDRSTRLEN> canonical{};
                if(InetNtopA(AF_INET6,&ipv6,canonical.data(),static_cast<DWORD>(canonical.size()))) {entry.value=canonical.data();feed.domains.push_back(entry);}
            }
            else if (hexHash(entry.value) && (entry.tier == "sample" || entry.tier == "vuln-driver"))
                feed.hashes.emplace(entry.value, entry);
            else if (entry.tier != "artifact" && entry.value.size() <= 253 &&
                entry.value.find('.') != std::string::npos &&
                std::all_of(entry.value.begin(), entry.value.end(), [](unsigned char c) {
                    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-';
                })) feed.domains.push_back(entry);
            if (feed.domains.size() + feed.hashes.size() > 10000) throw std::runtime_error("feed limit exceeded");
        }
        if (input.bad()) throw std::runtime_error("feed read failed");
    }
    if (feed.hashes.empty() && feed.domains.empty()) throw std::runtime_error("empty feed");
    return feed;
}
struct Hasher {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<unsigned char> object;
    Hasher() {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            throw std::runtime_error("hash provider failed");
        DWORD length = 0, copied = 0;
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof length, &copied, 0) < 0) {
            BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr;
            throw std::runtime_error("hash setup failed");
        }
        object.resize(length);
        if (BCryptCreateHash(algorithm, &hash, object.data(), length, nullptr, 0, 0) < 0) {
            BCryptCloseAlgorithmProvider(algorithm, 0); algorithm = nullptr;
            throw std::runtime_error("hash setup failed");
        }
    }
    ~Hasher() { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); }
    void add(const char* data, DWORD size) {
        if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(data)), size, 0) < 0)
            throw std::runtime_error("hash failed");
    }
    std::string finish() {
        std::array<unsigned char, 32> digest{};
        if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
            throw std::runtime_error("hash failed");
        std::ostringstream out;
        for (auto b : digest) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return out.str();
    }
};
bool boundary(unsigned char c) {
    return !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.');
}
bool containsDomain(const std::string& data, const std::string& needle) {
    if(needle.find(':')!=std::string::npos){IN6_ADDR left{},right{};
        return InetPtonA(AF_INET6,data.c_str(),&left)==1&&InetPtonA(AF_INET6,needle.c_str(),&right)==1&&std::memcmp(&left,&right,sizeof left)==0;}
    const bool numeric = std::all_of(needle.begin(), needle.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || c == '.';
    });
    size_t start = 0;
    while ((start = data.find(needle, start)) != std::string::npos) {
        const auto end = start + needle.size();
        if ((start == 0 || boundary(data[start - 1]) || (!numeric && data[start - 1] == '.')) &&
            (end == data.size() || boundary(data[end]))) return true;
        ++start;
    }
    return false;
}
bool hashCandidate(const fs::path& path) {
    static const std::set<std::wstring> extensions = {L".exe", L".dll", L".sys", L".scr", L".msi", L".com"};
    return extensions.contains(lower(path.extension().wstring()));
}
bool browserArtifact(const fs::path& path) {
    const auto name=lower(path.filename().wstring());
    return name==L"history"||name==L"places.sqlite"||name==L"bookmarks";
}
bool within(const fs::path& child,const fs::path& parent) {
    auto a=lower(child.lexically_normal().wstring()),b=lower(parent.lexically_normal().wstring());
    if(a==b)return true;if(!b.ends_with(L"\\"))b+=L"\\";return a.starts_with(b);
}
std::string readBounded(const fs::path& path,size_t limit) {
    if(!safePath(path))throw std::runtime_error("path refused");
    Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    LARGE_INTEGER size{};
    if(!safeHandle(h.value)||!GetFileSizeEx(h.value,&size)||size.QuadPart<0||static_cast<std::uint64_t>(size.QuadPart)>limit)throw std::runtime_error("read refused");
    std::string text(static_cast<size_t>(size.QuadPart),'\0');DWORD read=0;
    if(!ReadFile(h.value,text.data(),static_cast<DWORD>(text.size()),&read,nullptr)||read!=text.size())throw std::runtime_error("read failed");
    return text;
}
std::string readTail(const fs::path& path,DWORD limit) {
    if(!safePath(path))throw std::runtime_error("path refused");
    Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    LARGE_INTEGER size{};
    if(!safeHandle(h.value)||!GetFileSizeEx(h.value,&size)||size.QuadPart<0)throw std::runtime_error("tail refused");
    LARGE_INTEGER start{};start.QuadPart=std::max<LONGLONG>(0,size.QuadPart-limit);
    if(!SetFilePointerEx(h.value,start,nullptr,FILE_BEGIN))throw std::runtime_error("tail seek failed");
    const DWORD wanted=static_cast<DWORD>(size.QuadPart-start.QuadPart);std::string text(wanted,'\0');DWORD read=0;
    if(!ReadFile(h.value,text.data(),wanted,&read,nullptr)||read!=wanted)throw std::runtime_error("tail changed");
    // Drop a possible partial first line and the in-flight final line.
    if(start.QuadPart){auto newline=text.find('\n');if(newline==std::string::npos)throw std::runtime_error("no bounded record");text.erase(0,newline+1);}
    auto end=text.rfind('\n');if(end==std::string::npos)throw std::runtime_error("no complete record");text.resize(end);
    auto begin=text.rfind('\n');return begin==std::string::npos?text:text.substr(begin+1);
}
Outcome parseOutcome(const std::string& text) {
    for(auto outcome:{Outcome::pending,Outcome::running,Outcome::checked_no_matches,Outcome::leads,Outcome::partial,
        Outcome::access_denied,Outcome::unsupported,Outcome::failed,Outcome::cancelled}) if(text==outcomeName(outcome))return outcome;
    throw std::runtime_error("unknown outcome");
}
CheckId parseCheck(const std::string& text) {
    for(auto id:systemChecks())if(text==checkName(id))return id;
    if(text=="settings")return CheckId::settings;
    if(text=="files")return CheckId::files;if(text=="browser")return CheckId::browser;
    throw std::runtime_error("unknown check");
}
Collection fixtureCollection(const fs::path& root,CheckId id) {
    Collection out;
    const auto doc=json::parse(readBounded(root/(std::string(checkName(id))+".json"),4*1024*1024));
    out.outcome=parseOutcome(doc.at("outcome").string());
    if(out.outcome==Outcome::pending||out.outcome==Outcome::running)throw std::runtime_error("fixture not terminal");
    for(const auto* key:{"denied","skipped","errors"})if(doc.members.contains(key)){
        auto value=doc.at(key).uint();if(value>100000)throw std::runtime_error("fixture count limit");
        if(std::string(key)=="denied")out.denied=value;else if(std::string(key)=="errors")out.errors=value;else out.skipped=value;
    }
    const auto& rows=doc.at("records");if(rows.type!=json::Value::Type::array||rows.items.size()>10000)throw std::runtime_error("fixture limit");
    for(const auto& row:rows.items){Record r;
        if(row.members.contains("name"))r.name=row.at("name").string();
        if(row.members.contains("detail"))r.detail=row.at("detail").string();
        if(row.members.contains("address"))r.address=row.at("address").string();
        if(row.members.contains("executable")){r.executable=fromUtf8(row.at("executable").string());if(!r.executable.empty()&&!within(r.executable,root))throw std::runtime_error("fixture path escaped");}
        if(row.members.contains("pid")){auto pid=row.at("pid").uint();if(pid>UINT32_MAX)throw std::runtime_error("pid overflow");r.pid=static_cast<std::uint32_t>(pid);}
        out.records.push_back(std::move(r));
    }
    return out;
}
void finish(CheckProgress& c) {
    if(c.outcome!=Outcome::running)return;
    if(c.errors||c.denied||c.skipped){
        if(c.checked||c.leads)c.outcome=Outcome::partial;
        else if(c.errors)c.outcome=Outcome::failed;
        else if(c.denied)c.outcome=Outcome::access_denied;
        else c.outcome=Outcome::unsupported;
    }
    else c.outcome=c.leads?Outcome::leads:Outcome::checked_no_matches;
}
void writeRecord(Output& out,CheckId id,const Record& r) {
    out.line("{\"type\":\"inventory\",\"check\":"+quote(checkName(id))+",\"name\":"+quote(r.name)+
        ",\"detail\":"+quote(r.detail)+",\"executable\":"+quote(utf8(r.executable.wstring()))+
        ",\"address\":"+quote(r.address)+",\"pid\":"+std::to_string(r.pid)+"}");
}
const char* investigationAdvice(const Indicator& entry, std::string_view grade) {
    if (entry.tier == "reclaimable" || entry.tier == "candiru-ip" || entry.tier == "infrastructure-ip")
        return "Ownership may have changed since the source report. Check its date and corroborate the match with local process or file evidence before acting.";
    if (grade == "known_sample_hash")
        return "Compare the full path with running processes, startup entries and endpoint-protection history. Preserve the file without running it.";
    if (grade == "legitimate_vulnerable_driver_lead")
        return "Verify the driver publisher and installed version against its security advisory. Use the vendor's supported update procedure.";
    if (grade == "observed_connection_reference")
        return "Review the owning process in the connection inventory and compare its executable with file findings.";
    return "Check the browser artifact and profile. Synced history, bookmarks and download references cannot establish execution.";
}
std::string reviewField(const std::string& value) {
    // Keep a field on one line, even when an input record contains control characters.
    if (std::none_of(value.begin(), value.end(), [](unsigned char c) { return c < 32 || c == 127; }))
        return value;
    return quote(value);
}
void writeMatch(Output& out, Output& review,CheckId id,const std::string& artifact,const Indicator& entry,const char* grade) {
    const auto advice = investigationAdvice(entry, grade);
    review.line("Matched: " + reviewField(entry.value) + "\nObserved in: " + reviewField(artifact) + "\nEvidence: " + grade +
        "\nFeed tier: " + reviewField(entry.tier) + "\nSource: " + reviewField(entry.source) + "\nNext step: " + advice + "\n");
    out.line("{\"type\":\"indicator_match\",\"check\":"+quote(checkName(id))+",\"artifact\":"+quote(artifact)+
        ",\"grade\":"+quote(grade)+",\"indicator\":"+quote(entry.value)+",\"tier\":"+quote(entry.tier)+
        ",\"source\":"+quote(entry.source)+",\"next_step\":"+quote(advice)+",\"infection_confirmed\":false}");
}
void fileCheck(const fs::path& path,const Feed& feed,std::atomic_bool& cancel,Progress& p,CheckProgress& c,Output& details,Output& review,const Pulse& pulse){
    if(!hashCandidate(path)){++c.skipped;return;}
    if(!safePath(path)){if(GetLastError()==ERROR_ACCESS_DENIED)++c.denied;else ++c.skipped;return;}
    Handle input(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(input.value==INVALID_HANDLE_VALUE){if(GetLastError()==ERROR_ACCESS_DENIED)++c.denied;else ++c.errors;return;}
    LARGE_INTEGER size{};
    if(!safeHandle(input.value)||!GetFileSizeEx(input.value,&size)||size.QuadPart<0){++c.errors;return;}
    if(static_cast<std::uint64_t>(size.QuadPart)>maxFile){++c.skipped;return;}
    Hasher hash;std::array<char,65536> buffer{};std::uint64_t total=0;
    while(!cancel){DWORD count=0;if(!ReadFile(input.value,buffer.data(),static_cast<DWORD>(buffer.size()),&count,nullptr)){++c.errors;return;}
        if(!count)break;total+=count;if(total>maxFile){++c.skipped;return;}hash.add(buffer.data(),count);p.bytes+=count;pulse();}
    if(cancel)return;if(total!=static_cast<std::uint64_t>(size.QuadPart)){++c.errors;return;}++c.checked;
    auto found=feed.hashes.find(hash.finish());if(found!=feed.hashes.end()){
        ++c.leads;++p.hashes;writeMatch(details,review,c.id,utf8(path.wstring()),found->second,
            found->second.tier=="vuln-driver"?"legitimate_vulnerable_driver_lead":"known_sample_hash");
    }
}
void browserCheck(const fs::path& path,const Feed& feed,std::atomic_bool& cancel,Progress& p,CheckProgress& c,Output& details,Output& review,const Pulse& pulse){
    auto result=readBrowserArtifact(path,cancel,pulse);
    c.denied+=result.denied;c.errors+=result.errors;c.skipped+=result.skipped;
    if(result.outcome==Outcome::failed&&!result.errors)++c.errors;
    if(result.outcome==Outcome::access_denied&&!result.denied)++c.denied;
    if(result.outcome==Outcome::unsupported&&!result.skipped)++c.skipped;
    if(!result.limitation.empty())details.line("{\"type\":\"coverage_gap\",\"check\":\"browser\",\"detail\":"+quote(result.limitation)+"}");
    c.checked+=result.records.size();
    for(const auto& row:result.records){if(cancel)break;pulse();for(const auto& indicator:feed.domains){
        if(containsDomain(asciiLower(row.host),indicator.value)){
            ++c.leads;++p.references;
            const bool visit=row.kind=="history_record";
            writeMatch(details,review,c.id,utf8(path.wstring()),indicator,visit?"browser_history_record":"browser_reference");
        }
    }}
}
void walk(const fs::path& root,const fs::path& excluded,std::atomic_bool& cancel,CheckProgress& c,const Pulse& pulse,
          const std::function<void(const fs::path&)>& visit){
    std::vector<std::pair<fs::path,unsigned>> pending{{root,0}};std::uint64_t total=0;
    while(!pending.empty()&&!cancel){auto [path,depth]=pending.back();pending.pop_back();pulse();
        if(++total>maxEntries){++c.skipped;break;}if(within(path,excluded))continue;
        if(!safePath(path)){if(GetLastError()==ERROR_ACCESS_DENIED)++c.denied;else ++c.skipped;continue;}
        std::error_code error;
        if(fs::is_directory(path,error)){
            if(depth>=64){++c.skipped;continue;}fs::directory_iterator it(path,error),end;
            if(error){if(error.value()==ERROR_ACCESS_DENIED)++c.denied;else ++c.errors;continue;}
            for(;it!=end&&!cancel;it.increment(error)){
                if(error){++c.errors;break;}if(pending.size()+total>=maxEntries){++c.skipped;break;}
                pending.emplace_back(it->path(),depth+1);
            }if(error)++c.errors;
        }else if(error){++c.errors;}else visit(path);
    }
}
} // namespace

const char* checkName(CheckId id){switch(id){
case CheckId::processes:return "processes";case CheckId::services:return "services";case CheckId::drivers:return "drivers";
case CheckId::startup_registry:return "startup_registry";case CheckId::startup_folders:return "startup_folders";
case CheckId::scheduled_tasks:return "scheduled_tasks";case CheckId::installed_apps:return "installed_apps";
case CheckId::security:return "security";case CheckId::event_logs:return "event_logs";
case CheckId::connections:return "connections";case CheckId::settings:return "settings";case CheckId::devices:return "devices";case CheckId::files:return "files";case CheckId::browser:return "browser";
default:return "unknown";}}
const char* outcomeName(Outcome o){switch(o){case Outcome::pending:return "pending";case Outcome::running:return "running";
case Outcome::checked_no_matches:return "checked_no_matches";case Outcome::leads:return "leads";case Outcome::partial:return "partial";
case Outcome::access_denied:return "access_denied";case Outcome::unsupported:return "unsupported";case Outcome::failed:return "failed";case Outcome::cancelled:return "cancelled";default:return "failed";}}
std::vector<CheckId> systemChecks(){return {CheckId::processes,CheckId::services,CheckId::drivers,CheckId::startup_registry,
    CheckId::startup_folders,CheckId::scheduled_tasks,CheckId::installed_apps,CheckId::security,CheckId::event_logs,CheckId::connections,CheckId::devices};}
bool safeLocalPath(const fs::path& path,bool allowMissing){return safePath(path,allowMissing);}
std::string toUtf8(const std::wstring& text){return utf8(text);}
std::wstring fromUtf8(const std::string& text){if(text.empty())return {};auto size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(!size)throw std::runtime_error("invalid UTF8");std::wstring result(size,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),size);return result;}
std::string jsonQuote(const std::string& text){return quote(text);}
const char* stateName(State state){switch(state){case State::idle:return "idle";case State::running:return "running";case State::completed:return "completed";case State::cancelled:return "cancelled";default:return "failed";}}
bool validRunId(const std::string& id){if(id.size()!=38||id.front()!='{'||id.back()!='}')return false;
    for(size_t n=1;n<37;++n){if(n==9||n==14||n==19||n==24){if(id[n]!='-')return false;}else if(!std::isxdigit(static_cast<unsigned char>(id[n])))return false;}return true;}
std::string filteredJson(const Progress& p){
    std::string out="{\"schema\":1,\"state\":"+quote(stateName(p.state))+",\"mode\":"+quote(p.mode==Mode::folder?"folder":"system")+
        ",\"fixture\":"+(p.fixture?"true":"false")+",\"current_check\":"+quote(checkName(p.current));
    if(validRunId(p.runId))out+=",\"run_id\":"+quote(p.runId);
    out+=",\"checked\":"+std::to_string(p.checked)+",\"skipped\":"+std::to_string(p.skipped)+",\"hash_leads\":"+std::to_string(p.hashes)+
        ",\"reference_leads\":"+std::to_string(p.references)+",\"bytes_read\":"+std::to_string(p.bytes)+",\"elapsed_seconds\":"+std::to_string(p.elapsedSeconds)+
        ",\"clean_bill_of_health\":false,\"checks\":[";
    bool first=true;for(const auto& c:p.checks){if(!first)out+=",";first=false;
        out+="{\"id\":"+quote(checkName(c.id))+",\"outcome\":"+quote(outcomeName(c.outcome))+",\"checked\":"+std::to_string(c.checked)+
            ",\"leads\":"+std::to_string(c.leads)+",\"skipped\":"+std::to_string(c.skipped)+",\"denied\":"+std::to_string(c.denied)+",\"errors\":"+std::to_string(c.errors)+"}";}
    return out+"]}";
}
void scan(const Options& options,std::atomic_bool& cancel,const Observer& observer){
    Progress p;p.state=State::running;p.mode=options.mode;p.fixture=!options.fixtureRoot.empty();
    if(p.mode==Mode::system){
        for(auto id:systemChecks())p.checks.push_back({id});
        if(options.securitySettings)p.checks.push_back({CheckId::settings});
    }
    p.checks.push_back({CheckId::files});p.checks.push_back({CheckId::browser});
    std::unique_ptr<Output> events;fs::path run;ULONGLONG started=GetTickCount64(),last=0;
    auto publish=[&](bool force=false){p.checked=0;p.skipped=0;for(const auto& c:p.checks){p.checked+=c.checked;p.skipped+=c.skipped+c.denied+c.errors;}
        p.elapsedSeconds=(GetTickCount64()-started)/1000;
        if(!run.empty()&&safePath(run/L"cancel.request")&&fs::exists(run/L"cancel.request"))cancel=true;
        if(!force&&GetTickCount64()-last<250)return;last=GetTickCount64();if(events)events->line(filteredJson(p));observer(p);};
    try{
        if(!safePath(options.application))throw std::runtime_error("application path refused");
        if(p.fixture&&!safePath(options.fixtureRoot))throw std::runtime_error("fixture path refused");
        if(options.mode==Mode::folder&&(!safePath(options.target)||(p.fixture&&!within(options.target,options.fixtureRoot))))throw std::runtime_error("target refused");
        auto feed=loadFeed(p.fixture?options.fixtureRoot:options.application);
        GUID id{};if(FAILED(CoCreateGuid(&id)))throw std::runtime_error("run id failed");wchar_t name[40]{};StringFromGUID2(id,name,40);p.runId=utf8(name);
        auto base=options.application/L"findings";if(!safePath(base,true))throw std::runtime_error("output refused");fs::create_directory(base);
        run=base/name;if(!safePath(run,true)||!fs::create_directory(run))throw std::runtime_error("run refused");
        events=std::make_unique<Output>(run/L"progress.jsonl");Output details(run/L"private-evidence.jsonl");
        Output review(run/L"private-review.txt");
        details.line("{\"type\":\"scope\",\"mode\":"+quote(options.mode==Mode::folder?"folder":"system")+",\"fixture\":"+(p.fixture?"true":"false")+
            ",\"target\":"+quote(utf8(options.target.wstring()))+",\"note\":\"Read-only bounded known-indicator audit. Inventory is not infection. No absence-of-compromise guarantee.\"}");
        std::set<fs::path> candidates;publish(true);
        for(auto& c:p.checks){if(cancel)break;p.current=c.id;c.outcome=Outcome::running;publish(true);
            Pulse pulse=[&]{publish();};
            if(c.id==CheckId::files){
                if(options.mode==Mode::folder||p.fixture){auto root=options.mode==Mode::folder?options.target:options.fixtureRoot/L"files";
                    walk(root,base,cancel,c,pulse,[&](const fs::path& path){fileCheck(path,feed,cancel,p,c,details,review,pulse);});
                }else{for(const auto& path:candidates){if(cancel)break;fileCheck(path,feed,cancel,p,c,details,review,pulse);pulse();}}
            }else if(c.id==CheckId::browser){
                if(!options.browserReferences){c.outcome=Outcome::unsupported;c.skipped=1;details.line("{\"type\":\"coverage_gap\",\"check\":\"browser\",\"detail\":\"Browser checking was not enabled.\"}");}
                else{std::vector<fs::path> roots;
                    if(options.mode==Mode::folder)roots.push_back(options.target);else if(p.fixture)roots.push_back(options.fixtureRoot/L"browser");else roots=discoverBrowserRoots();
                    if(roots.empty()){c.outcome=Outcome::unsupported;++c.skipped;}
                    for(const auto& root:roots){if(cancel)break;walk(root,base,cancel,c,pulse,[&](const fs::path& path){if(browserArtifact(path))browserCheck(path,feed,cancel,p,c,details,review,pulse);});}
                }
            }else{
                Collection result;
                try{result=p.fixture?fixtureCollection(options.fixtureRoot,c.id):collectWindows(c.id,cancel,pulse);}
                catch(...){result.outcome=Outcome::failed;result.errors=1;}
                c.denied=result.denied;c.skipped=result.skipped;c.errors=result.errors;
                if(!result.limitation.empty())details.line("{\"type\":\"coverage_gap\",\"check\":"+quote(checkName(c.id))+",\"detail\":"+quote(result.limitation)+"}");
                if(c.id==CheckId::settings)review.line("WINDOWS SECURITY SETTINGS (configuration only)");
                for(const auto& record:result.records){if(cancel)break;++c.checked;writeRecord(details,c.id,record);
                    if(c.id==CheckId::settings){ review.line(reviewField(record.name) + ": " + reviewField(record.detail)); continue; }
                    if(!record.executable.empty()&&candidates.size()<maxEntries)candidates.insert(record.executable);
                    if(!record.address.empty())for(const auto& indicator:feed.domains)if(containsDomain(asciiLower(record.address),indicator.value)){
                        ++c.leads;++p.references;writeMatch(details,review,c.id,record.address,indicator,"observed_connection_reference");}
                    pulse();}
                if(c.id==CheckId::settings){
                    if(result.skipped || result.errors || result.denied || result.records.empty())
                        review.line("Some settings could not be verified. See per-check coverage.");
                    review.line("");
                }
                if(result.outcome!=Outcome::checked_no_matches&&result.outcome!=Outcome::leads)c.outcome=result.outcome;
                if(result.outcome==Outcome::leads&&!c.leads)c.leads=1;
            }
            if(cancel)c.outcome=Outcome::cancelled;else finish(c);publish(true);
        }
        for(auto& c:p.checks)if(c.outcome==Outcome::pending||c.outcome==Outcome::running)c.outcome=Outcome::cancelled;
        p.state=cancel?State::cancelled:State::completed;
        // Update aggregate counts, write a complete summary, then emit terminal progress.
        p.checked=0;p.skipped=0;for(const auto& c:p.checks){p.checked+=c.checked;p.skipped+=c.skipped+c.denied+c.errors;}
        p.elapsedSeconds=(GetTickCount64()-started)/1000;
        Output summary(run/L"summary.json");summary.line(filteredJson(p));publish(true);
    }catch(...){p.state=State::failed;for(auto& c:p.checks)if(c.outcome==Outcome::running)c.outcome=Outcome::failed;
        try{if(!run.empty()){Output summary(run/L"summary.json");summary.line(filteredJson(p));}}catch(...){}
        try{publish(true);}catch(...){observer(p);}
    }
}

std::string control(const fs::path& application,const std::string& action,const std::string& runId){
    try{
        if(!validRunId(runId)||(action!="status"&&action!="summary"&&action!="cancel"))throw std::runtime_error("bad command");
        auto folder=application/L"findings"/fromUtf8(runId);if(!safePath(folder))throw std::runtime_error("run refused");
        std::string raw;
        if(action=="summary")raw=readBounded(folder/L"summary.json",65536);
        else raw=readTail(folder/L"progress.jsonl",65536);
        auto doc=json::parse(raw);Progress p;p.runId=runId;
        if(doc.at("schema").uint()!=1)throw std::runtime_error("unknown schema");
        auto state=doc.at("state").string();bool valid=false;
        for(auto v:{State::idle,State::running,State::completed,State::cancelled,State::failed})if(state==stateName(v)){p.state=v;valid=true;}
        if(!valid||doc.at("run_id").string()!=runId)throw std::runtime_error("invalid state");
        auto mode=doc.at("mode").string();if(mode!="system"&&mode!="folder")throw std::runtime_error("invalid mode");p.mode=mode=="folder"?Mode::folder:Mode::system;
        if(doc.at("fixture").type!=json::Value::Type::boolean)throw std::runtime_error("invalid fixture flag");
        p.fixture=doc.at("fixture").text=="true";
        p.current=parseCheck(doc.at("current_check").string());p.checked=doc.at("checked").uint();p.skipped=doc.at("skipped").uint();
        p.hashes=doc.at("hash_leads").uint();p.references=doc.at("reference_leads").uint();p.bytes=doc.at("bytes_read").uint();p.elapsedSeconds=doc.at("elapsed_seconds").uint();
        auto checks=doc.at("checks");if(checks.type!=json::Value::Type::array||checks.items.size()>14)throw std::runtime_error("check limit");
        std::set<CheckId> seen;for(const auto& row:checks.items){CheckProgress c;c.id=parseCheck(row.at("id").string());if(!seen.insert(c.id).second)throw std::runtime_error("duplicate check");
            c.outcome=parseOutcome(row.at("outcome").string());c.checked=row.at("checked").uint();c.leads=row.at("leads").uint();c.skipped=row.at("skipped").uint();c.denied=row.at("denied").uint();c.errors=row.at("errors").uint();p.checks.push_back(c);}
        if(action=="cancel"){
            if(p.state!=State::running)throw std::runtime_error("run not active");auto flag=folder/L"cancel.request";
            if(!fs::exists(flag)){Output request(flag);request.line("");}
            return "{\"state\":\"cancel_requested\",\"run_id\":"+quote(runId)+"}";
        }
        return filteredJson(p);
    }catch(...){return "{\"state\":\"failed\",\"error\":\"control_request_refused\"}";}
}
} // namespace xa
