#include "allowlist.h"
#include "dns_query.h"
#include "domain_rules.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

struct Entry {
  std::string value;
  Entry& operator=(const char* text) { value = text; return *this; }
  const char* c_str() const { return value.c_str(); }
};

class FailureString {
 public:
  static bool failReserve;
  static bool forbidAllocation;

  bool reserve(unsigned int size) {
    if (size > value.capacity() && (failReserve || forbidAllocation)) return false;
    value.reserve(size);
    return true;
  }
  FailureString& operator=(const char* text) {
    if (!text || !reserve(std::strlen(text))) { value.clear(); return *this; }
    value = text;
    return *this;
  }
  FailureString& operator=(const FailureString& other) {
    if (!reserve(static_cast<unsigned int>(other.length()))) { value.clear(); return *this; }
    value = other.value;
    return *this;
  }
  FailureString& operator=(FailureString&& other) {
    value = std::move(other.value);
    return *this;
  }
  explicit operator bool() const { return true; }
  const char* c_str() const { return value.c_str(); }
  size_t length() const { return value.length(); }

 private:
  std::string value;
};

bool FailureString::failReserve = false;
bool FailureString::forbidAllocation = false;

struct FakeStorage;
struct FakeFile {
  FakeStorage* storage = nullptr;
  std::vector<uint8_t>* bytes = nullptr;
  size_t position = 0;
  bool writable = false;
  bool open = false;

  FakeFile() = default;
  FakeFile(FakeStorage* owner, std::vector<uint8_t>* data, size_t offset, bool canWrite, bool isOpen)
      : storage(owner), bytes(data), position(offset), writable(canWrite), open(isOpen) {}

  explicit operator bool() const { return open && storage && bytes; }
  int available() const { return *this ? static_cast<int>(bytes->size() - position) : 0; }
  int read();
  size_t write(const uint8_t* data, size_t length);
  void flush();
  void close();
};

struct FakeStorage {
  std::vector<uint8_t> live;
  std::vector<uint8_t> candidate;
  bool candidatePresent = false;
  bool failOpen = false;
  bool failWrite = false;
  bool failRename = false;
  bool flushed = false;

  bool exists(const char* path) const {
    return std::strcmp(path, "/allowlist.new") == 0 && candidatePresent;
  }
  bool remove(const char* path) {
    if (std::strcmp(path, "/allowlist.new") != 0) return false;
    candidate.clear();
    candidatePresent = false;
    return true;
  }
  FakeFile open(const char* path, const char* mode) {
    const bool temp = std::strcmp(path, "/allowlist.new") == 0;
    const bool writing = mode[0] == 'w';
    if (failOpen || (!writing && temp && !candidatePresent)) return {};
    if (temp && writing) {
      candidate.clear();
      candidatePresent = true;
      return FakeFile{this, &candidate, 0, true, true};
    }
    if (std::strcmp(path, "/allowlist.txt") == 0)
      return FakeFile{this, &live, 0, false, true};
    return {};
  }
  bool rename(const char* from, const char* to) {
    if (failRename || std::strcmp(from, "/allowlist.new") != 0 ||
        std::strcmp(to, "/allowlist.txt") != 0 || !candidatePresent) return false;
    live = candidate;
    candidate.clear();
    candidatePresent = false;
    return true;
  }
};

int FakeFile::read() {
  if (!*this || position >= bytes->size()) return -1;
  return (*bytes)[position++];
}
size_t FakeFile::write(const uint8_t* data, size_t length) {
  if (!*this || !writable || storage->failWrite) return 0;
  bytes->insert(bytes->end(), data, data + length);
  position += length;
  return length;
}
void FakeFile::flush() { if (*this) storage->flushed = true; }
void FakeFile::close() { open = false; }

static void expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    std::abort();
  }
}

static std::string normalized(const char* input) {
  char output[domain_rules::MAX_DOMAIN_LENGTH + 1];
  expect(domain_rules::normalize(input, output, sizeof(output)), "normalization succeeds");
  return output;
}

static bool matchesSuffix(const char* suffix, size_t length, void* context) {
  const std::string* denied = static_cast<const std::string*>(context);
  return denied->compare(0, denied->size(), suffix, length) == 0 && denied->size() == length;
}

static void normalization_cases() {
  expect(normalized("  WWW.Example.COM.  ") == "example.com", "case, www, trim, and terminal dot normalize together");
  expect(normalized("WWW.WWW.Example.com") == "www.example.com", "only one leading www is removed");
  expect(normalized("WWW.XN--BCHER-KVA.Example") == "xn--bcher-kva.example", "ASCII punycode labels remain valid");
  expect(!domain_rules::normalize("", nullptr, 0), "empty input rejected");
  const char* invalid[] = {
      "example.com/path", "https://example.com", "foo bar.example", "*.example.com",
      "foo..example.com", "-foo.example.com", "foo-.example.com", "foo._bar.example",
      "192.168.1.1", "foo.example.com\x01", "foo.example.com:443", "foo.example.com?x"};
  for (const char* value : invalid) {
    char output[domain_rules::MAX_DOMAIN_LENGTH + 1];
    expect(!domain_rules::normalize(value, output, sizeof(output)), "invalid domain rejected");
  }
  std::string longLabel(64, 'a');
  char output[domain_rules::MAX_DOMAIN_LENGTH + 1];
  expect(!domain_rules::normalize((longLabel + ".example").c_str(), output, sizeof(output)), "label over 63 rejected");
  const std::string maxDomain = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                                 std::string(63, 'c') + "." + std::string(61, 'd');
  expect(maxDomain.size() == 253 && domain_rules::normalize(maxDomain.c_str(), output, sizeof(output)),
         "253-byte domain accepted at exact boundary");
  expect(!domain_rules::normalize((maxDomain + "a").c_str(), output, sizeof(output)), "254-byte domain rejected");
}

static std::string domain_of_length(size_t length) {
  expect(length >= 249 && length <= 254, "test domain length is within parser test bounds");
  return std::string(63, 'a') + "." + std::string(63, 'b') + "." +
         std::string(63, 'c') + "." + std::string(length - 192, 'd');
}

static std::vector<uint8_t> query_packet(const std::string& domain) {
  std::vector<uint8_t> packet(12, 0);
  size_t begin = 0;
  while (begin < domain.size()) {
    const size_t dot = domain.find('.', begin);
    const size_t end = dot == std::string::npos ? domain.size() : dot;
    packet.push_back(static_cast<uint8_t>(end - begin));
    packet.insert(packet.end(), domain.begin() + begin, domain.begin() + end);
    begin = end + 1;
  }
  packet.push_back(0);
  packet.push_back(0);
  packet.push_back(1);
  packet.push_back(0);
  packet.push_back(1);
  return packet;
}

static void parser_cases() {
  for (size_t length = 249; length <= 253; ++length) {
    const std::string domain = domain_of_length(length);
    const std::vector<uint8_t> packet = query_packet(domain);
    char output[domain_rules::MAX_DOMAIN_LENGTH + 1];
    uint16_t qtype = 0;
    int qend = 0;
    expect(dns_query::parseQuery(packet.data(), static_cast<int>(packet.size()), output,
                                  sizeof(output), &qtype, &qend) == length &&
               std::strcmp(output, domain.c_str()) == 0 && qtype == 1 &&
               qend == static_cast<int>(packet.size()),
           "production parser accepts 249 through 253-byte names with a NUL bound");
  }
  const std::string overlong = domain_of_length(254);
  const std::vector<uint8_t> overlongPacket = query_packet(overlong);
  char output[domain_rules::MAX_DOMAIN_LENGTH + 1];
  uint16_t qtype = 0;
  int qend = 0;
  expect(dns_query::parseQuery(overlongPacket.data(), static_cast<int>(overlongPacket.size()), output,
                               sizeof(output), &qtype, &qend) == 0,
         "production parser rejects a 254-byte name");

  const std::vector<uint8_t> label63 = query_packet(std::string(63, 'a') + ".example.com");
  expect(dns_query::parseQuery(label63.data(), static_cast<int>(label63.size()), output,
                               sizeof(output), &qtype, &qend) != 0,
         "production parser accepts a 63-byte label");
  const std::vector<uint8_t> label64 = query_packet(std::string(64, 'a') + ".example.com");
  expect(dns_query::parseQuery(label64.data(), static_cast<int>(label64.size()), output,
                               sizeof(output), &qtype, &qend) == 0,
         "production parser rejects a 64-byte label");

  const std::vector<uint8_t> complete = query_packet("example.com");
  std::vector<uint8_t> compressed = complete;
  compressed[12] = 0xc0;
  compressed[13] = 0x0c;
  expect(dns_query::parseQuery(compressed.data(), static_cast<int>(compressed.size()), output,
                               sizeof(output), &qtype, &qend) == 0,
         "compressed question names remain rejected by the uncompressed parser");
  for (size_t length = 0; length < complete.size(); ++length) {
    expect(dns_query::parseQuery(complete.data(), static_cast<int>(length), output,
                                 sizeof(output), &qtype, &qend) == 0,
           "truncated DNS packets are rejected without reading past the packet");
  }

  const std::string maxDomain = domain_of_length(253);
  const std::vector<uint8_t> maxPacket = query_packet(maxDomain);
  expect(dns_query::parseQuery(maxPacket.data(), static_cast<int>(maxPacket.size()), output,
                               sizeof(output), &qtype, &qend) == maxDomain.size(),
         "maximum production query remains available for exact matching");
  Entry allowEntries[1];
  allowEntries[0] = maxDomain.c_str();
  expect(allowlist::contains(allowEntries, 1, output),
         "a normalized 253-byte query matches the exact allowlist entry");

  const std::vector<uint8_t> wwwPacket = query_packet("www.Example.com");
  expect(dns_query::parseQuery(wwwPacket.data(), static_cast<int>(wwwPacket.size()), output,
                               sizeof(output), &qtype, &qend) == std::strlen("example.com") &&
             std::strcmp(output, "example.com") == 0 &&
             normalized("WWW.Example.com") == output,
         "parser strips one leading www exactly like normalization");
}

static void transaction_commit_cases() {
  FailureString::failReserve = true;
  FailureString addEntries[2];
  size_t addCount = 0;
  int addWrites = 0;
  int addRenames = 0;
  expect(!allowlist::commitAdd<FailureString>(
             addEntries, addCount, 2, "new-long.example.com",
             [&](const char*) { ++addWrites; ++addRenames; return true; }) &&
             addCount == 0 && addWrites == 0 && addRenames == 0,
         "add preallocation failure avoids file writes and rename");
  FailureString::failReserve = false;

  std::vector<std::string> addDisk;
  addEntries[0] = "old.example.com";
  addCount = 1;
  addDisk.push_back(addEntries[0].c_str());
  FailureString::forbidAllocation = false;
  expect(allowlist::commitAdd<FailureString>(
             addEntries, addCount, 2, "new-long.example.com",
             [&](const char* candidate) {
               expect(std::strcmp(addEntries[0].c_str(), "old.example.com") == 0,
                      "add persists before active array mutation");
               addDisk.push_back(candidate);
               ++addWrites;
               ++addRenames;
               FailureString::forbidAllocation = true;
               return true;
             }) && addCount == 2 && addDisk.size() == 2 &&
             std::strcmp(addEntries[1].c_str(), addDisk[1].c_str()) == 0,
         "successful add keeps active memory and disk in sync without post-save allocation");
  FailureString::forbidAllocation = false;

  FailureString removeEntries[3];
  removeEntries[0] = "short.example";
  removeEntries[1] = "longer-source.example.com";
  removeEntries[2] = "tail.example.com";
  size_t removeCount = 3;
  int removeWrites = 0;
  int removeRenames = 0;
  FailureString::failReserve = true;
  expect(!allowlist::commitRemove(
             removeEntries, removeCount, 0,
             [&](size_t) { ++removeWrites; ++removeRenames; return true; }) &&
             removeCount == 3 && removeWrites == 0 && removeRenames == 0,
         "remove preallocation failure avoids file writes and rename");
  FailureString::failReserve = false;

  std::vector<std::string> removeDisk;
  removeDisk.push_back(removeEntries[1].c_str());
  removeDisk.push_back(removeEntries[2].c_str());
  expect(allowlist::commitRemove(
             removeEntries, removeCount, 0,
             [&](size_t skipIndex) {
               expect(skipIndex == 0 && std::strcmp(removeEntries[0].c_str(), "short.example") == 0,
                      "remove persists before active array shift");
               ++removeWrites;
               ++removeRenames;
               FailureString::forbidAllocation = true;
               return true;
             }) && removeCount == removeDisk.size() &&
             std::strcmp(removeEntries[0].c_str(), removeDisk[0].c_str()) == 0 &&
             std::strcmp(removeEntries[1].c_str(), removeDisk[1].c_str()) == 0,
         "successful remove keeps shifted memory and disk in sync without allocation");
  FailureString::forbidAllocation = false;
}

static void precedence_and_suffix_cases() {
  const std::string flashDenied = "example.com";
  expect(domain_rules::suffixDenied("ads.example.com", matchesSuffix,
                                    const_cast<std::string*>(&flashDenied)),
         "suffix walk finds a deny with a flash/custom-independent matcher");
  const std::string singleLabelDenied = "com";
  expect(!domain_rules::suffixDenied("example.com", matchesSuffix,
                                     const_cast<std::string*>(&singleLabelDenied)),
         "existing suffix walk preserves the final single-label stop boundary");
  expect(!domain_rules::shouldBlock(false, true, true, true), "exact allow wins manual and flash deny");
  expect(!domain_rules::shouldBlock(false, true, true, false), "exact allow remains harmless without flash list");
  expect(domain_rules::shouldBlock(true, false, true, false), "client ban wins while paused and allowed");
  expect(!domain_rules::shouldBlock(false, false, false, true), "pause bypasses domain rules");
  expect(domain_rules::shouldBlock(false, true, false, true), "nonmatching subdomain remains denied");
  expect(domain_rules::exactMatch("example.com", "example.com"), "normalized query matches normalized allow entry");
  expect(!domain_rules::exactMatch("foo.example.com", "example.com"), "allowlist does not perform suffix matching");
  expect(domain_rules::shouldBlock(false, true, false, true), "manual deny works with an empty flash list");
}

static void persistence_cases() {
  FakeStorage storage;
  std::vector<Entry> entries;
  entries.push_back(Entry{"example.com"});
  entries.push_back(Entry{"ads.example.com"});
  expect(allowlist::save(storage, "/allowlist.txt", "/allowlist.new", entries, entries.size()),
         "initial allowlist save succeeds");
  expect(storage.flushed, "candidate is flushed before rename");

  std::vector<Entry> loaded(allowlist::MAX_ENTRIES);
  FakeFile persisted = storage.open("/allowlist.txt", "r");
  const size_t loadedCount = allowlist::load(persisted, loaded);
  expect(loadedCount == 2 && std::strcmp(loaded[0].c_str(), "example.com") == 0 &&
             std::strcmp(loaded[1].c_str(), "ads.example.com") == 0,
         "restart load reproduces the persisted normalized entries");

  const std::vector<uint8_t> oldBytes = storage.live;
  storage.failWrite = true;
  entries.push_back(Entry{"new.example.com"});
  expect(!allowlist::save(storage, "/allowlist.txt", "/allowlist.new", entries, entries.size()),
         "write failure rejects save");
  expect(storage.live == oldBytes && entries.size() == 3, "write failure preserves persisted and active lists");
  storage.failWrite = false;
  storage.failRename = true;
  expect(!allowlist::save(storage, "/allowlist.txt", "/allowlist.new", entries, entries.size()),
         "rename failure rejects save");
  expect(storage.live == oldBytes, "rename failure preserves persisted list");
  storage.failRename = false;
  expect(allowlist::save(storage, "/allowlist.txt", "/allowlist.new", entries, entries.size(), nullptr, 1),
         "deletion candidate saves before active deletion");
  loaded.assign(allowlist::MAX_ENTRIES, Entry{});
  persisted = storage.open("/allowlist.txt", "r");
  expect(allowlist::load(persisted, loaded) == 2 &&
             std::strcmp(loaded[0].c_str(), "example.com") == 0 &&
             std::strcmp(loaded[1].c_str(), "new.example.com") == 0,
         "deletion candidate commits the remaining entries");

  std::vector<Entry> full(allowlist::MAX_ENTRIES);
  for (size_t i = 0; i < full.size(); ++i) full[i] = (std::string("d") + std::to_string(i) + ".example").c_str();
  expect(allowlist::save(storage, "/allowlist.txt", "/allowlist.new", full, full.size()),
         "exact 200-entry boundary persists");
  persisted = storage.open("/allowlist.txt", "r");
  loaded.assign(allowlist::MAX_ENTRIES, Entry{});
  expect(allowlist::load(persisted, loaded) == allowlist::MAX_ENTRIES, "exact max count loads without truncation");

  const std::string malformedLines = "example.com\nWWW.Example.com\nbad/path\n";
  storage.live.assign(malformedLines.begin(), malformedLines.end());
  persisted = storage.open("/allowlist.txt", "r");
  loaded.assign(allowlist::MAX_ENTRIES, Entry{});
  expect(allowlist::load(persisted, loaded) == 1 &&
             std::strcmp(loaded[0].c_str(), "example.com") == 0 &&
             allowlist::contains(loaded, 1, "example.com"),
         "restart skips malformed and normalized duplicate lines without duplicating active state");
}

int main() {
  normalization_cases();
  parser_cases();
  transaction_commit_cases();
  precedence_and_suffix_cases();
  persistence_cases();
  std::cout << "PASS domain normalization, precedence, bounded persistence, and restart load\n";
  return 0;
}
