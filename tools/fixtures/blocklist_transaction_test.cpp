#include "blocklist_helpers.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

struct FakeStorage;

struct FakeFile {
  FakeStorage* storage = nullptr;
  std::vector<uint8_t>* bytes = nullptr;
  size_t position = 0;
  bool writable = false;
  bool open = false;
  bool shortRead = false;

  FakeFile() = default;
  FakeFile(FakeStorage* owner, std::vector<uint8_t>* data, size_t offset, bool canWrite,
           bool isOpen, bool shouldShortRead)
      : storage(owner), bytes(data), position(offset), writable(canWrite), open(isOpen),
        shortRead(shouldShortRead) {}

  explicit operator bool() const { return open && storage != nullptr && bytes != nullptr; }
  size_t size() const { return bytes ? bytes->size() : 0; }
  bool seek(size_t offset) {
    if (!*this || offset > bytes->size()) return false;
    position = offset;
    return true;
  }
  size_t read(uint8_t* output, size_t length);
  size_t write(const uint8_t* input, size_t length);
  void flush() {}
  void close();
};

struct FakeStorage {
  using File = FakeFile;
  const char* livePath() const { return "/blocklist.bin"; }

  size_t total = 8192;
  size_t metadata = 4;
  std::vector<uint8_t> live;
  std::vector<uint8_t> candidate;
  bool livePresent = true;
  bool candidatePresent = false;
  bool candidateWritableOpen = false;
  bool liveOpen = true;
  bool failOpen = false;
  bool failCandidateReadOpen = false;
  bool failRemove = false;
  bool failRename = false;
  bool failReopen = false;
  size_t writeLimit = static_cast<size_t>(-1);

  size_t totalBytes() const { return total; }
  size_t usedBytes() const {
    return metadata + live.size() + (candidatePresent ? candidate.size() : 0);
  }
  bool exists(const char* path) const {
    return std::strcmp(path, "/blocklist.new") == 0 && candidatePresent;
  }
  bool remove(const char* path) {
    if (std::strcmp(path, "/blocklist.new") != 0) return false;
    if (failRemove) return false;
    candidate.clear();
    candidatePresent = false;
    candidateWritableOpen = false;
    return true;
  }
  File open(const char* path, const char* mode) {
    const bool isCandidate = std::strcmp(path, "/blocklist.new") == 0;
    const bool writing = mode[0] == 'w';
    if (failOpen || (isCandidate && !writing && (candidateWritableOpen || failCandidateReadOpen))) return {};
    if (isCandidate && writing) {
      candidate.clear();
      candidatePresent = true;
      candidateWritableOpen = true;
      return File{this, &candidate, 0, true, true, false};
    }
    if (isCandidate && !candidatePresent) return {};
    if (std::strcmp(path, livePath()) == 0 && !livePresent) return {};
    return File{this, std::strcmp(path, livePath()) == 0 ? &live : &candidate, 0, false, true, false};
  }
  bool rename(const char* from, const char* to) {
    if (failRename || !candidatePresent || std::strcmp(from, "/blocklist.new") != 0 ||
        std::strcmp(to, livePath()) != 0) return false;
    live = candidate;
    livePresent = true;
    candidate.clear();
    candidatePresent = false;
    candidateWritableOpen = false;
    return true;
  }
  void closeLive() { liveOpen = false; }
  bool reopenLiveAndValidate(size_t hashBytes = 5,
                             blocklist::ValidationHook hook = nullptr) {
    if (failReopen) { liveOpen = false; return false; }
    File file = open(livePath(), "r");
    if (!file) { liveOpen = false; return false; }
    const blocklist::ValidationResult result = blocklist::validateSorted(file, hashBytes, hook);
    file.close();
    liveOpen = result.ok;
    return result.ok;
  }
};

size_t FakeFile::read(uint8_t* output, size_t length) {
  if (!*this || writable || position >= bytes->size()) return 0;
  const size_t available = bytes->size() - position;
  size_t amount = available < length ? available : length;
  if (shortRead && amount > 0) --amount;
  std::copy(bytes->begin() + position, bytes->begin() + position + amount, output);
  position += amount;
  return amount;
}

size_t FakeFile::write(const uint8_t* input, size_t length) {
  if (!*this || !writable) return 0;
  const size_t amount = length < storage->writeLimit ? length : storage->writeLimit;
  storage->candidate.insert(storage->candidate.end(), input, input + amount);
  position += amount;
  return amount;
}

void FakeFile::close() {
  if (!open) return;
  if (writable) storage->candidateWritableOpen = false;
  open = false;
}

static std::vector<uint8_t> records(std::initializer_list<uint64_t> values) {
  std::vector<uint8_t> result;
  for (uint64_t value : values) {
    for (size_t byte = 0; byte < 5; ++byte) result.push_back(static_cast<uint8_t>(value >> (byte * 8)));
  }
  return result;
}

static void expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    std::abort();
  }
}

static size_t validationHookCalls = 0;
static size_t validationHookLastRecord = 0;
static void countValidationHook(size_t recordsValidated) {
  ++validationHookCalls;
  validationHookLastRecord = recordsValidated;
}

static std::vector<uint8_t> longRecords(size_t count) {
  std::vector<uint8_t> result;
  result.reserve(count * 5);
  for (size_t value = 1; value <= count; ++value) {
    for (size_t byte = 0; byte < 5; ++byte)
      result.push_back(static_cast<uint8_t>(static_cast<uint64_t>(value) >> (byte * 8)));
  }
  return result;
}

static void validation_cases() {
  FakeStorage storage;
  storage.live = records({1, 9, 100});
  FakeFile valid = storage.open(storage.livePath(), "r");
  expect(blocklist::validateSorted(valid).ok, "valid sorted 5-byte input");

  storage.live.clear();
  FakeFile empty = storage.open(storage.livePath(), "r");
  expect(!blocklist::validateSorted(empty).ok, "empty input rejected");
  storage.live = {1, 2, 3, 4, 5, 6};
  FakeFile misaligned = storage.open(storage.livePath(), "r");
  expect(blocklist::validateSorted(misaligned).failure == blocklist::Failure::length, "misaligned input rejected");
  storage.live = records({1, 9, 9});
  FakeFile duplicate = storage.open(storage.livePath(), "r");
  expect(blocklist::validateSorted(duplicate).failure == blocklist::Failure::order, "duplicate rejected");
  storage.live = records({9, 1});
  FakeFile descending = storage.open(storage.livePath(), "r");
  expect(blocklist::validateSorted(descending).failure == blocklist::Failure::order, "descending input rejected");
  storage.live = records({1});
  FakeFile shortRead = storage.open(storage.livePath(), "r");
  shortRead.shortRead = true;
  expect(blocklist::validateSorted(shortRead).failure == blocklist::Failure::read, "short read rejected");

  storage.live = longRecords(1024);
  FakeFile longInput = storage.open(storage.livePath(), "r");
  validationHookCalls = 0;
  validationHookLastRecord = 0;
  const blocklist::ValidationResult longResult =
      blocklist::validateSorted(longInput, 5, countValidationHook);
  expect(longResult.ok && longResult.records == 1024 && longResult.bytes == 1024 * 5,
         "cooperative validation preserves long-stream result");
  expect(validationHookCalls == 4 && validationHookLastRecord == 1024,
         "cooperative validation yields every 256 records");
}

static FakeStorage makeStorage() {
  FakeStorage storage;
  storage.live = records({10, 20});
  return storage;
}

static void failure_preserves_old_list() {
  {
    FakeStorage storage = makeStorage();
    storage.failOpen = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    expect(!transaction.begin(10), "open failure rejected");
    expect(storage.live == records({10, 20}) && storage.liveOpen, "open failure preserves live");
  }
  {
    FakeStorage storage = makeStorage();
    storage.writeLimit = 2;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    expect(transaction.begin(10), "write failure setup");
    const std::vector<uint8_t> data = records({30, 40});
    expect(!transaction.write(data.data(), data.size()), "short write rejected");
    expect(storage.live == records({10, 20}) && storage.liveOpen && !storage.candidatePresent,
           "write failure preserves live and removes candidate");
  }
  {
    FakeStorage storage = makeStorage();
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> invalid = records({30, 30});
    expect(transaction.begin(invalid.size()) && transaction.write(invalid.data(), invalid.size()), "validation failure setup");
    expect(!transaction.finish(invalid.size()), "invalid sorted candidate rejected by transaction");
    expect(storage.live == records({10, 20}) && storage.liveOpen && !storage.candidatePresent,
           "validation failure preserves live and removes candidate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failRename = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "rename failure setup");
    expect(!transaction.finish(data.size()), "rename failure rejected");
    expect(storage.live == records({10, 20}) && storage.liveOpen && !storage.candidatePresent,
           "rename failure preserves live and removes candidate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failCandidateReadOpen = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "candidate validation open failure setup");
    expect(!transaction.finish(data.size()) && transaction.failure() == blocklist::Failure::open &&
               transaction.recoveryStatus() == blocklist::RecoveryStatus::retained,
           "candidate validation open failure keeps original failure after successful recovery");
    expect(std::strcmp(blocklist::failureText(transaction.failure()), "candidate open failed") == 0,
           "candidate validation open failure message is accurate");
    expect(storage.live == records({10, 20}) && storage.liveOpen && !storage.candidatePresent,
           "candidate validation open failure preserves live and removes candidate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failCandidateReadOpen = true;
    storage.failRemove = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "candidate read-open and cleanup failure setup");
    expect(!transaction.finish(data.size()) &&
               transaction.recoveryStatus() == blocklist::RecoveryStatus::cleanup_failed_live_available &&
               transaction.failure() == blocklist::Failure::cleanup,
           "candidate read-open plus cleanup failure reports mixed recovery");
    expect(std::strcmp(blocklist::failureText(transaction.failure()),
                       "candidate cleanup failed; live list remains available; candidate remains") == 0,
           "candidate read-open plus cleanup failure message is accurate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failCandidateReadOpen = true;
    storage.failReopen = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "candidate read-open and reopen failure setup");
    expect(!transaction.finish(data.size()) &&
               transaction.recoveryStatus() == blocklist::RecoveryStatus::reopen_failed &&
               transaction.failure() == blocklist::Failure::reopen,
           "candidate read-open plus reopen failure reports unknown retention");
    expect(std::strcmp(blocklist::failureText(transaction.failure()),
                       "live list reopen failed; retention unknown") == 0,
           "candidate read-open plus reopen failure message is accurate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failCandidateReadOpen = true;
    storage.failRemove = true;
    storage.failReopen = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "candidate read-open combined failure setup");
    expect(!transaction.finish(data.size()) &&
               transaction.recoveryStatus() == blocklist::RecoveryStatus::cleanup_and_reopen_failed &&
               transaction.failure() == blocklist::Failure::cleanup_reopen,
           "candidate read-open combined failure reports both recovery failures");
    expect(std::strcmp(blocklist::failureText(transaction.failure()),
                       "candidate cleanup and live reopen failed; retention unknown") == 0,
           "candidate read-open combined failure message is accurate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failReopen = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "post-rename reopen failure setup");
    expect(!transaction.finish(data.size()) && transaction.failure() == blocklist::Failure::reopen,
           "post-rename reopen failure rejected");
    expect(storage.live == data && !storage.candidatePresent && !storage.liveOpen,
           "post-rename reopen failure leaves new bytes without retention claim");
  }
  {
    FakeStorage storage = makeStorage();
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "abort setup");
    expect(transaction.abort() == blocklist::RecoveryStatus::retained, "abort succeeds");
    expect(storage.live == records({10, 20}) && storage.liveOpen && !storage.candidatePresent,
           "abort preserves live and removes candidate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failRemove = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "failed abort setup");
    const blocklist::RecoveryStatus recovery = transaction.abort();
    expect(recovery == blocklist::RecoveryStatus::cleanup_failed_live_available &&
               transaction.recoveryStatus() == recovery,
           "failed candidate abort reports mixed state");
    expect(std::strcmp(blocklist::recoveryText(recovery),
                       "candidate cleanup failed; live list remains available; candidate remains") == 0,
           "production recovery helper reports mixed state");
    expect(storage.live == records({10, 20}) && storage.liveOpen && storage.candidatePresent,
           "failed candidate cleanup preserves live availability and candidate");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failReopen = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "failed reopen abort setup");
    expect(transaction.abort() == blocklist::RecoveryStatus::reopen_failed,
           "failed live reopen is reported separately");
    expect(std::strcmp(blocklist::recoveryText(blocklist::RecoveryStatus::reopen_failed),
                       "live list reopen failed; retention unknown") == 0,
           "failed reopen does not claim retention");
  }
  {
    FakeStorage storage = makeStorage();
    storage.failReopen = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    const std::vector<uint8_t> data = records({30, 40});
    expect(transaction.begin(data.size()) && transaction.write(data.data(), data.size()), "failed cleanup and reopen setup");
    storage.failRemove = true;
    expect(transaction.abort() == blocklist::RecoveryStatus::cleanup_and_reopen_failed,
           "combined cleanup and reopen failure is reported");
  }
}

static void capacity_and_stale_cases() {
  {
    FakeStorage storage = makeStorage();
    storage.total = storage.usedBytes() + 10;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    expect(!transaction.begin(10), "capacity preflight rejects no-headroom candidate");
    expect(storage.live == records({10, 20}) && storage.liveOpen, "preflight preserves live");
  }
  {
    FakeStorage storage = makeStorage();
    storage.total = 1376256;
    storage.live.assign(700000, 0);
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    expect(!transaction.begin(700000), "C3 cannot fit two 700 kB lists with headroom");
    expect(storage.liveOpen, "C3 capacity rejection preserves live availability");
  }
  {
    FakeStorage storage = makeStorage();
    storage.candidate = records({99});
    storage.candidatePresent = true;
    blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
    expect(transaction.begin(10), "stale candidate is removed before new transaction");
    expect(storage.candidate.empty(), "candidate starts empty after stale removal");
    transaction.abort();
  }
}

static void successful_commit_and_exact_length() {
  FakeStorage storage = makeStorage();
  blocklist::SafeTransaction<FakeStorage> transaction(storage, "/blocklist.new");
  const std::vector<uint8_t> data = records({30, 40, 50});
  expect(transaction.begin(data.size()), "successful transaction begins");
  expect(transaction.write(data.data(), 4), "partial candidate write succeeds");
  expect(transaction.write(data.data() + 4, data.size() - 4), "second candidate write succeeds");
  expect(transaction.finish(data.size()), "successful transaction commits");
  expect(storage.live == data && storage.liveOpen && !storage.candidatePresent, "commit installs candidate");

  blocklist::ExactLength complete(data.size());
  expect(complete.accept(4) && complete.accept(data.size() - 4) && complete.complete(), "known length completes");
  blocklist::ExactLength shortTransfer(data.size());
  expect(shortTransfer.accept(4) && !shortTransfer.complete(), "known length detects short transfer");
  blocklist::ExactLength overlong(data.size());
  expect(!overlong.accept(data.size() + 1), "known length rejects overlong transfer");
}

int main() {
  validation_cases();
  failure_preserves_old_list();
  capacity_and_stale_cases();
  successful_commit_and_exact_length();
  std::cout << "PASS blocklist helper transaction and validation cases\n";
  return 0;
}
