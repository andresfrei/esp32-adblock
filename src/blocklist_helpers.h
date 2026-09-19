#pragma once

#include <stddef.h>
#include <stdint.h>

namespace blocklist {

static const size_t DEFAULT_HASH_BYTES = 5;
static const size_t DEFAULT_METADATA_HEADROOM = 4096;

enum class Failure {
  none,
  stale_candidate,
  capacity,
  open,
  write,
  length,
  read,
  order,
  rename,
  reopen,
  cleanup,
  cleanup_reopen,
  incomplete,
};

enum class RecoveryStatus {
  retained,
  cleanup_failed_live_available,
  reopen_failed,
  cleanup_and_reopen_failed,
};

using ValidationHook = void (*)(size_t recordsValidated);

inline bool recoverySucceeded(RecoveryStatus status) {
  return status == RecoveryStatus::retained;
}

inline const char* recoveryText(RecoveryStatus status) {
  switch (status) {
    case RecoveryStatus::retained: return "live list retained";
    case RecoveryStatus::cleanup_failed_live_available:
      return "candidate cleanup failed; live list remains available; candidate remains";
    case RecoveryStatus::reopen_failed: return "live list reopen failed; retention unknown";
    case RecoveryStatus::cleanup_and_reopen_failed:
      return "candidate cleanup and live reopen failed; retention unknown";
  }
  return "live list recovery status unknown";
}

struct ValidationResult {
  bool ok;
  Failure failure;
  size_t bytes;
  size_t records;
};

inline bool capacityAllows(size_t totalBytes, size_t usedBytes, size_t candidateBytes,
                           size_t metadataHeadroom = DEFAULT_METADATA_HEADROOM) {
  if (usedBytes > totalBytes || candidateBytes > totalBytes - usedBytes) return false;
  const size_t freeBytes = totalBytes - usedBytes;
  return candidateBytes <= freeBytes && metadataHeadroom <= freeBytes - candidateBytes;
}

inline uint64_t littleEndianValue(const uint8_t* record, size_t bytes) {
  uint64_t value = 0;
  for (size_t i = 0; i < bytes; ++i) value |= static_cast<uint64_t>(record[i]) << (i * 8);
  return value;
}

template <typename FileLike>
ValidationResult validateSorted(FileLike& file, size_t hashBytes = DEFAULT_HASH_BYTES,
                                ValidationHook hook = nullptr) {
  ValidationResult result{false, Failure::length, 0, 0};
  if (hashBytes == 0 || hashBytes > sizeof(uint8_t[8])) return result;
  const size_t size = file.size();
  result.bytes = size;
  if (size == 0) return result;
  if (size % hashBytes != 0) return result;
  if (!file.seek(0)) {
    result.failure = Failure::read;
    return result;
  }

  uint8_t record[8] = {};
  uint64_t previous = 0;
  bool havePrevious = false;
  result.records = size / hashBytes;
  static const size_t VALIDATION_YIELD_INTERVAL = 256;
  for (size_t index = 0; index < result.records; ++index) {
    if (file.read(record, hashBytes) != hashBytes) {
      result.ok = false;
      result.failure = Failure::read;
      return result;
    }
    if (hook && ((index + 1) % VALIDATION_YIELD_INTERVAL) == 0) hook(index + 1);
    const uint64_t current = littleEndianValue(record, hashBytes);
    if (havePrevious && current <= previous) {
      result.ok = false;
      result.failure = Failure::order;
      return result;
    }
    previous = current;
    havePrevious = true;
  }
  result.ok = true;
  result.failure = Failure::none;
  return result;
}

template <typename FileLike>
bool writeChunk(FileLike& file, const uint8_t* data, size_t length, size_t& written,
               size_t maximumBytes) {
  if (length > maximumBytes || written > maximumBytes - length) return false;
  if (length != 0 && file.write(data, length) != length) return false;
  written += length;
  return true;
}

struct ExactLength {
  size_t expected;
  size_t received;

  explicit ExactLength(size_t expectedBytes) : expected(expectedBytes), received(0) {}

  bool accept(size_t bytes) {
    if (bytes > expected - received) return false;
    received += bytes;
    return true;
  }

  bool complete() const { return received == expected; }
};

// Storage is deliberately small: the target supplies file and filesystem adapters,
// while this transaction owns candidate cleanup, validation, and commit ordering.
template <typename Storage>
class SafeTransaction {
 public:
  using File = typename Storage::File;

  SafeTransaction(Storage& storage, const char* candidatePath,
                  ValidationHook validationHook = nullptr)
      : storage_(storage), candidatePath_(candidatePath), validationHook_(validationHook),
        active_(false), written_(0), maximumBytes_(0), failure_(Failure::none),
        recoveryStatus_(RecoveryStatus::retained) {}

  bool begin(size_t expectedBytes = 0,
             size_t metadataHeadroom = DEFAULT_METADATA_HEADROOM) {
    failure_ = Failure::none;
    recoveryStatus_ = RecoveryStatus::retained;
    written_ = 0;
    if (storage_.exists(candidatePath_) && !storage_.remove(candidatePath_)) {
      failure_ = Failure::stale_candidate;
      return false;
    }
    const size_t available = storage_.totalBytes() >= storage_.usedBytes()
                                 ? storage_.totalBytes() - storage_.usedBytes()
                                 : 0;
    maximumBytes_ = expectedBytes ? expectedBytes :
        (available > metadataHeadroom ? available - metadataHeadroom : 0);
    if (!capacityAllows(storage_.totalBytes(), storage_.usedBytes(), maximumBytes_,
                        metadataHeadroom)) {
      failure_ = Failure::capacity;
      return false;
    }
    candidate_ = storage_.open(candidatePath_, "w");
    if (!candidate_) {
      failure_ = Failure::open;
      return false;
    }
    active_ = true;
    return true;
  }

  bool write(const uint8_t* data, size_t length) {
    if (!active_ || !writeChunk(candidate_, data, length, written_, maximumBytes_)) {
      failure_ = active_ ? Failure::write : Failure::open;
      applyRecoveryFailure(recoverCandidate());
      return false;
    }
    return true;
  }

  bool finish(size_t expectedBytes = 0, size_t hashBytes = DEFAULT_HASH_BYTES) {
    if (!active_) {
      failure_ = Failure::open;
      return false;
    }
    if (expectedBytes != 0 && written_ != expectedBytes) {
      failure_ = Failure::incomplete;
      applyRecoveryFailure(recoverCandidate());
      return false;
    }
    candidate_.flush();
    candidate_.close();
    active_ = false;

    File check = storage_.open(candidatePath_, "r");
    if (!check) {
      failure_ = Failure::open;
      applyRecoveryFailure(cleanupAndRestore());
      return false;
    }
    const ValidationResult validation = validateSorted(check, hashBytes, validationHook_);
    check.close();
    if (!validation.ok || (expectedBytes != 0 && validation.bytes != expectedBytes)) {
      failure_ = validation.ok ? Failure::incomplete : validation.failure;
      applyRecoveryFailure(cleanupAndRestore());
      return false;
    }

    storage_.closeLive();
    if (!storage_.rename(candidatePath_, storage_.livePath())) {
      failure_ = Failure::rename;
      applyRecoveryFailure(cleanupAndRestore());
      return false;
    }
    if (!storage_.reopenLiveAndValidate(hashBytes, validationHook_)) {
      // The rename may already have succeeded. The old bytes are not promised here.
      failure_ = Failure::reopen;
      return false;
    }
    failure_ = Failure::none;
    return true;
  }

  RecoveryStatus abort() {
    failure_ = Failure::incomplete;
    const RecoveryStatus recovery = recoverCandidate();
    applyRecoveryFailure(recovery);
    return recovery;
  }

  bool active() const { return active_; }
  size_t written() const { return written_; }
  Failure failure() const { return failure_; }
  RecoveryStatus recoveryStatus() const { return recoveryStatus_; }
  size_t maximumBytes() const { return maximumBytes_; }

 private:
  RecoveryStatus recoverCandidate() {
    if (active_) {
      candidate_.close();
      active_ = false;
    }
    const bool removed = storage_.remove(candidatePath_);
    const bool reopened = storage_.reopenLiveAndValidate(DEFAULT_HASH_BYTES, validationHook_);
    if (removed && reopened) recoveryStatus_ = RecoveryStatus::retained;
    else if (!removed && reopened) recoveryStatus_ = RecoveryStatus::cleanup_failed_live_available;
    else if (removed) recoveryStatus_ = RecoveryStatus::reopen_failed;
    else recoveryStatus_ = RecoveryStatus::cleanup_and_reopen_failed;
    return recoveryStatus_;
  }

  RecoveryStatus cleanupAndRestore() { return recoverCandidate(); }

  void applyRecoveryFailure(RecoveryStatus recovery) {
    if (recovery == RecoveryStatus::cleanup_failed_live_available) failure_ = Failure::cleanup;
    else if (recovery == RecoveryStatus::reopen_failed) failure_ = Failure::reopen;
    else if (recovery == RecoveryStatus::cleanup_and_reopen_failed) failure_ = Failure::cleanup_reopen;
  }

  Storage& storage_;
  const char* candidatePath_;
  ValidationHook validationHook_;
  File candidate_;
  bool active_;
  size_t written_;
  size_t maximumBytes_;
  Failure failure_;
  RecoveryStatus recoveryStatus_;
};

inline const char* failureText(Failure failure) {
  switch (failure) {
    case Failure::none: return "ok";
    case Failure::stale_candidate: return "stale candidate cleanup failed";
    case Failure::capacity: return "insufficient filesystem capacity";
    case Failure::open: return "candidate open failed";
    case Failure::write: return "candidate write failed";
    case Failure::length: return "empty or misaligned candidate";
    case Failure::read: return "candidate read failed";
    case Failure::order: return "candidate hashes are not strictly increasing";
    case Failure::rename: return "candidate rename failed; live list retained";
    case Failure::reopen: return "live list reopen failed; retention unknown";
    case Failure::cleanup: return "candidate cleanup failed; live list remains available; candidate remains";
    case Failure::cleanup_reopen: return "candidate cleanup and live reopen failed; retention unknown";
    case Failure::incomplete: return "candidate transfer incomplete or aborted";
  }
  return "blocklist transaction failed";
}

}  // namespace blocklist
