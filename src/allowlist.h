#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "domain_rules.h"

namespace allowlist {

static const size_t MAX_ENTRIES = 200;
static const size_t NO_SKIP = static_cast<size_t>(-1);

// File is deliberately a small Arduino/File-like interface. The same helper is
// exercised by the host fixture with a fake filesystem, without duplicating the
// persistence algorithm in tests.
template <typename File, typename EntryArray>
size_t load(File& file, EntryArray& entries, size_t capacity = MAX_ENTRIES) {
  size_t count = 0;
  char line[domain_rules::MAX_DOMAIN_LENGTH + 2];
  size_t length = 0;
  bool overflow = false;

  const auto acceptLine = [&](void) {
    if (overflow || length == 0) {
      length = 0;
      overflow = false;
      return;
    }
    line[length] = '\0';
    char normalized[domain_rules::MAX_DOMAIN_LENGTH + 1];
    if (domain_rules::normalize(line, normalized, sizeof(normalized))) {
      bool duplicate = false;
      for (size_t i = 0; i < count; ++i) {
        if (strcmp(entries[i].c_str(), normalized) == 0) {
          duplicate = true;
          break;
        }
      }
      if (!duplicate && count < capacity) entries[count++] = normalized;
    }
    length = 0;
    overflow = false;
  };

  while (file.available()) {
    const int value = file.read();
    if (value < 0) break;
    if (value == '\n') {
      acceptLine();
    } else if (!overflow) {
      if (length < sizeof(line) - 1) line[length++] = static_cast<char>(value);
      else overflow = true;
    }
  }
  if (length > 0 || overflow) acceptLine();
  return count;
}

template <typename EntryArray>
bool contains(const EntryArray& entries, size_t count, const char* normalized) {
  if (!normalized) return false;
  for (size_t i = 0; i < count; ++i) {
    if (strcmp(entries[i].c_str(), normalized) == 0) return true;
  }
  return false;
}

// Prepare every String allocation before persistence. The commit helpers only
// mutate the active array after the caller's persistence callback succeeds.
template <typename Entry>
bool prepareEntry(Entry& entry, const char* value) {
  if (!value) return false;
  const size_t length = strlen(value);
  if (!entry.reserve(static_cast<unsigned int>(length))) return false;
  entry = value;
  return static_cast<bool>(entry) && entry.c_str() && strcmp(entry.c_str(), value) == 0;
}

template <typename EntryArray>
bool prepareRemoval(EntryArray& entries, size_t count, size_t skipIndex) {
  if (skipIndex >= count) return false;
  for (size_t i = skipIndex; i + 1 < count; ++i) {
    if (!entries[i].reserve(static_cast<unsigned int>(entries[i + 1].length()))) return false;
  }
  return true;
}

template <typename Entry, typename EntryArray, typename Persist>
bool commitAdd(EntryArray& entries, size_t& count, size_t capacity,
               const char* value, Persist persist) {
  if (count >= capacity) return false;
  Entry candidate;
  if (!prepareEntry(candidate, value)) return false;
  if (!persist(candidate.c_str())) return false;
  entries[count] = static_cast<Entry&&>(candidate);
  ++count;
  return true;
}

template <typename EntryArray, typename Persist>
bool commitRemove(EntryArray& entries, size_t& count, size_t skipIndex, Persist persist) {
  if (!prepareRemoval(entries, count, skipIndex)) return false;
  if (!persist(skipIndex)) return false;
  for (size_t i = skipIndex; i + 1 < count; ++i) entries[i] = entries[i + 1];
  --count;
  return true;
}

template <typename File>
bool writeLine(File& file, const char* value) {
  const size_t length = strlen(value);
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(value);
  const uint8_t newline = '\n';
  return file.write(bytes, length) == length && file.write(&newline, 1) == 1;
}

// Write a candidate sequentially. skipIndex supports deletion and appendValue
// supports insertion without changing the active array before rename commits.
template <typename Storage, typename EntryArray>
bool save(Storage& storage, const char* livePath, const char* tempPath,
          const EntryArray& entries, size_t count,
          const char* appendValue = nullptr, size_t skipIndex = NO_SKIP) {
  if (storage.exists(tempPath) && !storage.remove(tempPath)) return false;
  auto file = storage.open(tempPath, "w");
  if (!file) return false;

  bool ok = true;
  for (size_t i = 0; i < count && ok; ++i) {
    if (i != skipIndex) ok = writeLine(file, entries[i].c_str());
  }
  if (ok && appendValue) ok = writeLine(file, appendValue);
  file.flush();
  file.close();
  if (!ok) {
    if (storage.exists(tempPath)) storage.remove(tempPath);
    return false;
  }
  if (!storage.rename(tempPath, livePath)) {
    if (storage.exists(tempPath)) storage.remove(tempPath);
    return false;
  }
  return true;
}

}  // namespace allowlist
