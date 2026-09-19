#pragma once

#include <cstddef>
#include <cstdint>

// Persistent upstream DNS configuration is deliberately independent from the
// filesystem. The helper has no Arduino dependencies so its validation and
// store-then-apply ordering can be exercised on the host.
namespace upstream_config {

static constexpr const char* NAMESPACE = "upstream";
static constexpr const char* KEY = "ip";
static constexpr const char* DEFAULT_TEXT = "9.9.9.9";
static constexpr size_t TEXT_CAPACITY = 16;  // longest dotted IPv4 plus NUL

struct IPv4 {
  uint8_t octets[4];

  IPv4() : octets{0, 0, 0, 0} {}
  IPv4(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth)
      : octets{first, second, third, fourth} {}
};

enum class Error {
  none,
  empty,
  malformed,
  unspecified,
  broadcast,
  multicast,
  loopback,
  selfAddress,
  persistence,
};

enum class LoadResult { loaded, missing, invalid };

inline bool same(const IPv4& left, const IPv4& right) {
  for (size_t i = 0; i < 4; ++i) {
    if (left.octets[i] != right.octets[i]) return false;
  }
  return true;
}

inline bool format(const IPv4& address, char* output, size_t capacity) {
  if (!output || capacity < TEXT_CAPACITY) return false;
  size_t position = 0;
  for (size_t i = 0; i < 4; ++i) {
    const uint8_t value = address.octets[i];
    if (value >= 100) output[position++] = static_cast<char>('0' + value / 100);
    if (value >= 10) output[position++] = static_cast<char>('0' + (value / 10) % 10);
    output[position++] = static_cast<char>('0' + value % 10);
    if (i != 3) output[position++] = '.';
  }
  output[position] = '\0';
  return true;
}

inline Error validate(const char* input, IPv4& output, const IPv4* self = nullptr) {
  if (!input || !*input) return Error::empty;

  uint8_t values[4] = {0, 0, 0, 0};
  size_t position = 0;
  for (size_t octet = 0; octet < 4; ++octet) {
    const size_t start = position;
    unsigned value = 0;
    size_t digits = 0;
    while (input[position] >= '0' && input[position] <= '9') {
      if (++digits > 3) return Error::malformed;
      value = value * 10U + static_cast<unsigned>(input[position] - '0');
      ++position;
    }
    if (digits == 0 || (digits > 1 && input[start] == '0') || value > 255) {
      return Error::malformed;
    }
    values[octet] = static_cast<uint8_t>(value);
    if (octet != 3) {
      if (input[position] != '.') return Error::malformed;
      ++position;
    } else if (input[position] != '\0') {
      return Error::malformed;
    }
  }

  IPv4 candidate(values[0], values[1], values[2], values[3]);
  if (same(candidate, IPv4(0, 0, 0, 0))) return Error::unspecified;
  if (same(candidate, IPv4(255, 255, 255, 255))) return Error::broadcast;
  if (candidate.octets[0] >= 224 && candidate.octets[0] <= 239) return Error::multicast;
  if (candidate.octets[0] == 127) return Error::loopback;
  if (self && same(candidate, *self)) return Error::selfAddress;

  output = candidate;
  return Error::none;
}

inline const char* errorText(Error error) {
  switch (error) {
    case Error::none: return "ok";
    case Error::empty: return "missing IPv4 address";
    case Error::malformed: return "invalid IPv4 address";
    case Error::unspecified: return "unspecified address is not allowed";
    case Error::broadcast: return "broadcast address is not allowed";
    case Error::multicast: return "multicast address is not allowed";
    case Error::loopback: return "loopback address is not allowed";
    case Error::selfAddress: return "upstream cannot be this device address";
    case Error::persistence: return "upstream persistence failed";
  }
  return "upstream configuration failed";
}

// Store must provide the Preferences-shaped methods used below. Keeping this
// seam small lets host tests use a failure-injecting fake without simulating
// Arduino or NVS internals.
template <typename Store>
LoadResult load(Store& store, IPv4& active, const IPv4* self = nullptr) {
  if (!store.isKey(KEY)) return LoadResult::missing;
  char stored[TEXT_CAPACITY] = {};
  const size_t length = store.getString(KEY, stored, sizeof(stored));
  if (length == 0 || length >= sizeof(stored)) return LoadResult::invalid;
  IPv4 candidate;
  if (validate(stored, candidate, self) != Error::none) return LoadResult::invalid;
  active = candidate;
  return LoadResult::loaded;
}

template <typename Store>
bool persist(Store& store, const IPv4& candidate) {
  char text[TEXT_CAPACITY] = {};
  if (!format(candidate, text, sizeof(text))) return false;
  const size_t written = store.putString(KEY, text);
  size_t length = 0;
  while (text[length] != '\0') ++length;
  if (written != length) return false;

  char verification[TEXT_CAPACITY] = {};
  const size_t verified = store.getString(KEY, verification, sizeof(verification));
  if (verified != length) return false;
  for (size_t i = 0; i <= length; ++i) {
    if (verification[i] != text[i]) return false;
  }
  return true;
}

inline bool prepare(const char* input, const IPv4* self, IPv4& candidate, Error& error) {
  error = validate(input, candidate, self);
  return error == Error::none;
}

template <typename Store>
bool apply(Store& store, IPv4& active, const char* input, const IPv4* self,
           Error& error) {
  IPv4 candidate;
  if (!prepare(input, self, candidate, error)) return false;
  if (!persist(store, candidate)) {
    error = Error::persistence;
    return false;
  }
  active = candidate;
  return true;
}

}  // namespace upstream_config
