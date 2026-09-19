#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// N1 network-only seam. It is Arduino-free and deliberately owns one bounded
// NVS key so N2 can connect it to the portal without coupling validation to UI.
// The installed Preferences implementation must provide one-key putBytes
// atomicity; this helper verifies the readback, while host fakes do not prove
// power-loss behavior of a particular NVS/core version.
// Integration contract: N2 stages from the portal, calls boot() before applying
// a candidate, confirms with the socket's local IP (never Host), and lets this
// helper own the 180-second deadline. N3 may call reset(); it must preserve
// Wi-Fi credentials and every other NVS key. Revisions are uint32_t: after
// 2^32 successful transitions a theoretical token collision is possible;
// N1 intentionally has no epoch/auth framework because that is outside scope.
namespace network_profile {

static constexpr const char* NAMESPACE = "network";
static constexpr const char* KEY = "profile";
static constexpr uint32_t TRIAL_TIMEOUT_MS = 180000UL;
static constexpr size_t RECORD_SIZE = 68;

struct IPv4 {
  uint8_t octets[4];
  IPv4() : octets{0, 0, 0, 0} {}
  IPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) : octets{a, b, c, d} {}
};

struct Profile {
  bool dhcp;
  IPv4 local;
  IPv4 gateway;
  IPv4 netmask;
  IPv4 dnsIPv4;

  Profile() : dhcp(true), local(), gateway(), netmask(), dnsIPv4() {}
  static Profile dhcpProfile() { return Profile(); }
  static Profile staticProfile(const IPv4& local, const IPv4& gateway,
                               const IPv4& netmask, const IPv4& dns) {
    Profile result;
    result.dhcp = false;
    result.local = local;
    result.gateway = gateway;
    result.netmask = netmask;
    result.dnsIPv4 = dns;
    return result;
  }
};

enum class ValidationError {
  none,
  malformedIPv4,
  unspecified,
  broadcast,
  multicast,
  loopback,
  invalidNetmask,
  localNetwork,
  localBroadcast,
  gatewayNetwork,
  gatewayBroadcast,
  gatewayOutsideSubnet,
  gatewayIsLocal,
  dnsIsLocal,
};

enum class LoadStatus { missing, loaded, invalid, indeterminate };
enum class Result { pending, committed, reverted, ioerror, indeterminate };
enum class BootAction { none, applyCandidate, applyPrevious, useDhcp };
enum class ConfirmError { none, noTrial, tokenMismatch, invalidActual, storage };

template <typename T>
inline bool same(const T& left, const T& right) {
  for (size_t i = 0; i < 4; ++i) {
    if (left.octets[i] != right.octets[i]) return false;
  }
  return true;
}

inline bool parseIPv4(const char* input, IPv4& output) {
  if (!input || !*input) return false;
  uint8_t values[4] = {0, 0, 0, 0};
  size_t position = 0;
  for (size_t octet = 0; octet < 4; ++octet) {
    const size_t start = position;
    unsigned value = 0;
    size_t digits = 0;
    while (input[position] >= '0' && input[position] <= '9') {
      if (++digits > 3) return false;
      value = value * 10U + static_cast<unsigned>(input[position] - '0');
      ++position;
    }
    if (!digits || (digits > 1 && input[start] == '0') || value > 255) return false;
    values[octet] = static_cast<uint8_t>(value);
    if (octet != 3) {
      if (input[position] != '.') return false;
      ++position;
    } else if (input[position] != '\0') {
      return false;
    }
  }
  output = IPv4(values[0], values[1], values[2], values[3]);
  return true;
}

inline uint32_t number(const IPv4& value) {
  return (static_cast<uint32_t>(value.octets[0]) << 24) |
         (static_cast<uint32_t>(value.octets[1]) << 16) |
         (static_cast<uint32_t>(value.octets[2]) << 8) |
         static_cast<uint32_t>(value.octets[3]);
}

inline IPv4 fromNumber(uint32_t value) {
  return IPv4(static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
              static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value));
}

inline bool validUnicast(const IPv4& address) {
  const uint8_t first = address.octets[0];
  if (same(address, IPv4(0, 0, 0, 0)) || same(address, IPv4(255, 255, 255, 255))) return false;
  if (first == 127 || first >= 224) return false;
  return true;
}

inline bool validNetmask(const IPv4& mask) {
  const uint32_t value = number(mask);
  if (value == 0 || value == 0xffffffffU) return false;
  bool sawZero = false;
  unsigned ones = 0;
  for (int bit = 31; bit >= 0; --bit) {
    const bool one = (value & (1UL << bit)) != 0;
    if (!one) sawZero = true;
    else {
      if (sawZero) return false;
      ++ones;
    }
  }
  return ones >= 1 && ones <= 30;  // a subnet needs distinct network/broadcast hosts
}

inline uint32_t networkOf(const IPv4& address, const IPv4& mask) {
  return number(address) & number(mask);
}

inline uint32_t broadcastOf(const IPv4& address, const IPv4& mask) {
  return networkOf(address, mask) | ~number(mask);
}

inline ValidationError addressError(const IPv4& address) {
  if (same(address, IPv4(0, 0, 0, 0))) return ValidationError::unspecified;
  if (same(address, IPv4(255, 255, 255, 255))) return ValidationError::broadcast;
  if (address.octets[0] == 127) return ValidationError::loopback;
  if (address.octets[0] >= 224) return ValidationError::multicast;
  return ValidationError::none;
}

inline ValidationError validate(const Profile& profile) {
  if (profile.dhcp) {
    const IPv4 zero;
    if (!same(profile.local, zero) || !same(profile.gateway, zero) ||
        !same(profile.netmask, zero) || !same(profile.dnsIPv4, zero)) {
      // A DHCP profile carrying static fields is a malformed profile payload.
      return ValidationError::malformedIPv4;
    }
    return ValidationError::none;
  }
  if (!validNetmask(profile.netmask)) return ValidationError::invalidNetmask;
  ValidationError error = addressError(profile.local);
  if (error != ValidationError::none) return error;
  error = addressError(profile.gateway);
  if (error != ValidationError::none) return error;
  error = addressError(profile.dnsIPv4);
  if (error != ValidationError::none) return error;

  const uint32_t network = networkOf(profile.local, profile.netmask);
  const uint32_t broadcast = broadcastOf(profile.local, profile.netmask);
  if (number(profile.local) == network) return ValidationError::localNetwork;
  if (number(profile.local) == broadcast) return ValidationError::localBroadcast;
  if (number(profile.gateway) == network) return ValidationError::gatewayNetwork;
  if (number(profile.gateway) == broadcast) return ValidationError::gatewayBroadcast;
  if (same(profile.local, profile.gateway)) return ValidationError::gatewayIsLocal;
  if (networkOf(profile.gateway, profile.netmask) != network) return ValidationError::gatewayOutsideSubnet;
  if (same(profile.local, profile.dnsIPv4)) return ValidationError::dnsIsLocal;
  return ValidationError::none;
}

inline const char* errorText(ValidationError error) {
  switch (error) {
    case ValidationError::none: return "ok";
    case ValidationError::malformedIPv4: return "malformed IPv4 address";
    case ValidationError::unspecified: return "unspecified IPv4 address is not allowed";
    case ValidationError::broadcast: return "broadcast IPv4 address is not allowed";
    case ValidationError::multicast: return "multicast IPv4 address is not allowed";
    case ValidationError::loopback: return "loopback IPv4 address is not allowed";
    case ValidationError::invalidNetmask: return "invalid contiguous IPv4 netmask";
    case ValidationError::localNetwork: return "local IPv4 address is the subnet network";
    case ValidationError::localBroadcast: return "local IPv4 address is the subnet broadcast";
    case ValidationError::gatewayNetwork: return "gateway IPv4 address is the subnet network";
    case ValidationError::gatewayBroadcast: return "gateway IPv4 address is the subnet broadcast";
    case ValidationError::gatewayOutsideSubnet: return "gateway is outside the local subnet";
    case ValidationError::gatewayIsLocal: return "gateway must differ from local IPv4 address";
    case ValidationError::dnsIsLocal: return "DNS IPv4 address must differ from local IPv4 address";
  }
  return "invalid network profile";
}

inline bool equal(const Profile& left, const Profile& right) {
  return left.dhcp == right.dhcp && same(left.local, right.local) &&
         same(left.gateway, right.gateway) && same(left.netmask, right.netmask) &&
         same(left.dnsIPv4, right.dnsIPv4);
}

struct ConfirmationToken {
  uint32_t revision;
  IPv4 expectedIP;
  ConfirmationToken() : revision(0), expectedIP() {}
  ConfirmationToken(uint32_t value, const IPv4& expected) : revision(value), expectedIP(expected) {}
};

struct TrialSession {
  uint32_t revision;
  uint32_t startedAt;
  Profile candidate;
  TrialSession() : revision(0), startedAt(0), candidate() {}
};

struct StageResult {
  Result result;
  ValidationError error;
  uint32_t revision;
  StageResult(Result r = Result::ioerror, ValidationError e = ValidationError::none, uint32_t v = 0)
      : result(r), error(e), revision(v) {}
};

struct BootResult {
  Result result;
  BootAction action;
  Profile profile;
  TrialSession trial;
  bool diagnostic;
  BootResult() : result(Result::ioerror), action(BootAction::none), profile(), trial(), diagnostic(false) {}
};

struct ConfirmResult {
  Result result;
  ConfirmError error;
  Profile profile;
  ConfirmResult() : result(Result::reverted), error(ConfirmError::noTrial), profile() {}
};

struct ExpireResult {
  Result result;
  Profile profile;
  ExpireResult() : result(Result::pending), profile() {}
};

namespace detail {
static constexpr uint8_t STATE_STABLE = 0;
static constexpr uint8_t STATE_PENDING = 1;
static constexpr uint8_t STATE_TRIAL = 2;
static constexpr uint8_t MAGIC[4] = {'N', 'P', 'R', 'F'};
static constexpr uint8_t SCHEMA = 1;
static constexpr size_t CHECKSUM_OFFSET = 64;

struct Record {
  uint8_t state;
  uint32_t revision;
  uint8_t attempt;
  Profile current;
  Profile candidate;
  IPv4 confirmedIP;
};

inline void put32(uint8_t* bytes, size_t offset, uint32_t value) {
  bytes[offset] = static_cast<uint8_t>(value >> 24);
  bytes[offset + 1] = static_cast<uint8_t>(value >> 16);
  bytes[offset + 2] = static_cast<uint8_t>(value >> 8);
  bytes[offset + 3] = static_cast<uint8_t>(value);
}

inline uint32_t get32(const uint8_t* bytes, size_t offset) {
  return (static_cast<uint32_t>(bytes[offset]) << 24) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 8) | bytes[offset + 3];
}

inline uint32_t checksum(const uint8_t* bytes) {
  uint32_t hash = 2166136261UL;
  for (size_t i = 0; i < CHECKSUM_OFFSET; ++i) {
    hash ^= bytes[i];
    hash *= 16777619UL;
  }
  return hash;
}

inline void encodeProfile(const Profile& profile, uint8_t* bytes, size_t offset) {
  bytes[offset++] = profile.dhcp ? 1 : 0;
  const IPv4* values[4] = {&profile.local, &profile.gateway, &profile.netmask, &profile.dnsIPv4};
  for (size_t value = 0; value < 4; ++value)
    for (size_t octet = 0; octet < 4; ++octet) bytes[offset++] = values[value]->octets[octet];
}

inline bool decodeProfile(const uint8_t* bytes, size_t offset, Profile& profile) {
  const uint8_t mode = bytes[offset++];
  if (mode > 1) return false;
  profile = Profile();
  profile.dhcp = mode == 1;
  IPv4* values[4] = {&profile.local, &profile.gateway, &profile.netmask, &profile.dnsIPv4};
  for (size_t value = 0; value < 4; ++value)
    for (size_t octet = 0; octet < 4; ++octet) values[value]->octets[octet] = bytes[offset++];
  // The encoder emits a zero payload for DHCP; accepting alternate bytes would
  // create multiple encodings for one logical profile.
  if (profile.dhcp) {
    const IPv4 zero;
    return same(profile.local, zero) && same(profile.gateway, zero) &&
           same(profile.netmask, zero) && same(profile.dnsIPv4, zero);
  }
  return true;
}

inline void encode(const Record& record, uint8_t* bytes) {
  std::memset(bytes, 0, RECORD_SIZE);
  for (size_t i = 0; i < 4; ++i) bytes[i] = MAGIC[i];
  bytes[4] = SCHEMA;
  bytes[5] = record.state;
  put32(bytes, 6, record.revision);
  bytes[10] = record.attempt;
  encodeProfile(record.current, bytes, 11);
  encodeProfile(record.candidate, bytes, 28);
  for (size_t octet = 0; octet < 4; ++octet) bytes[45 + octet] = record.confirmedIP.octets[octet];
  put32(bytes, CHECKSUM_OFFSET, checksum(bytes));
}

inline bool decode(const uint8_t* bytes, Record& record) {
  for (size_t i = 0; i < 4; ++i) if (bytes[i] != MAGIC[i]) return false;
  if (bytes[4] != SCHEMA || bytes[5] > STATE_TRIAL || bytes[10] > 1) return false;
  if (get32(bytes, CHECKSUM_OFFSET) != checksum(bytes)) return false;
  record.state = bytes[5];
  record.revision = get32(bytes, 6);
  record.attempt = bytes[10];
  if (!decodeProfile(bytes, 11, record.current) || !decodeProfile(bytes, 28, record.candidate)) return false;
  record.confirmedIP = IPv4(bytes[45], bytes[46], bytes[47], bytes[48]);
  for (size_t i = 49; i < CHECKSUM_OFFSET; ++i) if (bytes[i] != 0) return false;
  if (record.revision == 0 || validate(record.current) != ValidationError::none) return false;
  if (record.state == STATE_STABLE) {
    if (record.attempt != 0 || !record.candidate.dhcp) return false;
    const IPv4 zero;
    if (!same(record.confirmedIP, zero)) {
      if (!validUnicast(record.confirmedIP)) return false;
      if (!record.current.dhcp && !same(record.confirmedIP, record.current.local)) return false;
    }
    return true;
  }
  if (!same(record.confirmedIP, IPv4())) return false;
  if (validate(record.candidate) != ValidationError::none) return false;
  if (record.state == STATE_PENDING && record.attempt != 0) return false;
  if (record.state == STATE_TRIAL && record.attempt != 1) return false;
  return true;
}

enum class ReadState { missing, valid, invalid, indeterminate };

template <typename Store>
ReadState read(Store& store, Record& record) {
  if (!store.isKey(KEY)) return ReadState::missing;
  if (store.getBytesLength(KEY) != RECORD_SIZE) return ReadState::invalid;
  uint8_t bytes[RECORD_SIZE] = {};
  if (store.getBytes(KEY, bytes, RECORD_SIZE) != RECORD_SIZE) return ReadState::indeterminate;
  return decode(bytes, record) ? ReadState::valid : ReadState::invalid;
}

template <typename Store>
Result write(Store& store, const Record& record) {
  uint8_t bytes[RECORD_SIZE] = {};
  encode(record, bytes);
  if (store.putBytes(KEY, bytes, RECORD_SIZE) != RECORD_SIZE) return Result::ioerror;
  Record verified;
  const ReadState state = read(store, verified);
  if (state == ReadState::indeterminate) return Result::indeterminate;
  if (state != ReadState::valid) return Result::indeterminate;
  uint8_t check[RECORD_SIZE] = {};
  encode(verified, check);
  for (size_t i = 0; i < RECORD_SIZE; ++i) if (bytes[i] != check[i]) return Result::indeterminate;
  return Result::committed;
}

inline uint32_t nextRevision(uint32_t revision) { return revision == 0xffffffffUL ? 1 : revision + 1; }
inline Record stable(uint32_t revision, const Profile& profile, const IPv4* confirmedIP = nullptr) {
  Record result = {STATE_STABLE, revision, 0, profile, Profile::dhcpProfile(), IPv4()};
  if (confirmedIP) result.confirmedIP = *confirmedIP;
  return result;
}
inline bool reached(uint32_t now, uint32_t start) {
  // Unsigned subtraction is intentional: all supported intervals are below 2^31.
  return static_cast<uint32_t>(now - start) >= TRIAL_TIMEOUT_MS;
}
}  // namespace detail

template <typename Store>
LoadStatus load(Store& store, Profile& active) {
  detail::Record record;
  const detail::ReadState state = detail::read(store, record);
  if (state == detail::ReadState::missing) {
    active = Profile::dhcpProfile();
    return LoadStatus::missing;
  }
  if (state != detail::ReadState::valid) {
    active = Profile::dhcpProfile();
    return state == detail::ReadState::indeterminate ? LoadStatus::indeterminate : LoadStatus::invalid;
  }
  active = record.current;
  return LoadStatus::loaded;
}

inline bool timedOut(const TrialSession& trial, uint32_t now) {
  return trial.revision != 0 && detail::reached(now, trial.startedAt);
}

inline ConfirmationToken tokenForTrial(const TrialSession& trial, const IPv4& expectedIP) {
  return ConfirmationToken(trial.revision, expectedIP);
}

inline ConfirmationToken tokenForStaticTrial(const TrialSession& trial) {
  return ConfirmationToken(trial.revision, trial.candidate.local);
}

template <typename Store>
StageResult stage(Store& store, const Profile& candidate) {
  const ValidationError error = validate(candidate);
  if (error != ValidationError::none) return StageResult(Result::reverted, error, 0);

  detail::Record existing;
  const detail::ReadState state = detail::read(store, existing);
  if (state == detail::ReadState::indeterminate) return StageResult(Result::indeterminate);
  if (state == detail::ReadState::valid && existing.state != detail::STATE_STABLE)
    return StageResult(Result::ioerror);
  const Profile previous = state == detail::ReadState::valid ? existing.current : Profile::dhcpProfile();
  const uint32_t revision = state == detail::ReadState::valid ? detail::nextRevision(existing.revision) : 1;
  detail::Record pending = {detail::STATE_PENDING, revision, 0, previous, candidate, IPv4()};
  const Result result = detail::write(store, pending);
  return StageResult(result == Result::committed ? Result::pending : result, ValidationError::none, revision);
}

template <typename Store>
BootResult boot(Store& store, uint32_t now) {
  BootResult result;
  detail::Record record;
  const detail::ReadState state = detail::read(store, record);
  if (state == detail::ReadState::missing) {
    result.result = Result::committed;
    result.action = BootAction::useDhcp;
    result.profile = Profile::dhcpProfile();
    return result;
  }
  if (state != detail::ReadState::valid) {
    result.result = state == detail::ReadState::indeterminate ? Result::indeterminate : Result::reverted;
    result.action = BootAction::useDhcp;
    result.profile = Profile::dhcpProfile();
    result.diagnostic = true;
    return result;
  }
  if (record.state == detail::STATE_STABLE) {
    result.result = Result::committed;
    result.profile = record.current;
    return result;
  }
  if (record.state == detail::STATE_TRIAL) {
    const detail::Record rollback = detail::stable(detail::nextRevision(record.revision), record.current);
    const Result persisted = detail::write(store, rollback);
    if (persisted != Result::committed) {
      result.result = persisted;
      result.diagnostic = true;
      return result;  // do not ask integration to reboot or apply an unrecorded rollback
    }
    result.result = Result::reverted;
    result.action = BootAction::applyPrevious;
    result.profile = record.current;
    return result;
  }

  // The marker is persisted before this action is returned. A power cut here
  // leaves STATE_TRIAL, so the next boot rolls back safely instead of guessing.
  detail::Record trialRecord = record;
  trialRecord.state = detail::STATE_TRIAL;
  trialRecord.attempt = 1;
  const Result persisted = detail::write(store, trialRecord);
  if (persisted != Result::committed) {
    result.result = persisted;
    result.diagnostic = true;
    return result;
  }
  result.result = Result::pending;
  result.action = BootAction::applyCandidate;
  result.profile = record.candidate;
  result.trial.revision = record.revision;
  result.trial.startedAt = now;
  result.trial.candidate = record.candidate;
  return result;
}

template <typename Store>
ConfirmResult confirm(Store& store, const ConfirmationToken& token, const IPv4& actualLocalIP) {
  ConfirmResult result;
  if (!validUnicast(actualLocalIP) || token.revision == 0 || !same(token.expectedIP, actualLocalIP)) {
    result.error = ConfirmError::invalidActual;
    return result;
  }
  detail::Record record;
  const detail::ReadState state = detail::read(store, record);
  if (state == detail::ReadState::indeterminate) {
    result.result = Result::indeterminate;
    result.error = ConfirmError::storage;
    return result;
  }
  if (state != detail::ReadState::valid) {
    result.result = state == detail::ReadState::invalid ? Result::reverted : Result::ioerror;
    result.error = ConfirmError::storage;
    return result;
  }
  if (record.state == detail::STATE_STABLE && record.revision == token.revision &&
      same(record.confirmedIP, actualLocalIP)) {
    result.result = Result::committed;  // idempotent repeat after this trial committed
    result.error = ConfirmError::none;
    result.profile = record.current;
    return result;
  }
  if (record.state != detail::STATE_TRIAL || record.revision != token.revision) {
    result.error = ConfirmError::tokenMismatch;
    return result;
  }
  if (!record.candidate.dhcp && !same(record.candidate.local, token.expectedIP)) {
    result.error = ConfirmError::tokenMismatch;
    return result;
  }
  const detail::Record committed = detail::stable(record.revision, record.candidate, &actualLocalIP);
  const Result persisted = detail::write(store, committed);
  result.result = persisted;
  result.error = persisted == Result::committed ? ConfirmError::none : ConfirmError::storage;
  if (persisted == Result::committed) result.profile = record.candidate;
  return result;
}

template <typename Store>
ExpireResult expire(Store& store, const TrialSession& trial, uint32_t now) {
  ExpireResult result;
  detail::Record record;
  const detail::ReadState state = detail::read(store, record);
  if (state != detail::ReadState::valid) {
    result.result = state == detail::ReadState::invalid ? Result::reverted : Result::indeterminate;
    return result;
  }
  if (record.state == detail::STATE_STABLE) {
    result.result = record.revision == trial.revision ? Result::committed : Result::reverted;
    result.profile = record.current;
    return result;  // confirmation already canceled this timer
  }
  if (record.state != detail::STATE_TRIAL || record.revision != trial.revision) {
    result.result = Result::reverted;
    return result;  // another transition won; never revert it
  }
  if (!timedOut(trial, now)) {
    result.result = Result::pending;
    result.profile = record.candidate;
    return result;
  }
  const detail::Record rollback = detail::stable(detail::nextRevision(record.revision), record.current);
  const Result persisted = detail::write(store, rollback);
  result.result = persisted == Result::committed ? Result::reverted : persisted;
  if (persisted == Result::committed) result.profile = record.current;
  return result;
}

template <typename Store>
Result reset(Store& store) {
  if (!store.isKey(KEY)) return Result::committed;
  if (!store.remove(KEY)) return Result::ioerror;
  return store.isKey(KEY) ? Result::indeterminate : Result::committed;
}

}  // namespace network_profile
