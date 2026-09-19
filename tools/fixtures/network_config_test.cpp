#include "network_config.h"
#include "network_profile.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

struct FakeStore {
  bool present = false;
  bool failPut = false;
  bool failRead = false;
  bool putWritesThenFails = false;
  bool failRemove = false;
  bool corruptReadback = false;
  bool corruptReadbackAfterPut = false;
  size_t putCount = 0;
  std::vector<uint8_t> value;
  bool otherPresent = true;

  bool isKey(const char* key) const {
    if (std::strcmp(key, network_profile::KEY) == 0) return present;
    return std::strcmp(key, "wifi") == 0 && otherPresent;
  }
  size_t getBytesLength(const char* key) const {
    if (std::strcmp(key, network_profile::KEY) != 0 || !present) return 0;
    return value.size();
  }
  size_t getBytes(const char* key, void* output, size_t length) const {
    if (std::strcmp(key, network_profile::KEY) != 0 || !present || failRead) return 0;
    if (value.size() != length) return value.size();
    std::memcpy(output, value.data(), length);
    if (corruptReadback) {
      uint8_t* bytes = static_cast<uint8_t*>(output);
      bytes[15] = static_cast<uint8_t>(bytes[15] == 5 ? 6 : bytes[15] ^ 1);
      const uint32_t hash = network_profile::detail::checksum(bytes);
      bytes[64] = static_cast<uint8_t>(hash >> 24);
      bytes[65] = static_cast<uint8_t>(hash >> 16);
      bytes[66] = static_cast<uint8_t>(hash >> 8);
      bytes[67] = static_cast<uint8_t>(hash);
    }
    return length;
  }
  size_t putBytes(const char* key, const void* input, size_t length) {
    if (std::strcmp(key, network_profile::KEY) != 0) return 0;
    ++putCount;
    if (putWritesThenFails) {
      value.assign(static_cast<const uint8_t*>(input), static_cast<const uint8_t*>(input) + length);
      present = true;
      return 0;
    }
    if (failPut) return 0;
    value.assign(static_cast<const uint8_t*>(input), static_cast<const uint8_t*>(input) + length);
    present = true;
    corruptReadback = corruptReadbackAfterPut;
    return length;
  }
  bool remove(const char* key) {
    if (std::strcmp(key, network_profile::KEY) != 0 || failRemove) return false;
    value.clear();
    present = false;
    return true;
  }
};

static void expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    std::abort();
  }
}

static network_profile::Profile profile(const char* local, const char* gateway,
                                        const char* mask, const char* dns) {
  network_profile::IPv4 l, g, m, d;
  expect(network_profile::parseIPv4(local, l), "local fixture parses");
  expect(network_profile::parseIPv4(gateway, g), "gateway fixture parses");
  expect(network_profile::parseIPv4(mask, m), "mask fixture parses");
  expect(network_profile::parseIPv4(dns, d), "DNS fixture parses");
  return network_profile::Profile::staticProfile(l, g, m, d);
}

static void validation_cases() {
  const network_profile::Profile valid = profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "1.1.1.1");
  expect(network_profile::validate(valid) == network_profile::ValidationError::none, "valid private static profile");
  expect(network_profile::validate(network_profile::Profile::dhcpProfile()) == network_profile::ValidationError::none,
         "DHCP is the non-hardcoded default");
  expect(network_profile::validate(profile("192.168.1.0", "192.168.1.1", "255.255.255.0", "8.8.8.8")) ==
             network_profile::ValidationError::localNetwork, "network address rejected for local");
  expect(network_profile::validate(profile("192.168.1.255", "192.168.1.1", "255.255.255.0", "8.8.8.8")) ==
             network_profile::ValidationError::localBroadcast, "broadcast address rejected for local");
  expect(network_profile::validate(profile("192.168.1.5", "192.168.2.1", "255.255.255.0", "8.8.8.8")) ==
             network_profile::ValidationError::gatewayOutsideSubnet, "gateway must share subnet");
  expect(network_profile::validate(profile("192.168.1.5", "192.168.1.5", "255.255.255.0", "8.8.8.8")) ==
             network_profile::ValidationError::gatewayIsLocal, "gateway cannot equal local");
  expect(network_profile::validate(profile("192.168.1.5", "192.168.1.1", "255.0.255.0", "8.8.8.8")) ==
             network_profile::ValidationError::invalidNetmask, "noncontiguous mask rejected");
  expect(network_profile::validate(profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "192.168.1.5")) ==
             network_profile::ValidationError::dnsIsLocal, "DNS cannot equal local");
  expect(network_profile::validate(profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "0.0.0.0")) ==
             network_profile::ValidationError::unspecified, "unspecified DNS rejected");
  expect(network_profile::validate(profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "224.0.0.1")) ==
             network_profile::ValidationError::multicast, "multicast DNS rejected");
  expect(network_profile::validate(profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "127.0.0.1")) ==
             network_profile::ValidationError::loopback, "loopback DNS rejected");
  network_profile::IPv4 notIPv4;
  expect(!network_profile::parseIPv4("2001:db8::1", notIPv4), "IPv6 rejected without a parser");
  expect(network_profile::validUnicast(network_profile::IPv4(8, 8, 8, 8)), "public DNS allowed");
  expect(network_profile::validUnicast(network_profile::IPv4(10, 0, 0, 2)), "private address allowed");

  network_config::StaticConfig legacy;
  network_config::Error error = network_config::Error::none;
  expect(network_config::select(true, "192.168.1.5", "192.168.1.1", "255.255.255.0", "1.1.1.1", legacy, error),
         "old config seam uses N1 validation");
  expect(!network_config::select(true, "192.168.1.5", "192.168.2.1", "255.255.255.0", "1.1.1.1", legacy, error),
         "old config seam rejects outside gateway");
}

static void canonical_record_cases() {
  const network_profile::Profile current =
      profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "8.8.8.8");
  const network_profile::IPv4 confirmed(192, 168, 1, 5);
  network_profile::detail::Record stable =
      network_profile::detail::stable(0x01020304UL, current, &confirmed);
  uint8_t bytes[network_profile::RECORD_SIZE] = {};
  network_profile::detail::encode(stable, bytes);
  const uint8_t expected[network_profile::RECORD_SIZE] = {
      0x4e, 0x50, 0x52, 0x46, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00,
      0x00, 0xc0, 0xa8, 0x01, 0x05, 0xc0, 0xa8, 0x01, 0x01, 0xff, 0xff,
      0xff, 0x00, 0x08, 0x08, 0x08, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0xc0, 0xa8, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x42, 0x39,
      0x3c};
  for (size_t i = 0; i < network_profile::RECORD_SIZE; ++i) {
    if (bytes[i] != expected[i]) {
      std::cerr << "vector mismatch at " << i << ": actual " << static_cast<unsigned>(bytes[i])
                << " expected " << static_cast<unsigned>(expected[i]) << '\n';
      std::abort();
    }
  }
  expect(network_profile::detail::get32(bytes, 6) == 0x01020304UL,
         "record revision uses big-endian bytes");
  expect(network_profile::detail::checksum(bytes) == 0xa842393cUL,
         "record checksum vector is stable");
  network_profile::detail::Record decoded;
  expect(network_profile::detail::decode(bytes, decoded) &&
             network_profile::equal(decoded.current, current) &&
             decoded.revision == 0x01020304UL,
         "canonical stable record decodes");

  const auto expectInvalidMutation = [&](size_t offset, uint8_t value, const char* message) {
    uint8_t mutated[network_profile::RECORD_SIZE] = {};
    std::memcpy(mutated, bytes, network_profile::RECORD_SIZE);
    mutated[offset] = value;
    network_profile::detail::put32(mutated, network_profile::detail::CHECKSUM_OFFSET,
                                   network_profile::detail::checksum(mutated));
    network_profile::detail::Record invalid;
    expect(!network_profile::detail::decode(mutated, invalid), message);
  };
  expectInvalidMutation(10, 1, "stable attempt marker must be zero");
  expectInvalidMutation(11, 2, "profile mode rejects raw values other than DHCP or static");
  expectInvalidMutation(29, 1, "stable DHCP candidate payload must be canonical zero");
  expectInvalidMutation(45, 6, "stable confirmed IP must match static local IP");
  expectInvalidMutation(49, 1, "reserved record bytes must remain canonical zero");

  network_profile::detail::Record pending = {
      network_profile::detail::STATE_PENDING, 7, 0, network_profile::Profile::dhcpProfile(), current,
      network_profile::IPv4()};
  network_profile::detail::encode(pending, bytes);
  expect(network_profile::detail::decode(bytes, decoded), "valid pending record remains accepted");
  pending.state = network_profile::detail::STATE_TRIAL;
  pending.attempt = 1;
  network_profile::detail::encode(pending, bytes);
  expect(network_profile::detail::decode(bytes, decoded), "valid trial record remains accepted");

  FakeStore maxRevision;
  maxRevision.present = true;
  stable.revision = 0xffffffffUL;
  maxRevision.value.assign(network_profile::RECORD_SIZE, 0);
  network_profile::detail::encode(stable, maxRevision.value.data());
  network_profile::StageResult wrapped = network_profile::stage(maxRevision, current);
  expect(wrapped.result == network_profile::Result::pending && wrapped.revision == 1,
         "maximum revision wraps to one");
}

static void invalid_dhcp_payload_cases() {
  const network_profile::IPv4 nonzero(192, 168, 1, 5);
  network_profile::Profile candidates[4] = {
      network_profile::Profile::dhcpProfile(), network_profile::Profile::dhcpProfile(),
      network_profile::Profile::dhcpProfile(), network_profile::Profile::dhcpProfile()};
  candidates[0].local = nonzero;
  candidates[1].gateway = nonzero;
  candidates[2].netmask = nonzero;
  candidates[3].dnsIPv4 = nonzero;
  const char* labels[4] = {"local", "gateway", "netmask", "dnsIPv4"};

  for (size_t i = 0; i < 4; ++i) {
    FakeStore store;
    store.present = true;
    store.value.assign(network_profile::RECORD_SIZE, 0xa5);
    const std::vector<uint8_t> before = store.value;
    const network_profile::StageResult result = network_profile::stage(store, candidates[i]);
    expect(network_profile::validate(candidates[i]) == network_profile::ValidationError::malformedIPv4,
           labels[i]);
    expect(result.result == network_profile::Result::reverted &&
               result.error == network_profile::ValidationError::malformedIPv4 &&
               result.revision == 0,
           "invalid DHCP payload fails deterministically before persistence");
    expect(store.putCount == 0 && store.value == before,
           "invalid DHCP payload does not change fake storage");
  }
  expect(network_profile::validate(network_profile::Profile::dhcpProfile()) ==
             network_profile::ValidationError::none,
         "canonical DHCP profile remains valid");
}

static void staging_and_confirmation() {
  FakeStore store;
  network_profile::Profile active;
  expect(network_profile::load(store, active) == network_profile::LoadStatus::missing, "missing storage");
  expect(active.dhcp, "missing storage fails safe to DHCP");

  const network_profile::Profile first = profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "1.1.1.1");
  network_profile::StageResult staged = network_profile::stage(store, first);
  expect(staged.result == network_profile::Result::pending && staged.revision == 1, "stage writes pending revision");
  expect(network_profile::load(store, active) == network_profile::LoadStatus::loaded && active.dhcp,
         "staging retains previous DHCP profile");

  network_profile::BootResult booted = network_profile::boot(store, 1000);
  expect(booted.result == network_profile::Result::pending && booted.action == network_profile::BootAction::applyCandidate,
         "first boot applies staged candidate only after marker");
  expect(booted.profile.local.octets[3] == 5, "candidate returned to integration");
  expect(network_profile::timedOut(booted.trial, 1000 + 179999) == false, "179999ms is before deadline");
  expect(network_profile::timedOut(booted.trial, 1000 + 180000), "180000ms reaches deadline");

  network_profile::ConfirmationToken wrong = network_profile::tokenForTrial(booted.trial, network_profile::IPv4(192, 168, 1, 6));
  network_profile::ConfirmResult rejected = network_profile::confirm(store, wrong, network_profile::IPv4(192, 168, 1, 5));
  expect(rejected.result == network_profile::Result::reverted, "different expected IP cannot confirm");
  network_profile::ConfirmationToken token = network_profile::tokenForStaticTrial(booted.trial);
  network_profile::ConfirmResult committed = network_profile::confirm(store, token, first.local);
  expect(committed.result == network_profile::Result::committed, "matching trial token commits");
  expect(network_profile::confirm(store, token, first.local).result == network_profile::Result::committed,
         "confirmation is idempotent after commit");
  expect(network_profile::confirm(store, token, network_profile::IPv4(192, 168, 1, 6)).result ==
             network_profile::Result::reverted,
         "a token cannot confirm a different actual socket address");

  const network_profile::Profile second = profile("192.168.1.6", "192.168.1.1", "255.255.255.0", "8.8.8.8");
  staged = network_profile::stage(store, second);
  expect(staged.result == network_profile::Result::pending && staged.revision == 2, "second stage retains prior committed profile");
  booted = network_profile::boot(store, 0xffffff00UL);
  expect(booted.action == network_profile::BootAction::applyCandidate, "second candidate starts trial");
  expect(network_profile::confirm(store, token, first.local).result == network_profile::Result::reverted,
         "stale revision token cannot confirm a later trial");
  network_profile::BootResult rebooted = network_profile::boot(store, 123);
  expect(rebooted.result == network_profile::Result::reverted && rebooted.action == network_profile::BootAction::applyPrevious,
         "unconfirmed reboot rolls back instead of resetting trial deadline forever");
  expect(rebooted.profile.local.octets[3] == 5, "rollback returns previous profile");
  expect(network_profile::expire(store, booted.trial, 999999).result == network_profile::Result::reverted,
         "timeout after reboot rollback is a no-op");
}

static void timeout_and_wrap_cases() {
  FakeStore store;
  const network_profile::Profile candidate = profile("10.0.0.5", "10.0.0.1", "255.255.255.0", "9.9.9.9");
  expect(network_profile::stage(store, candidate).result == network_profile::Result::pending, "timeout trial staged");
  network_profile::BootResult booted = network_profile::boot(store, 0xffffff00UL);
  expect(network_profile::timedOut(booted.trial, static_cast<uint32_t>(0xffffff00UL) + 179U) == false,
         "wrap-safe timer remains before 179ms");
  expect(network_profile::timedOut(booted.trial, static_cast<uint32_t>(0xffffff00UL) + 180000U - 1U) == false,
         "timeout remains before 180 seconds");
  expect(network_profile::timedOut(booted.trial, static_cast<uint32_t>(0xffffff00UL) + 180000U),
         "timeout fires at 180 seconds");
  network_profile::ExpireResult expired =
      network_profile::expire(store, booted.trial, static_cast<uint32_t>(0xffffff00UL) + 180000U);
  expect(expired.result == network_profile::Result::reverted, "expired trial persists rollback");
  expect(network_profile::expire(store, booted.trial, 180001).result == network_profile::Result::reverted,
         "timeout cancellation is idempotent after rollback");

  network_profile::TrialSession wrap;
  wrap.revision = 1;
  wrap.startedAt = 0xffffff00UL;
  expect(!network_profile::timedOut(wrap, static_cast<uint32_t>(0xffffff00UL) + 179999U),
         "wrap fixture before deadline");
  expect(network_profile::timedOut(wrap, static_cast<uint32_t>(0xffffff00UL) + 180000U),
         "wrap fixture reaches deadline safely");
}

static void storage_failure_cases() {
  const network_profile::Profile candidate = profile("172.16.0.5", "172.16.0.1", "255.255.255.0", "1.1.1.1");
  FakeStore putFailure;
  putFailure.failPut = true;
  expect(network_profile::stage(putFailure, candidate).result == network_profile::Result::ioerror, "put failure is definite IO error");
  expect(!putFailure.present, "put failure leaves no candidate claim");

  FakeStore readFailure;
  readFailure.failRead = true;
  expect(network_profile::stage(readFailure, candidate).result == network_profile::Result::indeterminate,
         "readback failure is explicitly indeterminate");

  const network_profile::Profile previous =
      profile("192.168.1.5", "192.168.1.1", "255.255.255.0", "1.1.1.1");
  const network_profile::Profile next =
      profile("192.168.1.6", "192.168.1.1", "255.255.255.0", "8.8.8.8");
  network_profile::Profile active;
  FakeStore fullRecordMismatch;
  expect(network_profile::stage(fullRecordMismatch, previous).result == network_profile::Result::pending,
         "full-record mismatch fixture stages initial profile");
  network_profile::BootResult initialTrial = network_profile::boot(fullRecordMismatch, 1);
  expect(network_profile::confirm(fullRecordMismatch,
                                  network_profile::tokenForStaticTrial(initialTrial.trial), previous.local).result ==
             network_profile::Result::committed,
         "full-record mismatch fixture commits previous profile");
  fullRecordMismatch.corruptReadbackAfterPut = true;
  expect(network_profile::stage(fullRecordMismatch, next).result == network_profile::Result::indeterminate,
         "full-length corrupted readback is indeterminate after production comparison");
  fullRecordMismatch.corruptReadback = false;
  expect(network_profile::load(fullRecordMismatch, active) == network_profile::LoadStatus::loaded &&
             network_profile::equal(active, previous),
         "corrupted readback leaves the persisted previous profile retained");

  FakeStore rollbackMismatch;
  expect(network_profile::stage(rollbackMismatch, previous).result == network_profile::Result::pending,
         "rollback mismatch fixture stages initial profile");
  initialTrial = network_profile::boot(rollbackMismatch, 1);
  expect(network_profile::confirm(rollbackMismatch,
                                  network_profile::tokenForStaticTrial(initialTrial.trial), previous.local).result ==
             network_profile::Result::committed,
         "rollback mismatch fixture commits previous profile");
  expect(network_profile::stage(rollbackMismatch, next).result == network_profile::Result::pending,
         "rollback mismatch fixture stages candidate");
  initialTrial = network_profile::boot(rollbackMismatch, 2);
  rollbackMismatch.corruptReadbackAfterPut = true;
  const network_profile::BootResult uncertainRollback = network_profile::boot(rollbackMismatch, 3);
  expect(uncertainRollback.result == network_profile::Result::indeterminate &&
             uncertainRollback.action == network_profile::BootAction::none,
         "corrupted rollback readback cannot claim or apply rollback");
  rollbackMismatch.corruptReadback = false;
  expect(network_profile::load(rollbackMismatch, active) == network_profile::LoadStatus::loaded &&
             network_profile::equal(active, previous),
         "uncertain rollback retains the previous profile without reboot looping");

  FakeStore malformed;
  malformed.present = true;
  malformed.value.assign(network_profile::RECORD_SIZE - 1, 0);
  expect(network_profile::load(malformed, active) == network_profile::LoadStatus::invalid && active.dhcp,
         "truncated record fails safe to DHCP");
  malformed.value.assign(network_profile::RECORD_SIZE, 0);
  expect(network_profile::load(malformed, active) == network_profile::LoadStatus::invalid && active.dhcp,
         "bad schema or checksum fails safe to DHCP");

  FakeStore rollbackFailure;
  expect(network_profile::stage(rollbackFailure, candidate).result == network_profile::Result::pending, "rollback failure trial staged");
  network_profile::BootResult booted = network_profile::boot(rollbackFailure, 1);
  rollbackFailure.putWritesThenFails = true;
  network_profile::BootResult failed = network_profile::boot(rollbackFailure, 2);
  expect((failed.result == network_profile::Result::ioerror ||
          failed.result == network_profile::Result::indeterminate) &&
             failed.action == network_profile::BootAction::none,
         "rollback write uncertainty does not request an infinite reboot");
  (void)booted;

  FakeStore resetStore;
  resetStore.present = true;
  resetStore.value.assign(network_profile::RECORD_SIZE, 0);
  expect(network_profile::reset(resetStore) == network_profile::Result::committed && !resetStore.present && resetStore.otherPresent,
         "reset removes only the network-owned record");
}

int main() {
  validation_cases();
  canonical_record_cases();
  invalid_dhcp_payload_cases();
  staging_and_confirmation();
  timeout_and_wrap_cases();
  storage_failure_cases();
  std::cout << "PASS production network validation, bounded trial state machine, and failure semantics\n";
  return 0;
}
