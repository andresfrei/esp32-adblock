#include "upstream_config.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

struct FakeStore {
  bool keyPresent = false;
  bool failPut = false;
  bool failGet = false;
  std::string value;

  bool isKey(const char* key) const {
    return std::strcmp(key, upstream_config::KEY) == 0 && keyPresent;
  }

  size_t getString(const char* key, char* output, size_t capacity) const {
    if (std::strcmp(key, upstream_config::KEY) != 0 || failGet || !keyPresent) return 0;
    const size_t length = value.size();
    if (capacity > 0) {
      const size_t copied = length < capacity - 1 ? length : capacity - 1;
      std::memcpy(output, value.data(), copied);
      output[copied] = '\0';
    }
    return length;
  }

  size_t putString(const char* key, const char* input) {
    if (std::strcmp(key, upstream_config::KEY) != 0 || failPut) return 0;
    value = input;
    keyPresent = true;
    return value.size();
  }
};

static void expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    std::abort();
  }
}

static void expectValid(const char* text, const upstream_config::IPv4* self = nullptr) {
  upstream_config::IPv4 parsed;
  expect(upstream_config::validate(text, parsed, self) == upstream_config::Error::none, text);
}

static void expectInvalid(const char* text, upstream_config::Error expected,
                          const upstream_config::IPv4* self = nullptr) {
  upstream_config::IPv4 parsed;
  expect(upstream_config::validate(text, parsed, self) == expected, text);
}

static void validation_cases() {
  expectValid("9.9.9.9");
  expectValid("1.1.1.1");
  expectValid("10.0.0.1");
  expectValid("172.16.0.1");
  expectValid("192.168.1.1");

  expectInvalid("", upstream_config::Error::empty);
  expectInvalid("1.2.3", upstream_config::Error::malformed);
  expectInvalid("1.2.3.4.5", upstream_config::Error::malformed);
  expectInvalid("1.2.3.x", upstream_config::Error::malformed);
  expectInvalid("256.2.3.4", upstream_config::Error::malformed);
  expectInvalid("1..3.4", upstream_config::Error::malformed);
  expectInvalid("01.2.3.4", upstream_config::Error::malformed);
  expectInvalid("1.2.3.4 ", upstream_config::Error::malformed);
  expectInvalid("1.2.3.4:53", upstream_config::Error::malformed);
  expectInvalid("http://1.2.3.4", upstream_config::Error::malformed);
  expectInvalid("dns.example", upstream_config::Error::malformed);

  expectInvalid("0.0.0.0", upstream_config::Error::unspecified);
  expectInvalid("255.255.255.255", upstream_config::Error::broadcast);
  expectInvalid("224.0.0.1", upstream_config::Error::multicast);
  expectInvalid("239.255.255.255", upstream_config::Error::multicast);
  expectInvalid("127.0.0.1", upstream_config::Error::loopback);

  const upstream_config::IPv4 self(192, 168, 1, 20);
  expectInvalid("192.168.1.20", upstream_config::Error::selfAddress, &self);
  expectValid("192.168.1.21", &self);
}

static void persistence_cases() {
  FakeStore store;
  upstream_config::IPv4 active(9, 9, 9, 9);
  upstream_config::IPv4 self(192, 168, 1, 20);
  expect(upstream_config::load(store, active, &self) == upstream_config::LoadResult::missing,
         "missing NVS key uses default owned by caller");

  FakeStore unreadableBootStore;
  unreadableBootStore.keyPresent = true;
  unreadableBootStore.value = "1.1.1.1";
  unreadableBootStore.failGet = true;
  upstream_config::IPv4 bootActive(9, 9, 9, 9);
  expect(upstream_config::load(unreadableBootStore, bootActive, &self) ==
             upstream_config::LoadResult::invalid,
         "NVS readback failure makes the stored boot value invalid");
  expect(upstream_config::same(bootActive, upstream_config::IPv4(9, 9, 9, 9)),
         "unreadable boot storage leaves the caller's default active");

  upstream_config::Error error = upstream_config::Error::none;
  expect(upstream_config::apply(store, active, "192.168.1.1", &self, error) == true,
         "private router address applies");
  expect(upstream_config::same(active, upstream_config::IPv4(192, 168, 1, 1)),
         "active changes only after verified persistence");
  expect(store.value == "192.168.1.1", "canonical address is persisted");

  upstream_config::IPv4 loaded(9, 9, 9, 9);
  expect(upstream_config::load(store, loaded, &self) == upstream_config::LoadResult::loaded,
         "persisted address loads");
  expect(upstream_config::same(loaded, active), "loaded address matches active address");

  store.value = "192.168.1.20";
  expect(upstream_config::load(store, loaded, &self) == upstream_config::LoadResult::invalid,
         "stored self address is invalid for current station");

  const upstream_config::IPv4 changedSelf(192, 168, 1, 1);
  error = upstream_config::Error::none;
  expect(upstream_config::apply(store, active, "192.168.1.1", &changedSelf, error) == false &&
             error == upstream_config::Error::selfAddress,
         "startup DHCP change rejects a newly self-addressed upstream");
  expect(upstream_config::same(active, upstream_config::IPv4(192, 168, 1, 1)),
         "validation failure leaves active address unchanged");

  store.failPut = true;
  error = upstream_config::Error::none;
  expect(upstream_config::apply(store, active, "1.1.1.1", &self, error) == false &&
             error == upstream_config::Error::persistence,
         "put failure is reported");
  expect(upstream_config::same(active, upstream_config::IPv4(192, 168, 1, 1)),
         "persistence failure leaves active address unchanged");

  store.failPut = false;
  store.failGet = true;
  error = upstream_config::Error::none;
  expect(upstream_config::apply(store, active, "1.1.1.1", &self, error) == false &&
             error == upstream_config::Error::persistence,
         "readback failure is reported as persistence failure");
  expect(upstream_config::same(active, upstream_config::IPv4(192, 168, 1, 1)),
         "readback failure leaves active address unchanged");
  expect(store.value == "1.1.1.1",
         "readback failure does not claim to roll back the already-written store value");
}

int main() {
  validation_cases();
  persistence_cases();
  std::cout << "PASS upstream IPv4 validation, NVS seam, and apply ordering\n";
  return 0;
}
