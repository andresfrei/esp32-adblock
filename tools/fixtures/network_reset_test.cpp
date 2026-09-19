#include "network_reset.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <set>
#include <string>

// Preferences-shaped fake: matches the isKey/remove surface network_profile
// already exercises in network_control_test.cpp, generalized to hold several
// named keys so one fake type can stand in for the wifi/network/upstream
// namespaces separately.
struct FakeStore {
  std::set<std::string> keys;
  bool failRemove = false;
  // Simulates a verified-readback mismatch: remove() reports success but the
  // key is still observed present afterward (network_profile::reset's own
  // indeterminate case works the same way).
  bool staleAfterRemove = false;

  void seed(const char* key) { keys.insert(key); }
  bool isKey(const char* key) const { return keys.count(key) != 0; }
  bool remove(const char* key) {
    if (failRemove) return false;
    if (staleAfterRemove) return true;
    keys.erase(key);
    return true;
  }
};

struct FakeFilesystem {
  std::set<std::string> files;
  std::set<std::string> failRemovePaths;

  void seed(const char* path) { files.insert(path); }
  bool exists(const char* path) const { return files.count(path) != 0; }
  bool remove(const char* path) {
    if (failRemovePaths.count(path)) return false;
    files.erase(path);
    return true;
  }
};

static void expect(bool condition, const char* message) {
  if (!condition) { std::cerr << "FAIL: " << message << '\n'; std::abort(); }
}

static void clear_wifi_credentials_cases() {
  FakeStore populated;
  populated.seed(network_reset::WIFI_SSID_KEY);
  populated.seed(network_reset::WIFI_PASS_KEY);
  expect(network_reset::clearWifiCredentials(populated) == network_reset::Result::committed,
         "clearing populated wifi credentials commits");
  expect(!populated.isKey(network_reset::WIFI_SSID_KEY) && !populated.isKey(network_reset::WIFI_PASS_KEY),
         "wifi ssid/pass keys removed");

  FakeStore empty;
  expect(network_reset::clearWifiCredentials(empty) == network_reset::Result::committed,
         "clearing already-empty wifi credentials is a no-op commit");

  FakeStore failing;
  failing.seed(network_reset::WIFI_SSID_KEY);
  failing.failRemove = true;
  expect(network_reset::clearWifiCredentials(failing) == network_reset::Result::ioerror,
         "wifi credential remove failure reports ioerror");

  FakeStore stale;
  stale.seed(network_reset::WIFI_PASS_KEY);
  stale.staleAfterRemove = true;
  expect(network_reset::clearWifiCredentials(stale) == network_reset::Result::indeterminate,
         "wifi credential key surviving remove() reports indeterminate");
}

static void clear_upstream_config_cases() {
  FakeStore populated;
  populated.seed(upstream_config::KEY);
  expect(network_reset::clearUpstreamConfig(populated) == network_reset::Result::committed,
         "clearing populated upstream config commits");
  expect(!populated.isKey(upstream_config::KEY), "upstream ip key removed");

  FakeStore empty;
  expect(network_reset::clearUpstreamConfig(empty) == network_reset::Result::committed,
         "clearing already-missing upstream config is a no-op commit");

  FakeStore failing;
  failing.seed(upstream_config::KEY);
  failing.failRemove = true;
  expect(network_reset::clearUpstreamConfig(failing) == network_reset::Result::ioerror,
         "upstream config remove failure reports ioerror");
}

static void connection_reset_preserves_other_state() {
  FakeStore wifiStore;
  wifiStore.seed(network_reset::WIFI_SSID_KEY);
  wifiStore.seed(network_reset::WIFI_PASS_KEY);
  FakeStore networkStore;
  networkStore.seed(network_profile::KEY);

  // Untouched by connectionReset: it never receives a handle to these.
  FakeStore upstreamStore;
  upstreamStore.seed(upstream_config::KEY);
  FakeFilesystem fs;
  fs.seed("/blocklist.bin");
  fs.seed("/custom.txt");
  fs.seed("/allowlist.txt");
  fs.seed("/banned.txt");
  fs.seed("/update.cfg");

  const auto result = network_reset::connectionReset(wifiStore, networkStore);
  expect(result.committed(), "connection reset commits wifi + network");
  expect(!wifiStore.isKey(network_reset::WIFI_SSID_KEY) && !wifiStore.isKey(network_reset::WIFI_PASS_KEY),
         "connection reset clears wifi credentials");
  expect(!networkStore.isKey(network_profile::KEY), "connection reset clears the network profile");

  expect(upstreamStore.isKey(upstream_config::KEY), "connection reset preserves upstream DNS config");
  expect(fs.exists("/custom.txt") && fs.exists("/allowlist.txt") && fs.exists("/banned.txt") &&
             fs.exists("/update.cfg"),
         "connection reset preserves allowlist/bans/update-state files");
  expect(fs.exists("/blocklist.bin"), "connection reset preserves the blocklist binary");
}

static void factory_reset_clears_named_files_and_config() {
  FakeStore wifiStore;
  wifiStore.seed(network_reset::WIFI_SSID_KEY);
  wifiStore.seed(network_reset::WIFI_PASS_KEY);
  FakeStore networkStore;
  networkStore.seed(network_profile::KEY);
  FakeStore upstreamStore;
  upstreamStore.seed(upstream_config::KEY);
  FakeFilesystem fs;
  fs.seed("/blocklist.bin");
  fs.seed("/custom.txt");
  fs.seed("/allowlist.txt");
  fs.seed("/allowlist.new");
  fs.seed("/banned.txt");
  fs.seed("/update.cfg");
  fs.seed("/other.txt");  // sanity: factory reset is not a blanket LittleFS wipe

  const auto result = network_reset::factoryReset(wifiStore, networkStore, upstreamStore, fs);
  expect(result.committed(), "factory reset commits wifi + network + upstream + files");
  expect(!wifiStore.isKey(network_reset::WIFI_SSID_KEY) && !wifiStore.isKey(network_reset::WIFI_PASS_KEY),
         "factory reset clears wifi credentials");
  expect(!networkStore.isKey(network_profile::KEY), "factory reset clears the network profile");
  expect(!upstreamStore.isKey(upstream_config::KEY), "factory reset clears upstream DNS config");
  expect(!fs.exists("/custom.txt") && !fs.exists("/allowlist.txt") && !fs.exists("/allowlist.new") &&
             !fs.exists("/banned.txt") && !fs.exists("/update.cfg"),
         "factory reset deletes the named app-state files");

  expect(fs.exists("/blocklist.bin"), "factory reset preserves the blocklist binary");
  expect(fs.exists("/other.txt"), "factory reset does not touch unrelated files");
}

static void factory_reset_file_removal_partial_failure_is_visible() {
  FakeStore wifiStore, networkStore, upstreamStore;
  FakeFilesystem fs;
  fs.seed("/custom.txt");
  fs.seed("/banned.txt");
  fs.failRemovePaths.insert("/custom.txt");

  const auto result = network_reset::factoryReset(wifiStore, networkStore, upstreamStore, fs);
  expect(!result.files, "a single file removal failure is reported");
  expect(!result.committed(), "factory reset is not reported committed on partial file failure");
  expect(!fs.exists("/banned.txt"), "removal continues best-effort past one failure");
  expect(fs.exists("/custom.txt"), "the failed removal leaves that file in place");
}

static void authorize_rejects_non_post_and_wrong_origin() {
  const char* host = "192.168.5.5";
  const char* origin = "http://192.168.5.5";
  const char* intent = "connection-reset";
  expect(network_reset::authorize("POST", host, origin, "", intent, intent, false) ==
             network_reset::RequestError::none,
         "same-origin POST with matching intent is accepted");
  expect(network_reset::authorize("GET", host, origin, "", intent, intent, false) ==
             network_reset::RequestError::notPost,
         "GET cannot trigger a reset");
  expect(network_reset::authorize("POST", host, "http://evil.example", "", intent, intent, false) ==
             network_reset::RequestError::badOrigin,
         "cross-origin POST is rejected");
  expect(network_reset::authorize("POST", host, origin, "", "wrong-intent", intent, false) ==
             network_reset::RequestError::missingIntent,
         "mismatched intent is rejected");
}

static void authorize_rejects_while_update_in_progress() {
  const char* host = "192.168.5.5";
  const char* origin = "http://192.168.5.5";
  const char* intent = "factory-reset";
  expect(network_reset::authorize("POST", host, origin, "", intent, intent, true) ==
             network_reset::RequestError::updateInProgress,
         "an otherwise-valid reset is rejected while an update/OTA is in progress");
  expect(network_reset::authorize("GET", host, origin, "", intent, intent, true) ==
             network_reset::RequestError::notPost,
         "method/origin/intent are still checked first: notPost outranks updateInProgress");
}

int main() {
  clear_wifi_credentials_cases();
  clear_upstream_config_cases();
  connection_reset_preserves_other_state();
  factory_reset_clears_named_files_and_config();
  factory_reset_file_removal_partial_failure_is_visible();
  authorize_rejects_non_post_and_wrong_origin();
  authorize_rejects_while_update_in_progress();
  std::cout << "PASS connection/factory reset and HTTP policy\n";
}
