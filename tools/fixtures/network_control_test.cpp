#include "network_control.h"
#include "network_web.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

struct Store {
  bool present = false;
  bool failPut = false;
  bool failRead = false;
  size_t readCalls = 0;
  std::vector<uint8_t> bytes;
  bool isKey(const char* key) const { return std::strcmp(key, network_profile::KEY) == 0 && present; }
  size_t getBytesLength(const char* key) const { return isKey(key) ? bytes.size() : 0; }
  size_t getBytes(const char* key, void* output, size_t length) const {
    const_cast<Store*>(this)->readCalls++;
    if (!isKey(key) || failRead || bytes.size() != length) return 0;
    std::memcpy(output, bytes.data(), length);
    return length;
  }
  size_t putBytes(const char* key, const void* input, size_t length) {
    if (std::strcmp(key, network_profile::KEY) != 0 || failPut) return 0;
    bytes.assign(static_cast<const uint8_t*>(input), static_cast<const uint8_t*>(input) + length);
    present = true;
    return length;
  }
  bool remove(const char* key) {
    if (std::strcmp(key, network_profile::KEY) != 0) return false;
    present = false; bytes.clear(); return true;
  }
};

static void expect(bool condition, const char* message) {
  if (!condition) { std::cerr << "FAIL: " << message << '\n'; std::abort(); }
}

static network_profile::Profile profile() {
  return network_profile::Profile::staticProfile(network_profile::IPv4(192, 168, 5, 5),
                                                   network_profile::IPv4(192, 168, 5, 1),
                                                   network_profile::IPv4(255, 255, 255, 0),
                                                   network_profile::IPv4(1, 1, 1, 1));
}

static void controller_cases() {
  Store store;
  network_control::Controller<Store> controller(store);
  const network_profile::BootResult first = controller.boot(100);
  expect(first.action == network_profile::BootAction::useDhcp, "missing profile uses DHCP");
  expect(controller.boot(200).profile.dhcp, "boot is idempotent and does not reset its deadline");
  expect(controller.stage(profile()).result == network_profile::Result::pending, "candidate is staged");
  network_control::Controller<Store> rebooted(store);
  const network_profile::BootResult trial = rebooted.boot(1000);
  expect(trial.action == network_profile::BootAction::applyCandidate && rebooted.trialActive(), "boot marks candidate trial");
  const network_profile::IPv4 wrong(192, 168, 5, 6);
  expect(network_control::matchesExpectedTrialIP(rebooted.trial(), profile().local), "static trial exposes exact candidate IP");
  expect(!network_control::matchesExpectedTrialIP(rebooted.trial(), wrong), "wrong socket IP cannot gate trial");
  const network_profile::ConfirmationToken token = network_profile::tokenForStaticTrial(rebooted.trial());
  expect(rebooted.confirm(token, wrong).result == network_profile::Result::reverted, "wrong IP cannot confirm");
  expect(rebooted.confirm(token, profile().local).result == network_profile::Result::committed, "matching socket IP confirms");

  Store timeoutStore;
  expect(network_profile::stage(timeoutStore, profile()).result == network_profile::Result::pending, "timeout profile stages");
  network_control::Controller<Store> timeoutBoot(timeoutStore);
  timeoutBoot.boot(10);
  expect(timeoutBoot.service(10 + network_profile::TRIAL_TIMEOUT_MS - 1).result == network_profile::Result::pending,
         "deadline remains pending before 180 seconds");
  expect(timeoutBoot.service(10 + network_profile::TRIAL_TIMEOUT_MS).result == network_profile::Result::reverted,
         "deadline persists rollback at 180 seconds");

  Store failureStore;
  expect(network_profile::stage(failureStore, profile()).result == network_profile::Result::pending, "failure profile stages");
  network_control::Controller<Store> failureBoot(failureStore);
  failureBoot.boot(1);
  failureStore.failPut = true;
  expect(failureBoot.service(1 + network_profile::TRIAL_TIMEOUT_MS).result != network_profile::Result::reverted,
         "indeterminate rollback never claims verified recovery");
  expect(failureBoot.status() == network_control::Status::storageError, "storage error remains visible");
  const size_t readsAfterFault = failureStore.readCalls;
  failureBoot.service(1 + network_profile::TRIAL_TIMEOUT_MS + 1000);
  expect(failureStore.readCalls == readsAfterFault,
         "storage error stops repeated expire() retries on every service() tick");

  Store confirmFaultStore;
  expect(network_profile::stage(confirmFaultStore, profile()).result == network_profile::Result::pending,
         "confirm-fault profile stages");
  network_control::Controller<Store> confirmFaultBoot(confirmFaultStore);
  const network_profile::BootResult confirmFaultTrial = confirmFaultBoot.boot(1);
  expect(confirmFaultTrial.action == network_profile::BootAction::applyCandidate, "confirm-fault boot marks trial");
  const network_profile::ConfirmationToken confirmFaultToken = network_profile::tokenForStaticTrial(confirmFaultBoot.trial());
  confirmFaultStore.failRead = true;
  const network_profile::ConfirmResult faultResult = confirmFaultBoot.confirm(confirmFaultToken, profile().local);
  expect(faultResult.error == network_profile::ConfirmError::storage, "indeterminate read surfaces a storage confirm error");
  expect(confirmFaultBoot.status() == network_control::Status::storageError,
         "confirm storage fault is surfaced on the controller, not silently kept as trial");
}

struct FakeNetworkAdapter {
  bool configured = false;
  bool began = false;
  bool applyProfile(const network_profile::Profile&) { configured = true; return !began; }
  bool useDhcp() { configured = true; return !began; }
  void begin() { began = true; }
};

static void action_cases() {
  FakeNetworkAdapter adapter;
  expect(network_control::handleAction(network_profile::BootAction::applyCandidate, profile(), adapter),
         "candidate action configures adapter");
  adapter.begin();
  expect(adapter.configured && adapter.began, "configuration precedes association begin");
  FakeNetworkAdapter previous;
  expect(network_control::handleAction(network_profile::BootAction::applyPrevious, profile(), previous),
         "previous action configures adapter");
  FakeNetworkAdapter dhcp;
  expect(network_control::handleAction(network_profile::BootAction::useDhcp, profile(), dhcp),
         "useDhcp action configures adapter");
  FakeNetworkAdapter none;
  expect(network_control::handleAction(network_profile::BootAction::none, profile(), none),
         "none action applies stable profile without resetting state");
}

static void policy_cases() {
  expect(network_web::authorizePost("POST", "192.168.5.5", "http://192.168.5.5", "", "network-change", "network-change") == network_web::RequestError::none,
         "same-origin explicit POST intent accepted");
  expect(network_web::authorizePost("GET", "192.168.5.5", "http://192.168.5.5", "", "network-change", "network-change") == network_web::RequestError::notPost,
         "GET cannot change network");
  expect(network_web::authorizePost("POST", "192.168.5.5", "http://192.168.5.6", "", "network-change", "network-change") == network_web::RequestError::badOrigin,
         "different origin rejected");
  expect(network_web::authorizePost("POST", "192.168.5.5", "", "", "network-change", "network-change") == network_web::RequestError::badOrigin,
         "missing Origin and Referer together is rejected, not auto-accepted");
  const network_profile::IPv4 expected(192, 168, 5, 5);
  expect(network_web::checkConfirmation(7, "7", "192.168.5.5", expected, expected, true) == network_web::RequestError::none,
         "matching revision/token/socket accepted");
  expect(network_web::checkConfirmation(8, "7", "192.168.5.5", expected, expected, true) == network_web::RequestError::staleTrial,
         "old tab revision rejected");
  expect(network_web::checkConfirmation(7, "7", "192.168.5.5", network_profile::IPv4(192,168,5,6), expected, true) == network_web::RequestError::wrongLocalIP,
         "different actual socket address rejected");
  expect(network_web::checkConfirmation(7, "7", "192.168.5.5", expected, expected, false) == network_web::RequestError::noTrial,
         "confirmation without trial rejected");
}

int main() {
  controller_cases();
  action_cases();
  policy_cases();
  std::cout << "PASS controller and web policy integration\n";
}
