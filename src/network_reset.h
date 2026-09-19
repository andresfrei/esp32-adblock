#pragma once

#include <cstddef>

#include "network_profile.h"
#include "network_web.h"
#include "upstream_config.h"

// N3 seam: connection reset (drop WiFi + network profile, force the portal)
// and factory reset (also drop upstream config and named LittleFS files).
// Arduino-free like network_control.h/network_web.h, so it stays host testable;
// the board layer (main.cpp) supplies Preferences-shaped stores (isKey/remove
// — the same surface network_profile::reset already uses, and the one the
// Arduino Preferences class implements directly) and a LittleFS-shaped
// filesystem (exists/remove), then performs the deferred restart the same
// way N2 schedules one after a staged network change.
namespace network_reset {

// main.cpp opens WiFi credentials under this exact namespace/keys in
// connectWiFi()/handleWifiSave()/"/forgetwifi"; N3 reuses them rather than
// inventing a parallel WiFi-credential representation.
static constexpr const char* WIFI_NAMESPACE = "wifi";
static constexpr const char* WIFI_SSID_KEY = "ssid";
static constexpr const char* WIFI_PASS_KEY = "pass";

enum class Result { committed, ioerror, indeterminate };

template <typename Store>
Result clearWifiCredentials(Store& store) {
  const bool hadSsid = store.isKey(WIFI_SSID_KEY);
  const bool hadPass = store.isKey(WIFI_PASS_KEY);
  if (!hadSsid && !hadPass) return Result::committed;
  const bool removedSsid = !hadSsid || store.remove(WIFI_SSID_KEY);
  const bool removedPass = !hadPass || store.remove(WIFI_PASS_KEY);
  if (!removedSsid || !removedPass) return Result::ioerror;
  return (store.isKey(WIFI_SSID_KEY) || store.isKey(WIFI_PASS_KEY)) ? Result::indeterminate : Result::committed;
}

template <typename Store>
Result clearUpstreamConfig(Store& store) {
  if (!store.isKey(upstream_config::KEY)) return Result::committed;
  if (!store.remove(upstream_config::KEY)) return Result::ioerror;
  return store.isKey(upstream_config::KEY) ? Result::indeterminate : Result::committed;
}

// Factory reset deletes only these app-state files; the blocklist binary and
// anything else on LittleFS stay untouched. Paths confirmed against
// allowlist.h ("/allowlist.txt"/"/allowlist.new" via allowlist::save's
// livePath/tempPath), blocklist_helpers.h/main.cpp's custom/banned/update.cfg
// loaders, and upstream_config.h (NVS, not a file).
static constexpr const char* FACTORY_RESET_FILES[] = {
    "/custom.txt", "/allowlist.txt", "/allowlist.new", "/banned.txt", "/update.cfg",
};
static constexpr size_t FACTORY_RESET_FILE_COUNT =
    sizeof(FACTORY_RESET_FILES) / sizeof(FACTORY_RESET_FILES[0]);

template <typename Filesystem>
bool removeIfPresent(Filesystem& fs, const char* path) {
  if (!fs.exists(path)) return true;
  return fs.remove(path);
}

// Best-effort across every path: each removal is idempotent, so a caller can
// safely retry after a partial failure instead of the whole reset silently
// stopping at the first file it could not delete.
template <typename Filesystem>
bool clearFactoryResetFiles(Filesystem& fs) {
  bool ok = true;
  for (size_t i = 0; i < FACTORY_RESET_FILE_COUNT; ++i) {
    if (!removeIfPresent(fs, FACTORY_RESET_FILES[i])) ok = false;
  }
  return ok;
}

template <typename WifiStore, typename NetworkStore>
struct ConnectionResetResult {
  Result wifi;
  network_profile::Result network;
  bool committed() const {
    return wifi == Result::committed && network == network_profile::Result::committed;
  }
};

// Drops WiFi credentials and the network profile only, which is what forces
// the portal on next boot (an empty "wifi" namespace makes connectWiFi() fall
// through to startConfigPortal() the same way "/forgetwifi" already does).
// Every other NVS namespace and LittleFS file is preserved by construction:
// this function is never given a handle to them.
template <typename WifiStore, typename NetworkStore>
ConnectionResetResult<WifiStore, NetworkStore> connectionReset(WifiStore& wifiStore, NetworkStore& networkStore) {
  ConnectionResetResult<WifiStore, NetworkStore> result;
  result.wifi = clearWifiCredentials(wifiStore);
  result.network = network_profile::reset(networkStore);
  return result;
}

struct FactoryResetResult {
  Result wifi;
  network_profile::Result network;
  Result upstream;
  bool files;
  bool committed() const {
    return wifi == Result::committed && network == network_profile::Result::committed &&
           upstream == Result::committed && files;
  }
};

// Drops WiFi credentials, the network profile, and upstream config, and
// deletes the named app-state files. Defaults (DHCP/Quad9/blocking-on) are
// never written back here: each module's existing missing-key/missing-file
// fallback path (network_profile::load, loadUpstreamConfig's LoadResult
// handling, loadCustom/loadAllow/loadBanned/loadUpdateCfg's "file missing"
// early return) re-creates them the next time the device boots.
template <typename WifiStore, typename NetworkStore, typename UpstreamStore, typename Filesystem>
FactoryResetResult factoryReset(WifiStore& wifiStore, NetworkStore& networkStore, UpstreamStore& upstreamStore,
                                Filesystem& fs) {
  FactoryResetResult result;
  result.wifi = clearWifiCredentials(wifiStore);
  result.network = network_profile::reset(networkStore);
  result.upstream = clearUpstreamConfig(upstreamStore);
  result.files = clearFactoryResetFiles(fs);
  return result;
}

// HTTP policy layer, mirroring network_web::authorizePost exactly (same-origin
// POST + explicit intent — never a weaker check). Resets add one more
// rejection: any updater/OTA operation in progress. Method/origin/intent are
// checked first, so a request that is invalid for other reasons never learns
// whether the device happens to be mid-update.
enum class RequestError { none, notPost, badOrigin, missingIntent, updateInProgress };

inline RequestError authorize(const char* method, const char* host, const char* origin, const char* referer,
                              const char* intent, const char* expectedIntent, bool updateInProgress) {
  const network_web::RequestError webError =
      network_web::authorizePost(method, host, origin, referer, intent, expectedIntent);
  switch (webError) {
    case network_web::RequestError::notPost: return RequestError::notPost;
    case network_web::RequestError::badOrigin: return RequestError::badOrigin;
    case network_web::RequestError::missingIntent: return RequestError::missingIntent;
    default: break;
  }
  if (updateInProgress) return RequestError::updateInProgress;
  return RequestError::none;
}

inline const char* errorText(RequestError error) {
  switch (error) {
    case RequestError::none: return "ok";
    case RequestError::notPost: return "POST required";
    case RequestError::badOrigin: return "same-origin request required";
    case RequestError::missingIntent: return "explicit reset intent required";
    case RequestError::updateInProgress: return "a blocklist or firmware update is in progress; try again after it finishes";
  }
  return "reset request rejected";
}

}  // namespace network_reset
