// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "board_config.h"
#include "wifi_credentials.h"  // private secrets.h values, or empty defaults when absent
#include "wifi_portal.h"
#include "domain_rules.h"
#include "allowlist.h"
#include "dns_query.h"
#include "blocklist_helpers.h"
#include "upstream_config.h"
#include "network_profile.h"
#include "network_control.h"
#include "network_web.h"
#include "network_reset.h"

// ---- config ----
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File liveBlocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[600];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_ALLOW = static_cast<int>(allowlist::MAX_ENTRIES);
String allowDom[MAX_ALLOW]; int numAllow = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";
static bool blocklistStorageReady = false;

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;

// Upstream DNS is stored in its own NVS namespace so firmware-only OTA keeps
// it independently of LittleFS and the WiFi credential namespace.
static const upstream_config::IPv4 DEFAULT_UPSTREAM(9, 9, 9, 9);
static upstream_config::IPv4 upstreamAddress = DEFAULT_UPSTREAM;
static Preferences upstreamPrefs;
static bool upstreamPrefsReady = false;
static bool upstreamLoopGuardReported = false;

#if AD_BLOCK_NETWORK_PROFILE_ENABLED
static Preferences networkProfilePrefs;
static bool networkProfilePrefsReady = false;
static network_control::Controller<Preferences>* networkController = nullptr;
static network_profile::BootResult networkBootResult;
static network_profile::Profile networkProfile = network_profile::Profile::dhcpProfile();
static bool networkRestartPending = false;
static uint32_t networkRestartAt = 0;
static bool networkRecoveryVisible = false;
static network_profile::Result networkLastResult = network_profile::Result::pending;
#endif

String      portalOpts;             // <option> list of scanned networks, built once at portal start
String      portalSsids[WIFI_PORTAL_MAX_NETWORKS];
size_t      portalNetworkCount = 0;
static bool portalRestartPending = false;
static uint32_t portalRestartAt = 0;

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static bool inFlash(uint64_t h) {
  int32_t lo = 0, hi = (int32_t)numHashes - 1; uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    liveBlocklist.seek((uint32_t)mid * HASH_BYTES); liveBlocklist.read(b, HASH_BYTES);
    uint64_t v = 0; for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid - 1; else return true;
  }
  return false;
}
static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool domainHashMatch(const char* domain, size_t length, void*) {
  const uint64_t hash = fnv40(domain, length);
  return inFlash(hash) || inCustom(hash);
}
static bool isBlocked(const char* domain) {
  return domain_rules::suffixDenied(domain, domainHashMatch, nullptr);
}
static bool isAllowedExact(const char* domain) {
  return allowlist::contains(allowDom, static_cast<size_t>(numAllow), domain);
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }

static void loadAllow() {
  numAllow = 0;
  File f = LittleFS.open("/allowlist.txt", "r");
  if (!f) return;
  numAllow = static_cast<int>(allowlist::load(f, allowDom, MAX_ALLOW));
  f.close();
}

static bool saveAllow(size_t skipIndex = allowlist::NO_SKIP, const char* appendValue = nullptr) {
  return allowlist::save(LittleFS, "/allowlist.txt", "/allowlist.new", allowDom,
                         static_cast<size_t>(numAllow), appendValue, skipIndex);
}

enum class AllowUpdate { added, removed, duplicate, missing, invalid, full, persistenceFailed };

static AllowUpdate addAllow(String value) {
  char normalized[domain_rules::MAX_DOMAIN_LENGTH + 1];
  if (!value) return AllowUpdate::persistenceFailed;
  if (!domain_rules::normalize(value.c_str(), normalized, sizeof(normalized))) return AllowUpdate::invalid;
  if (isAllowedExact(normalized)) return AllowUpdate::duplicate;
  if (numAllow >= MAX_ALLOW) return AllowUpdate::full;
  size_t count = static_cast<size_t>(numAllow);
  const bool committed = allowlist::commitAdd<String>(
      allowDom, count, MAX_ALLOW, normalized,
      [](const char* candidate) { return saveAllow(allowlist::NO_SKIP, candidate); });
  if (!committed) return AllowUpdate::persistenceFailed;
  numAllow = static_cast<int>(count);
  return AllowUpdate::added;
}

static AllowUpdate removeAllow(String value) {
  char normalized[domain_rules::MAX_DOMAIN_LENGTH + 1];
  if (!value) return AllowUpdate::persistenceFailed;
  if (!domain_rules::normalize(value.c_str(), normalized, sizeof(normalized))) return AllowUpdate::invalid;
  int index = -1;
  for (int i = 0; i < numAllow; ++i) {
    if (allowlist::contains(allowDom + i, 1, normalized)) { index = i; break; }
  }
  if (index < 0) return AllowUpdate::missing;
  size_t count = static_cast<size_t>(numAllow);
  const bool committed = allowlist::commitRemove(
      allowDom, count, static_cast<size_t>(index),
      [](size_t skipIndex) { return saveAllow(skipIndex); });
  if (!committed) return AllowUpdate::persistenceFailed;
  numAllow = static_cast<int>(count);
  return AllowUpdate::removed;
}

static int allowHttpStatus(AllowUpdate result) {
  switch (result) {
    case AllowUpdate::added:
    case AllowUpdate::removed:
    case AllowUpdate::duplicate: return 200;
    case AllowUpdate::missing: return 404;
    case AllowUpdate::invalid:
    case AllowUpdate::full: return 400;
    case AllowUpdate::persistenceFailed: return 500;
  }
  return 500;
}
static const char* allowResultText(AllowUpdate result) {
  switch (result) {
    case AllowUpdate::added: return "added";
    case AllowUpdate::removed: return "removed";
    case AllowUpdate::duplicate: return "already present";
    case AllowUpdate::missing: return "not found";
    case AllowUpdate::invalid: return "invalid domain";
    case AllowUpdate::full: return "allowlist full";
    case AllowUpdate::persistenceFailed: return "allowlist persistence failed";
  }
  return "allowlist update failed";
}

static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- upstream DNS configuration ----------
static upstream_config::IPv4 localIPv4() {
  const IPAddress address = WiFi.localIP();
  return upstream_config::IPv4(address[0], address[1], address[2], address[3]);
}

static String upstreamText() {
  char text[upstream_config::TEXT_CAPACITY] = {};
  upstream_config::format(upstreamAddress, text, sizeof(text));
  return String(text);
}

static void loadUpstreamConfig() {
  upstreamAddress = DEFAULT_UPSTREAM;
  upstreamPrefsReady = upstreamPrefs.begin(upstream_config::NAMESPACE, false);
  if (!upstreamPrefsReady) {
    Serial.println("[setup] upstream NVS open failed; using default 9.9.9.9");
    return;
  }

  const upstream_config::IPv4 self = localIPv4();
  const upstream_config::LoadResult result =
      upstream_config::load(upstreamPrefs, upstreamAddress, &self);
  if (result == upstream_config::LoadResult::loaded) {
    Serial.printf("upstream DNS: %s\n", upstreamText().c_str());
  } else if (result == upstream_config::LoadResult::invalid) {
    upstreamAddress = DEFAULT_UPSTREAM;
    Serial.println("[setup] stored upstream IPv4 invalid or self-addressed; using default 9.9.9.9");
  } else {
    Serial.println("[setup] no stored upstream IPv4; using default 9.9.9.9");
  }
}

#if AD_BLOCK_NETWORK_PROFILE_ENABLED
static network_profile::IPv4 networkIPv4(const IPAddress& address) {
  return network_profile::IPv4(address[0], address[1], address[2], address[3]);
}

static IPAddress networkIPAddress(const network_profile::IPv4& address) {
  return IPAddress(address.octets[0], address.octets[1], address.octets[2], address.octets[3]);
}

static String networkIPv4Text(const network_profile::IPv4& address) {
  return networkIPAddress(address).toString();
}

static bool networkSame(const network_profile::IPv4& left, const upstream_config::IPv4& right) {
  return left.octets[0] == right.octets[0] && left.octets[1] == right.octets[1] &&
         left.octets[2] == right.octets[2] && left.octets[3] == right.octets[3];
}

static bool networkApplyProfile(const network_profile::Profile& profile) {
  if (profile.dhcp) {
    return WiFi.config(IPAddress(0, 0, 0, 0), IPAddress(0, 0, 0, 0),
                       IPAddress(0, 0, 0, 0), IPAddress(0, 0, 0, 0));
  }
  return WiFi.config(networkIPAddress(profile.local), networkIPAddress(profile.gateway),
                     networkIPAddress(profile.netmask), networkIPAddress(profile.dnsIPv4));
}

struct ArduinoNetworkAdapter {
  bool applyProfile(const network_profile::Profile& profile) { return networkApplyProfile(profile); }
  bool useDhcp() { return networkApplyProfile(network_profile::Profile::dhcpProfile()); }
};

static void networkBootOnce() {
  networkProfilePrefsReady = networkProfilePrefs.begin(network_profile::NAMESPACE, false);
  if (!networkProfilePrefsReady) {
    networkBootResult = network_profile::BootResult();
    networkBootResult.result = network_profile::Result::indeterminate;
    networkBootResult.action = network_profile::BootAction::useDhcp;
    networkBootResult.profile = network_profile::Profile::dhcpProfile();
    networkProfile = network_profile::Profile::dhcpProfile();
    Serial.println("[network] NVS namespace unavailable; using DHCP, network changes disabled");
    return;
  }
  networkController = new network_control::Controller<Preferences>(networkProfilePrefs);
  networkBootResult = networkController->boot(millis());
  networkProfile = networkBootResult.profile;
  Serial.printf("[network] boot result=%d action=%d mode=%s\n",
                static_cast<int>(networkBootResult.result),
                static_cast<int>(networkBootResult.action), networkProfile.dhcp ? "DHCP" : "static");
  if (networkBootResult.diagnostic) Serial.println("[network] invalid or indeterminate record; conservative DHCP fallback");
  if (networkController->trialActive()) Serial.printf("[network] trial revision %lu started\n",
                                                        static_cast<unsigned long>(networkController->trial().revision));
}

static bool networkOriginAllowed(const char* intent) {
  const String host = web.hostHeader();
  const String origin = web.header("Origin");
  const String referer = web.header("Referer");
  return network_web::authorizePost("POST", host.c_str(), origin.c_str(), referer.c_str(),
                                    web.arg("intent").c_str(), intent) == network_web::RequestError::none;
}

static bool networkBuildCandidate(const String& mode, const String& ip, const String& mask,
                                  const String& gateway, const String& dns,
                                  network_profile::Profile& candidate, String& error) {
  if (mode == "dhcp") {
    candidate = network_profile::Profile::dhcpProfile();
    return true;
  }
  if (mode != "static") { error = "invalid network mode"; return false; }
  network_profile::IPv4 local, netmask, gatewayAddress, resolver;
  if (!network_profile::parseIPv4(ip.c_str(), local) ||
      !network_profile::parseIPv4(mask.c_str(), netmask) ||
      !network_profile::parseIPv4(gateway.c_str(), gatewayAddress) ||
      !network_profile::parseIPv4(dns.c_str(), resolver)) {
    error = "invalid IPv4 field";
    return false;
  }
  candidate = network_profile::Profile::staticProfile(local, gatewayAddress, netmask, resolver);
  const network_profile::ValidationError validation = network_profile::validate(candidate);
  if (validation != network_profile::ValidationError::none) {
    error = network_profile::errorText(validation);
    return false;
  }
  if (networkSame(local, upstreamAddress)) {
    error = "network address cannot equal configured upstream DNS";
    return false;
  }
  return true;
}

static bool networkStatusVisible(const network_profile::Profile& profile,
                                 const network_profile::TrialSession* trial,
                                 const network_profile::IPv4& caller) {
  if (!network_profile::validUnicast(caller)) return false;
  if (trial) return network_control::matchesExpectedTrialIP(*trial, caller);
  if (profile.dhcp) return network_profile::same(caller, networkIPv4(WiFi.localIP()));
  return network_profile::same(caller, profile.local) &&
         network_profile::same(caller, networkIPv4(WiFi.localIP()));
}

static String networkStatusJson(const network_profile::IPv4& caller) {
  if (!networkController || !networkProfilePrefsReady) return "{\"available\":false}";
  const network_profile::TrialSession* trial = networkController->trialActive() ? &networkController->trial() : nullptr;
  if (!networkStatusVisible(networkProfile, trial, caller)) return "{\"available\":true,\"network\":null}";
  const network_profile::Profile& profile = trial ? trial->candidate : networkProfile;
  const network_profile::IPv4 expected = profile.dhcp ? caller : profile.local;
  String json = "{\"available\":true,\"network\":{\"mode\":\"";
  json += profile.dhcp ? "dhcp" : "static";
  json += "\",\"local\":\"" + networkIPv4Text(profile.local) + "\",\"mask\":\"" +
          networkIPv4Text(profile.netmask) + "\",\"gateway\":\"" + networkIPv4Text(profile.gateway) +
          "\",\"dns\":\"" + networkIPv4Text(profile.dnsIPv4) + "\",\"currentIP\":\"" +
          networkIPv4Text(caller) + "\",\"newURL\":\"http://" + networkIPv4Text(expected) + "/\",\"status\":\"" +
          network_control::statusText(networkController->status()) + "\"";
  if (trial) {
    uint32_t remaining = network_profile::TRIAL_TIMEOUT_MS;
    const uint32_t elapsed = millis() - trial->startedAt;
    if (elapsed < network_profile::TRIAL_TIMEOUT_MS) remaining -= elapsed;
    else remaining = 0;
    json += ",\"revision\":" + String(trial->revision) + ",\"token\":\"" + networkIPv4Text(expected) +
            "\",\"remainingMs\":" + String(remaining);
  }
  json += "}}";
  return json;
}

static void networkScheduleRestart() {
  networkRestartPending = true;
  networkRestartAt = millis() + 1000UL;
}

static void networkService() {
  if (!networkController || !networkController->trialActive()) return;
  const network_profile::ExpireResult result = networkController->service(millis());
  networkLastResult = result.result;
  if (result.result == network_profile::Result::reverted) {
    networkProfile = result.profile;
    networkRecoveryVisible = true;
    if (!networkRestartPending) networkScheduleRestart();
    Serial.println("[network] trial expired; rollback persisted and restart scheduled");
  } else if (result.result == network_profile::Result::ioerror ||
             result.result == network_profile::Result::indeterminate) {
    networkRecoveryVisible = true;
    Serial.println("[network] trial rollback storage result indeterminate; restart suppressed");
  }
}

static void networkRestartService() {
  if (networkRestartPending && static_cast<int32_t>(millis() - networkRestartAt) >= 0) {
    networkRestartPending = false;
    ESP.restart();
  }
}
#endif

// ---------- DNS ----------
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int forwardUpstream(int qlen) {
  // DHCP can change the station address after boot. Never send DNS to our own
  // port 53: that would create a self-forward loop instead of an upstream.
  const upstream_config::IPv4 self = localIPv4();
  if (upstream_config::same(upstreamAddress, self)) {
    if (!upstreamLoopGuardReported) {
      Serial.println("[dns] upstream equals current WiFi address; forwarding skipped");
      upstreamLoopGuardReported = true;
    }
    return 0;
  }
  upstreamLoopGuardReported = false;
  const IPAddress target(upstreamAddress.octets[0], upstreamAddress.octets[1],
                         upstreamAddress.octets[2], upstreamAddress.octets[3]);
  upstreamCli.beginPacket(target, 53); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 1000) { int sz = upstreamCli.parsePacket(); if (sz > 0) return upstreamCli.read(buf, sizeof(buf)); delay(1); }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = dns_query::parseQuery(buf, qlen, domain, sizeof(domain), &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    const bool domainDenied = dl && isBlocked(domain);
    const bool exactAllowed = dl && isAllowedExact(domain);
    const bool blocked = domain_rules::shouldBlock(ban, blockingOn, exactAllowed, domainDenied);
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleUpstream() {
  if (!upstreamPrefsReady) {
    web.send(500, "text/plain", "upstream NVS unavailable");
    return;
  }
  upstream_config::Error error = upstream_config::Error::none;
  const upstream_config::IPv4 self = localIPv4();
  const bool applied = upstream_config::apply(
      upstreamPrefs, upstreamAddress, web.arg("ip").c_str(), &self, error);
  if (!applied) {
    const int status = error == upstream_config::Error::persistence ? 500 : 400;
    web.send(status, "text/plain", upstream_config::errorText(error));
    return;
  }
  upstreamLoopGuardReported = false;
  web.send(200, "text/plain", "saved " + upstreamText());
}

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upstream\":\"" + upstreamText() + "\",\"upurl\":\"" + jesc(updateUrl) +
             "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"allow\":[";
  for (int i = 0; i < numAllow; i++) { j += (i ? "," : ""); j += "\"" + jesc(allowDom[i]) + "\""; }
  j += "]";
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  // This address is the server socket's local endpoint, not Host: Host can be
  // copied from an old tab and must never authorize a different trial.
  j += ",\"network\":" + networkStatusJson(networkIPv4(web.client().localIP()));
#endif
  j += "}";
  web.send(200, "application/json", j);
}
static void handleBan() {
  if (!blocklistStorageReady) { web.send(503, "text/plain", "filesystem unavailable"); return; }
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

#if AD_BLOCK_NETWORK_PROFILE_ENABLED
static void handleNetworkStatus() {
  web.send(200, "application/json", networkStatusJson(networkIPv4(web.client().localIP())));
}

static void handleNetworkApply() {
  const network_web::RequestError request = network_web::authorizePost(
      "POST", web.hostHeader().c_str(), web.header("Origin").c_str(), web.header("Referer").c_str(),
      web.arg("intent").c_str(), "network-change");
  if (request != network_web::RequestError::none) {
    web.send(request == network_web::RequestError::badOrigin ? 403 : 400,
             "text/plain", network_web::errorText(request));
    return;
  }
  if (!networkProfilePrefsReady || !networkController) {
    web.send(500, "text/plain", "network profile NVS unavailable");
    return;
  }
  network_profile::Profile candidate;
  String error;
  if (!networkBuildCandidate(web.arg("mode"), web.arg("ip"), web.arg("mask"),
                             web.arg("gateway"), web.arg("dns"), candidate, error)) {
    web.send(400, "text/plain", error);
    return;
  }
  if (!networkController->trialActive() && network_profile::equal(candidate, networkProfile)) {
    web.send(200, "text/plain", "network profile unchanged; no trial started");
    return;
  }
  const network_profile::StageResult staged = networkController->stage(candidate);
  if (staged.result != network_profile::Result::pending) {
    const int status = staged.result == network_profile::Result::indeterminate ? 500 : 400;
    web.send(status, "text/plain", "network profile was not staged");
    return;
  }
  web.send(200, "text/plain", "network trial staged; reconnect at the new address and confirm within 180 seconds");
  // The response must leave the socket before the station configuration/reboot.
  networkScheduleRestart();
}

static void handleNetworkConfirm() {
  const network_web::RequestError request = network_web::authorizePost(
      "POST", web.hostHeader().c_str(), web.header("Origin").c_str(), web.header("Referer").c_str(),
      web.arg("intent").c_str(), "confirm-network");
  if (request != network_web::RequestError::none) {
    web.send(request == network_web::RequestError::badOrigin ? 403 : 400,
             "text/plain", network_web::errorText(request));
    return;
  }
  if (!networkProfilePrefsReady || !networkController || !networkController->trialActive()) {
    web.send(409, "text/plain", "no network trial is active");
    return;
  }
  const network_profile::IPv4 actual = networkIPv4(web.client().localIP());
  network_profile::IPv4 expected;
  network_control::expectedTrialIP(networkController->trial(), actual, expected);
  const network_web::RequestError check = network_web::checkConfirmation(
      networkController->trial().revision, web.arg("revision").c_str(), web.arg("token").c_str(),
      actual, expected, networkController->trialActive());
  if (check != network_web::RequestError::none) {
    web.send(check == network_web::RequestError::malformed ? 400 : 409,
             "text/plain", network_web::errorText(check));
    return;
  }
  const network_profile::ConfirmResult confirmed = networkController->confirm(
      network_profile::ConfirmationToken(networkController->trial().revision, expected), actual);
  if (confirmed.result == network_profile::Result::committed) {
    networkProfile = confirmed.profile;
    web.send(200, "text/plain", "network trial confirmed");
  } else {
    web.send(500, "text/plain", "network confirmation storage failed; trial remains recoverable");
  }
}
#endif

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The old list stays open and searchable while a candidate is written. Only a
// validated, closed candidate enters the short rename window.
static void cooperateBlocklistValidation(size_t) { yield(); }

struct BlocklistStorage {
  using File = ::File;
  size_t totalBytes() const { return LittleFS.totalBytes(); }
  size_t usedBytes() const { return LittleFS.usedBytes(); }
  bool exists(const char* path) const { return LittleFS.exists(path); }
  bool remove(const char* path) { return LittleFS.remove(path); }
  File open(const char* path, const char* mode) { return LittleFS.open(path, mode); }
  bool rename(const char* from, const char* to) { return LittleFS.rename(from, to); }
  const char* livePath() const { return BLOCKLIST_PATH; }
  void closeLive() { if (liveBlocklist) liveBlocklist.close(); }
  bool reopenLiveAndValidate(size_t hashBytes = HASH_BYTES,
                             blocklist::ValidationHook hook = cooperateBlocklistValidation) {
    closeLive();
    liveBlocklist = LittleFS.open(BLOCKLIST_PATH, "r");
    if (!liveBlocklist) { numHashes = 0; return false; }
    blocklist::ValidationResult result = blocklist::validateSorted(liveBlocklist, hashBytes, hook);
    if (!result.ok) { liveBlocklist.close(); numHashes = 0; return false; }
    numHashes = result.records;
    return true;
  }
};
static BlocklistStorage blocklistStorage;
static blocklist::SafeTransaction<BlocklistStorage> blocklistTransaction(
    blocklistStorage, "/blocklist.new", cooperateBlocklistValidation);

static bool reopenBlocklist() {
  return blocklistStorageReady && blocklistStorage.reopenLiveAndValidate();
}
static bool beginBlocklistSwap(size_t expectedBytes = 0) {
  return blocklistStorageReady && blocklistTransaction.begin(expectedBytes);
}
static bool finishBlocklistSwap(size_t expectedBytes = 0) {
  return blocklistStorageReady && blocklistTransaction.finish(expectedBytes, HASH_BYTES);
}
static blocklist::RecoveryStatus abortBlocklistSwap() {
  if (blocklistTransaction.active()) return blocklistTransaction.abort();
  return reopenBlocklist() ? blocklist::RecoveryStatus::retained
                           : blocklist::RecoveryStatus::reopen_failed;
}
static const char* listError() {
  return blocklist::failureText(blocklistTransaction.failure());
}
static const char* listError(blocklist::RecoveryStatus status) {
  return blocklist::recoveryText(status);
}

// ---------- N3: connection reset / factory reset ----------
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
// Both an in-flight blocklist swap (browser upload or remote fetch) and a
// firmware flash (browser upload or ArduinoOTA network flash — both funnel
// through the same Update singleton) must block a reset.
static bool networkUpdateInProgress() {
  return blocklistTransaction.active() || Update.isRunning();
}

static int networkResetHttpStatus(network_reset::RequestError error) {
  switch (error) {
    case network_reset::RequestError::badOrigin: return 403;
    case network_reset::RequestError::updateInProgress: return 409;
    default: return 400;
  }
}

static void handleNetworkResetConnection() {
  const network_reset::RequestError request = network_reset::authorize(
      "POST", web.hostHeader().c_str(), web.header("Origin").c_str(), web.header("Referer").c_str(),
      web.arg("intent").c_str(), "connection-reset", networkUpdateInProgress());
  if (request != network_reset::RequestError::none) {
    web.send(networkResetHttpStatus(request), "text/plain", network_reset::errorText(request));
    return;
  }
  if (!networkProfilePrefsReady) {
    web.send(500, "text/plain", "network profile NVS unavailable");
    return;
  }
  if (!prefs.begin("wifi", false)) {
    web.send(500, "text/plain", "WiFi credential storage unavailable");
    return;
  }
  const auto result = network_reset::connectionReset(prefs, networkProfilePrefs);
  prefs.end();
  if (!result.committed()) {
    web.send(500, "text/plain", "connection reset did not fully commit; check device state before retrying");
    return;
  }
  networkProfile = network_profile::Profile::dhcpProfile();
  web.send(200, "text/plain", "connection reset: WiFi and network address cleared; rebooting into setup portal");
  // The response must leave the socket before the restart, same as N2's staged apply.
  networkScheduleRestart();
}

static void handleNetworkResetFactory() {
  const network_reset::RequestError request = network_reset::authorize(
      "POST", web.hostHeader().c_str(), web.header("Origin").c_str(), web.header("Referer").c_str(),
      web.arg("intent").c_str(), "factory-reset", networkUpdateInProgress());
  if (request != network_reset::RequestError::none) {
    web.send(networkResetHttpStatus(request), "text/plain", network_reset::errorText(request));
    return;
  }
  if (!networkProfilePrefsReady || !upstreamPrefsReady) {
    web.send(500, "text/plain", "network/upstream NVS unavailable");
    return;
  }
  if (!blocklistStorageReady) {
    web.send(503, "text/plain", "filesystem unavailable; factory reset requires LittleFS");
    return;
  }
  if (!prefs.begin("wifi", false)) {
    web.send(500, "text/plain", "WiFi credential storage unavailable");
    return;
  }
  const network_reset::FactoryResetResult result =
      network_reset::factoryReset(prefs, networkProfilePrefs, upstreamPrefs, LittleFS);
  prefs.end();
  if (!result.committed()) {
    web.send(500, "text/plain", "factory reset did not fully commit; check device state before retrying");
    return;
  }
  networkProfile = network_profile::Profile::dhcpProfile();
  upstreamAddress = DEFAULT_UPSTREAM;
  web.send(200, "text/plain",
           "factory reset: app settings cleared; rebooting into setup portal with defaults");
  networkScheduleRestart();
}
#endif

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static String upStatus = "not started";
static void handleUploadDone() {
  web.send(upOk ? 200 : 500, "text/plain", upOk ? "ok: " + upStatus : "rejected: " + upStatus);
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START: {
      upOk = false;
      upStatus = blocklistStorageReady ? "receiving" : "filesystem unavailable";
      bool previousAborted = true;
      if (blocklistTransaction.active()) {
        const blocklist::RecoveryStatus recovery = abortBlocklistSwap();
        previousAborted = blocklist::recoverySucceeded(recovery);
        if (!previousAborted) upStatus = listError(recovery);
      }
      const size_t expected = u.totalSize;
      if (previousAborted && blocklistStorageReady && beginBlocklistSwap(expected)) {
        Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      } else if (previousAborted && blocklistStorageReady) {
        upStatus = listError();
      }
      break;
    }
    case UPLOAD_FILE_WRITE:
      if (blocklistTransaction.active() && !blocklistTransaction.write(u.buf, u.currentSize)) {
        upStatus = listError();
      }
      break;
    case UPLOAD_FILE_END: {
      const size_t expected = u.totalSize;
      if (blocklistTransaction.active()) {
        const bool committed = expected > 0 && finishBlocklistSwap(expected);
        if (committed) {
          upOk = true;
          upStatus = String(numHashes) + " domains";
        } else {
          if (blocklistTransaction.active()) {
            const blocklist::RecoveryStatus recovery = abortBlocklistSwap();
            upStatus = listError(recovery);
          } else {
            upStatus = listError();
          }
        }
      }
      Serial.printf("[ota] %s -> %u domains (%s)\n", upOk ? "OK" : "REJECTED", numHashes, upStatus.c_str());
      break;
    }
    case UPLOAD_FILE_ABORTED:
      if (blocklistStorageReady) {
        const blocklist::RecoveryStatus recovery = abortBlocklistSwap();
        upStatus = String("aborted; ") + listError(recovery);
      } else {
        upStatus = "aborted; filesystem unavailable";
      }
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim();
  if (!url.length()) { updateStatus = "no url set"; return false; }
  if (!blocklistStorageReady) { updateStatus = "filesystem unavailable"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // structural validation is not authenticity; TLS remains insecure by design
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false;
  }
  WiFiClient* stream = http.getStreamPtr();
  const int contentLength = http.getSize();
  if (!stream) {
    http.end(); updateStatus = "stream unavailable"; return false;
  }
  if (contentLength <= 0) {
    // Unknown-length/chunked bodies are deliberately rejected: consuming the raw
    // stream cannot prove that the decoded body ended without truncation.
    http.end(); updateStatus = "rejected: positive Content-Length required"; return false;
  }
  const size_t expected = static_cast<size_t>(contentLength);
  if (!beginBlocklistSwap(expected)) {
    http.end(); updateStatus = listError(); return false;
  }

  blocklist::ExactLength transfer(expected);
  uint8_t buffer[1024];
  uint32_t idle = millis();
  uint32_t loops = 0;
  bool transferOk = true;
  while (!transfer.complete()) {
    if (!http.connected() && stream->available() == 0) { transferOk = false; break; }
    const size_t available = stream->available();
    if (available) {
      const size_t wanted = available < sizeof(buffer) ? available : sizeof(buffer);
      const size_t remaining = expected - transfer.received;
      const size_t request = wanted < remaining ? wanted : remaining;
      const int received = stream->readBytes(buffer, request);
      if (received <= 0 || !transfer.accept(static_cast<size_t>(received)) ||
          !blocklistTransaction.write(buffer, static_cast<size_t>(received))) {
        transferOk = false; break;
      }
      idle = millis();
    } else {
      if (millis() - idle > 15000) { transferOk = false; break; }
      delay(2);
    }
    if ((++loops & 0x0f) == 0) yield();
  }
  // With a positive Content-Length, bytes beyond the declared body are an error.
  if (transferOk && stream->available() > 0) transferOk = false;
  http.end();
  if (!transferOk || !transfer.complete()) {
    const blocklist::RecoveryStatus recovery = blocklistTransaction.active()
        ? abortBlocklistSwap() : blocklistTransaction.recoveryStatus();
    const char* reason = transfer.complete() ? "transfer rejected" : "transfer incomplete or timed out";
    updateStatus = String(reason) + "; " + listError(recovery);
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  const bool ok = finishBlocklistSwap(expected);
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : listError();
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool connectWiFi() {
  if (!prefs.begin("wifi", true)) {
    Serial.println("[wifi] credential namespace unavailable; opening portal");
    return false;
  }
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting (%s)\n", ss.length() ? "provisioned credentials" : "compile-time fallback");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false);
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  if (networkProfilePrefsReady) {
    ArduinoNetworkAdapter adapter;
    if (!network_control::handleAction(networkBootResult.action, networkBootResult.profile, adapter))
      Serial.println("[network] WiFi profile apply failed; continuing without claiming success");
  }
#endif
  WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Choose a scanned 2.4 GHz network, or enter a hidden network manually. The device restarts and joins it.</p>";
  if (!portalNetworkCount) {
    html += "<p style='color:#f0ad4e'>No 2.4 GHz networks were found. Use manual entry for a hidden network.</p>";
  }
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  if (networkController && networkController->trialActive()) {
    const uint32_t elapsed = millis() - networkController->trial().startedAt;
    const uint32_t remaining = elapsed < network_profile::TRIAL_TIMEOUT_MS
        ? network_profile::TRIAL_TIMEOUT_MS - elapsed : 0;
    html += "<p style='color:#f0ad4e'>Network trial " + String(networkController->trial().revision) +
            " is active; rollback in " + String(remaining / 1000UL) +
            " seconds unless confirmed from the new address.</p>";
  } else if (networkRecoveryVisible) {
    html += "<p style='color:#f0ad4e'>Network rollback is persisted; restart/recovery is pending.</p>";
  }
#endif
  html +=
    "<form method=POST action=/wifisave>"
    "<label for=network-select>Network</label>"
    "<select id=network-select name=s style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<option value=''>Select a scanned network</option>" + portalOpts + "</select>"
    "<fieldset style='border:1px solid #30363d;border-radius:6px;margin:10px 0;padding:8px'>"
    "<legend>Network source</legend>"
    "<label><input type=radio name=mode value=network checked> Use selected network</label><br>"
    "<label><input type=radio name=mode value=manual> Hidden network / manual entry</label>"
    "</fieldset>"
    "<input name=manual type=text placeholder='Manual WiFi name (hidden network)' autocomplete=off style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<input name=p type=password placeholder='Password' autocomplete=current-password style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>";
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  const String dhcpMark = networkProfile.dhcp ? "checked" : "";
  const String staticMark = networkProfile.dhcp ? "" : "checked";
  const String portalIP = networkProfile.dhcp ? "192.168.5.5" : networkIPv4Text(networkProfile.local);
  const String portalMask = networkProfile.dhcp ? "255.255.255.0" : networkIPv4Text(networkProfile.netmask);
  const String portalGateway = networkProfile.dhcp ? "192.168.5.1" : networkIPv4Text(networkProfile.gateway);
  const String portalDNS = networkProfile.dhcp ? "1.1.1.1" : networkIPv4Text(networkProfile.dnsIPv4);
  html += "<hr><h3>Network address</h3><p style='color:#8b949e'>DHCP is the default. A static change is trialed for 180 seconds; reconnect at the new IP and confirm before it becomes permanent.</p>"
    "<label><input type=radio name=networkMode value=dhcp " + dhcpMark + "> DHCP</label> "
    "<label><input type=radio name=networkMode value=static " + staticMark + "> Static IPv4</label>"
    "<input name=ip placeholder='IP address (e.g. 192.168.5.5)' value='" + portalIP + "' autocomplete=off style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0'>"
    "<input name=mask placeholder='Netmask (e.g. 255.255.255.0)' value='" + portalMask + "' autocomplete=off style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0'>"
    "<input name=gateway placeholder='Gateway (e.g. 192.168.5.1)' value='" + portalGateway + "' autocomplete=off style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0'>"
    "<input name=dns placeholder='Resolver DNS (e.g. 1.1.1.1)' value='" + portalDNS + "' autocomplete=off style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0'>"
    "<input type=hidden name=intent value=wifi-save>";
#else
  html += "<input type=hidden name=intent value=wifi-save>";
#endif
  html += "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form>";
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  html +=
    "<hr><h3>Reset</h3>"
    "<p style='color:#8b949e'>Connection reset clears WiFi and network address settings only &mdash; everything else is kept. "
    "Factory reset also clears upstream DNS, the manual allowlist, client bans, and update settings, restoring DHCP + Quad9 + "
    "blocking-on defaults after reboot; firmware and the blocklist are never touched.</p>"
    "<form method=POST action=/network/reset-connection>"
    "<input type=hidden name=intent value=connection-reset>"
    "<button style='width:100%;padding:10px;border-radius:6px;border:1px solid #f0883e;background:#161b22;color:#f0883e;cursor:pointer'>Connection reset</button></form>"
    "<form method=POST action=/network/reset-factory style='margin-top:8px'>"
    "<input type=hidden name=intent value=factory-reset>"
    "<button style='width:100%;padding:10px;border-radius:6px;border:1px solid #f85149;background:#161b22;color:#f85149;cursor:pointer'>Factory reset</button></form>";
#endif
  html += "</body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss, pw = web.arg("p");
  if (!wifiPortalSelectSSID(web.arg("mode"), web.arg("s"), web.arg("manual"),
                            portalSsids, portalNetworkCount, ss)) {
    web.send(400, "text/plain", "missing or invalid WiFi name"); return;
  }
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  if (!networkOriginAllowed("wifi-save")) {
    web.send(400, "text/plain", "same-origin WiFi save with explicit intent required"); return;
  }
  network_profile::Profile candidate;
  String networkError;
  if (!networkBuildCandidate(web.arg("networkMode"), web.arg("ip"), web.arg("mask"),
                             web.arg("gateway"), web.arg("dns"), candidate, networkError)) {
    web.send(400, "text/plain", networkError);
    return;
  }
  if (!networkProfilePrefsReady && !candidate.dhcp) {
    web.send(500, "text/plain", "network profile NVS unavailable; static settings were not applied");
    return;
  }
  const bool profileChanged = networkProfilePrefsReady && networkController &&
                              !networkController->trialActive() &&
                              !network_profile::equal(candidate, networkProfile);
  if (profileChanged) {
    const network_profile::StageResult staged = networkController->stage(candidate);
    if (staged.result != network_profile::Result::pending) {
      web.send(staged.result == network_profile::Result::indeterminate ? 500 : 400,
               "text/plain", "network profile was not staged; credentials were not changed");
      return;
    }
  }
#endif
  if (!prefs.begin("wifi", false)) {
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
    if (profileChanged && network_profile::reset(networkProfilePrefs) != network_profile::Result::committed)
      Serial.println("[network] credential failure left profile recovery indeterminate; restart suppressed");
#endif
    web.send(500, "text/plain", "WiFi credential storage unavailable; no restart scheduled");
    return;
  }
  const size_t ssidWritten = prefs.putString("ssid", ss);
  const size_t passwordWritten = prefs.putString("pass", pw);
  const bool credentialsSaved = ssidWritten == ss.length() && passwordWritten == pw.length();
  prefs.end();
  if (!credentialsSaved) {
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
    // N1 exposes reset as the bounded recovery operation. It deliberately
    // falls back to DHCP rather than copying or attempting to restore a WiFi
    // password that this request did not own.
    if (profileChanged && network_profile::reset(networkProfilePrefs) != network_profile::Result::committed)
      Serial.println("[network] credential failure left profile recovery indeterminate; restart suppressed");
#endif
    web.send(500, "text/plain", "WiFi credentials were not fully stored; no restart scheduled");
    return;
  }
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + wifiPortalHtmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  networkScheduleRestart();
#else
  portalRestartPending = true; portalRestartAt = millis() + 1000UL;
#endif
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalNetworkCount = 0;
  for (int i = 0; i < n && i < static_cast<int>(WIFI_PORTAL_MAX_NETWORKS); ++i) {
    String ssid = WiFi.SSID(i);
    if (ssid.length()) portalSsids[portalNetworkCount++] = ssid;
  }
  portalOpts = wifiPortalNetworkOptions(portalSsids, portalNetworkCount);
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  web.on("/network/reset-connection", HTTP_POST, handleNetworkResetConnection);
  web.on("/network/reset-factory", HTTP_POST, handleNetworkResetFactory);
#endif
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  const char* portalHeaders[] = {"Origin", "Referer", "Host"};
  web.collectHeaders(portalHeaders, 3);
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  while (true) {
    dnsPortal.processNextRequest();
    web.handleClient();
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
    networkService();
    networkRestartService();
#endif
#if !AD_BLOCK_NETWORK_PROFILE_ENABLED
    if (portalRestartPending && static_cast<int32_t>(millis() - portalRestartAt) >= 0) {
      portalRestartPending = false;
      ESP.restart();
    }
#endif
    delay(2);
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.printf("\n[%s] booting\n", AD_BLOCK_BOARD_LABEL);
  Serial.printf("[memory] flash=%u bytes (%.1f MiB), psramFound=%s, psram=%u bytes, free_psram=%u, heap=%u\n",
                ESP.getFlashChipSize(), ESP.getFlashChipSize() / 1048576.0f,
                psramFound() ? "yes" : "no", ESP.getPsramSize(), ESP.getFreePsram(), ESP.getFreeHeap());
  blocklistStorageReady = LittleFS.begin(false);  // never auto-format an existing device
  if (!blocklistStorageReady) {
    numHashes = 0;
    Serial.println("[setup] LittleFS FAILED; persistence and blocklist updates unavailable");
  } else {
    if (LittleFS.exists("/blocklist.new") && !LittleFS.remove("/blocklist.new"))
      Serial.println("[setup] stale blocklist.new could not be removed; it will never be promoted");
    if (LittleFS.exists("/allowlist.new") && !LittleFS.remove("/allowlist.new"))
      Serial.println("[setup] stale allowlist.new could not be removed; it will never be promoted");
    if (!reopenBlocklist()) Serial.println("[setup] no valid live blocklist; updates remain available");
    else Serial.printf("blocklist: %u domains\n", numHashes);
    loadCustom(); loadAllow(); loadBanned(); loadUpdateCfg();
    Serial.printf("custom: %d, allow: %d, banned: %d\n", numCustom, numAllow, numBanned);
  }

  // C3 keeps its established BOOT reset. S3 GPIO0 is conventional but remains
  // opt-in because this provisional board/USB wiring is not confirmed.
#if AD_BLOCK_BOOT_RESET_ENABLED
  pinMode(AD_BLOCK_BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(AD_BLOCK_BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(AD_BLOCK_BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }
#endif

#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  // Upstream is loaded read-only before profile validation so a candidate
  // cannot select the resolver's configured address as its own station IP.
  loadUpstreamConfig();
  networkBootOnce();  // exactly once, before any WiFi.config/WiFi.begin call
#endif
  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
#if !AD_BLOCK_NETWORK_PROFILE_ENABLED
  loadUpstreamConfig();
#endif
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/upstream", HTTP_POST, handleUpstream);
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  web.on("/network/status", HTTP_GET, handleNetworkStatus);
  web.on("/network/apply", HTTP_POST, handleNetworkApply);
  web.on("/network/confirm", HTTP_POST, handleNetworkConfirm);
  web.on("/network/reset-connection", HTTP_POST, handleNetworkResetConnection);
  web.on("/network/reset-factory", HTTP_POST, handleNetworkResetFactory);
#endif
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    if (!blocklistStorageReady) { web.send(503, "text/plain", "filesystem unavailable"); return; }
    web.send(200, "text/plain", addCustom(web.arg("d")) ? "ok" : "rejected");
  });
  web.on("/unblock", []() {
    if (!blocklistStorageReady) { web.send(503, "text/plain", "filesystem unavailable"); return; }
    removeCustom(web.arg("d")); web.send(200, "text/plain", "ok");
  });
  web.on("/addallow", []() {
    if (!blocklistStorageReady) { web.send(500, "text/plain", "filesystem unavailable"); return; }
    const AllowUpdate result = addAllow(web.arg("d"));
    web.send(allowHttpStatus(result), "text/plain", allowResultText(result));
  });
  web.on("/unallow", []() {
    if (!blocklistStorageReady) { web.send(500, "text/plain", "filesystem unavailable"); return; }
    const AllowUpdate result = removeAllow(web.arg("d"));
    web.send(allowHttpStatus(result), "text/plain", allowResultText(result));
  });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA
  web.on("/fetchnow", []() {
    const bool ok = fetchBlocklist(updateUrl);
    web.send(ok ? 200 : 500, "text/plain", updateStatus);
  });
  web.on("/setupdate", []() {
    if (!blocklistStorageReady) { web.send(503, "text/plain", "filesystem unavailable"); return; }
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  const char* requestHeaders[] = {"Origin", "Referer", "Host"};
  web.collectHeaders(requestHeaders, 3);
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
#if AD_BLOCK_NETWORK_PROFILE_ENABLED
  networkService();
  networkRestartService();
#endif
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
