#pragma once

#include <stddef.h>

static const size_t WIFI_PORTAL_MAX_NETWORKS = 15;

// Escape SSIDs for both HTML attributes and text nodes without changing their
// bytes beyond the characters that have HTML syntax meaning.
static String wifiPortalHtmlEscape(const String& input) {
  String escaped;
  for (size_t i = 0; i < input.length(); ++i) {
    const char ch = input[i];
    switch (ch) {
      case '&': escaped += "&amp;"; break;
      case '"': escaped += "&quot;"; break;
      case '\'': escaped += "&#39;"; break;
      case '<': escaped += "&lt;"; break;
      case '>': escaped += "&gt;"; break;
      default: escaped += ch; break;
    }
  }
  return escaped;
}

static String wifiPortalNetworkOptions(const String* ssids, size_t count) {
  String options;
  if (count > WIFI_PORTAL_MAX_NETWORKS) count = WIFI_PORTAL_MAX_NETWORKS;
  for (size_t i = 0; i < count; ++i) {
    const String escaped = wifiPortalHtmlEscape(ssids[i]);
    options += "<option value=\"";
    options += escaped;
    options += "\">";
    options += escaped;
    options += "</option>";
  }
  return options;
}

static bool wifiPortalContainsSSID(const String& ssid, const String* scanned, size_t count) {
  if (count > WIFI_PORTAL_MAX_NETWORKS) count = WIFI_PORTAL_MAX_NETWORKS;
  for (size_t i = 0; i < count; ++i) {
    if (scanned[i] == ssid) return true;
  }
  return false;
}

// mode=manual selects the distinct manual field. mode=network and an omitted
// or empty mode preserve the legacy s field, which must exactly match one of
// the networks shown by the current scan. Other nonempty modes are invalid.
static bool wifiPortalSelectSSID(const String& mode, const String& selected,
                                 const String& manual, const String* scanned,
                                 size_t count, String& chosen) {
  const bool manualMode = mode == "manual";
  const bool legacyMode = mode == "network" || !mode.length();
  if (!manualMode && !legacyMode) return false;
  chosen = manualMode ? manual : selected;
  if (!chosen.length()) return false;
  return manualMode || wifiPortalContainsSSID(chosen, scanned, count);
}
