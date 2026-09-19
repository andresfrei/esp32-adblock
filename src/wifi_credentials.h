#pragma once

// Keep fallback values local to the no-header case. A present secrets.h owns
// WIFI_SSID and WIFI_PASS, including the documented static const char* form.
#if __has_include("secrets.h")
#include "secrets.h"
#else
static const char* WIFI_SSID = "";
static const char* WIFI_PASS = "";
#endif
