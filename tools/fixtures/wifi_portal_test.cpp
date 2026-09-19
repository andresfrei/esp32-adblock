#include <cstdio>
#include <string>

class String {
 public:
  String() = default;
  String(const char* value) : value_(value ? value : "") {}
  String(const std::string& value) : value_(value) {}

  size_t length() const { return value_.length(); }
  char operator[](size_t index) const { return value_[index]; }
  String& operator+=(const char* value) { value_ += value; return *this; }
  String& operator+=(const String& value) { value_ += value.value_; return *this; }
  String& operator+=(char value) { value_ += value; return *this; }
  String& operator=(const String&) = default;
  bool operator==(const String& other) const { return value_ == other.value_; }
  bool operator!=(const String& other) const { return !(*this == other); }
  const std::string& std() const { return value_; }

 private:
  std::string value_;
};

#include "wifi_portal.h"

static void expect(bool condition, const char* message) {
  if (!condition) throw message;
}

static void rendering_cases() {
  expect(wifiPortalNetworkOptions(nullptr, 0).length() == 0, "zero networks render no options");

  const String scanned[] = {String("Cafe  2G"), String("Guest & Family"), String("a\"b'c<&")};
  const String options = wifiPortalNetworkOptions(scanned, 3);
  expect(options.std().find("<option value=\"Cafe  2G\">Cafe  2G</option>") != std::string::npos,
         "ordinary SSID keeps exact spaces");
  expect(options.std().find("value=\"a&quot;b&#39;c&lt;&amp;\">a&quot;b&#39;c&lt;&amp;</option>") != std::string::npos,
         "special SSID is escaped in attribute and text");
  expect(options.std().find("<datalist") == std::string::npos, "visible selector does not use datalist");
}

static void selection_cases() {
  const String scanned[] = {String("real-network"), String("__manual__")};
  String chosen;
  expect(wifiPortalSelectSSID(String("network"), String("real-network"), String("ignored"),
                              scanned, 2, chosen) && chosen == String("real-network"),
         "one actual posted SSID is accepted");
  expect(wifiPortalSelectSSID(String(""), String("real-network"), String("ignored"),
                              scanned, 2, chosen) && chosen == String("real-network"),
         "omitted mode keeps legacy scanned-SSID behavior");
  expect(!wifiPortalSelectSSID(String("bogus"), String("real-network"), String("ignored"),
                               scanned, 2, chosen),
         "unknown mode rejects an otherwise valid scanned SSID");
  expect(!wifiPortalSelectSSID(String("Network"), String("real-network"), String("ignored"),
                               scanned, 2, chosen),
         "mode comparison does not normalize case");
  expect(!wifiPortalSelectSSID(String(" network "), String("real-network"), String("ignored"),
                               scanned, 2, chosen),
         "mode comparison does not trim whitespace");
  expect(!wifiPortalSelectSSID(String("network"), String("wrong-network"), String("ignored"),
                               scanned, 2, chosen),
         "unscanned network is rejected");
  expect(wifiPortalSelectSSID(String("manual"), String("__manual__"), String("__manual__"),
                              scanned, 2, chosen) && chosen == String("__manual__"),
         "manual mode remains distinct from a colliding real SSID value");
  expect(wifiPortalSelectSSID(String("manual"), String(""), String("Hidden  Network"),
                              scanned, 2, chosen) && chosen == String("Hidden  Network"),
         "manual hidden SSID keeps exact spaces");
  expect(!wifiPortalSelectSSID(String("manual"), String("real-network"), String(""),
                               scanned, 2, chosen),
         "missing manual SSID is rejected");
}

int main() {
  try {
    rendering_cases();
    selection_cases();
  } catch (const char* message) {
    return fprintf(stderr, "FAIL: %s\n", message), 1;
  }
  return 0;
}
