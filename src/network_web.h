#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "network_profile.h"

// HTTP policy for the S3 network-profile endpoints. This is intentionally not
// an authentication framework: it bounds accidental cross-origin changes and
// binds confirmation to the server socket's local address and current trial.
namespace network_web {

enum class RequestError { none, notPost, badOrigin, missingIntent, malformed, noTrial, staleTrial, wrongLocalIP };

inline bool equals(const char* left, const char* right) {
  if (!left || !right) return false;
  return std::strcmp(left, right) == 0;
}

inline bool authorityEquals(const char* authority, const char* host) {
  return authority && host && *authority && *host && equals(authority, host);
}

inline bool suppliedOriginMatchesHost(const char* value, const char* host) {
  if (!value || !*value) return true;  // Origin/Referer are optional on LAN clients.
  if (!host || !*host) return false;
  const char* scheme = std::strstr(value, "://");
  if (!scheme) return false;
  const char* authority = scheme + 3;
  const char* end = authority;
  while (*end && *end != '/' && *end != '?' && *end != '#') ++end;
  const size_t length = static_cast<size_t>(end - authority);
  char bounded[96] = {};
  if (length == 0 || length >= sizeof(bounded)) return false;
  std::memcpy(bounded, authority, length);
  return authorityEquals(bounded, host);
}

inline bool sameLocalOrigin(const char* host, const char* origin, const char* referer) {
  const bool originPresent = origin && *origin;
  const bool refererPresent = referer && *referer;
  // Omitting Origin is tolerated for LAN clients that only send one of the
  // two headers, but omitting BOTH must not silently satisfy the check --
  // that would let any non-browser request bypass it by simply sending
  // neither header, defeating its purpose of bounding accidental
  // cross-origin browser requests.
  if (!originPresent && !refererPresent) return false;
  return suppliedOriginMatchesHost(origin, host) && suppliedOriginMatchesHost(referer, host);
}

inline RequestError authorizePost(const char* method, const char* host, const char* origin,
                                  const char* referer, const char* intent,
                                  const char* expectedIntent) {
  if (!equals(method, "POST")) return RequestError::notPost;
  if (!sameLocalOrigin(host, origin, referer)) return RequestError::badOrigin;
  if (!expectedIntent || !equals(intent, expectedIntent)) return RequestError::missingIntent;
  return RequestError::none;
}

inline bool parseUnsigned(const char* text, uint32_t& output) {
  if (!text || !*text) return false;
  uint32_t value = 0;
  for (const char* cursor = text; *cursor; ++cursor) {
    if (*cursor < '0' || *cursor > '9') return false;
    const uint32_t digit = static_cast<uint32_t>(*cursor - '0');
    if (value > (0xffffffffUL - digit) / 10UL) return false;
    value = value * 10UL + digit;
  }
  output = value;
  return true;
}

inline RequestError checkConfirmation(uint32_t revision, const char* revisionText,
                                      const char* tokenText, const network_profile::IPv4& actual,
                                      const network_profile::IPv4& expected,
                                      bool trialActive) {
  if (!trialActive) return RequestError::noTrial;
  uint32_t suppliedRevision = 0;
  if (!parseUnsigned(revisionText, suppliedRevision) || !tokenText || !*tokenText)
    return RequestError::malformed;
  network_profile::IPv4 suppliedIP;
  if (!network_profile::parseIPv4(tokenText, suppliedIP)) return RequestError::malformed;
  if (suppliedRevision != revision || !network_profile::same(suppliedIP, expected))
    return RequestError::staleTrial;
  if (!network_profile::same(actual, expected)) return RequestError::wrongLocalIP;
  return RequestError::none;
}

inline const char* errorText(RequestError error) {
  switch (error) {
    case RequestError::none: return "ok";
    case RequestError::notPost: return "POST required";
    case RequestError::badOrigin: return "same-origin request required";
    case RequestError::missingIntent: return "explicit network intent required";
    case RequestError::malformed: return "malformed confirmation";
    case RequestError::noTrial: return "no network trial is active";
    case RequestError::staleTrial: return "stale network trial";
    case RequestError::wrongLocalIP: return "request reached a different local IP";
  }
  return "network request rejected";
}

}  // namespace network_web
