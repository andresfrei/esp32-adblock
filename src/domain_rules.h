#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace domain_rules {

static const size_t MAX_DOMAIN_LENGTH = 253;

inline bool isTrimSpace(unsigned char value) {
  return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f' || value == '\v';
}

inline bool isAsciiAlpha(unsigned char value) {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
}

inline bool isAsciiDigit(unsigned char value) { return value >= '0' && value <= '9'; }

// Normalize the same form emitted by parseQuery: ASCII lowercase and one leading
// "www." removed. Manual entries additionally accept surrounding whitespace and
// one terminal dot so persistence and UI input have one exact representation.
inline bool normalize(const char* input, char* output, size_t outputSize) {
  if (!input || !output || outputSize < MAX_DOMAIN_LENGTH + 1) return false;

  const unsigned char* begin = reinterpret_cast<const unsigned char*>(input);
  while (*begin && isTrimSpace(*begin)) ++begin;
  const unsigned char* end = begin + strlen(reinterpret_cast<const char*>(begin));
  while (end > begin && isTrimSpace(end[-1])) --end;
  if (begin == end) return false;

  size_t length = 0;
  for (const unsigned char* p = begin; p < end; ++p) {
    if (*p < 33 || *p > 126 || length >= outputSize - 1) return false;
    unsigned char value = *p;
    if (isAsciiAlpha(value)) {
      if (value >= 'A' && value <= 'Z') value = static_cast<unsigned char>(value + ('a' - 'A'));
    }
    output[length++] = static_cast<char>(value);
  }
  output[length] = '\0';

  if (length > 4 && strncmp(output, "www.", 4) == 0) {
    memmove(output, output + 4, length - 3);
    length -= 4;
  }
  if (length > 0 && output[length - 1] == '.') output[--length] = '\0';
  if (length == 0 || length > MAX_DOMAIN_LENGTH) return false;

  bool hasDot = false;
  bool possibleIpv4 = true;
  size_t labelCount = 0;
  size_t labelLength = 0;
  size_t numericValue = 0;
  bool labelNumeric = true;
  for (size_t i = 0; i <= length; ++i) {
    const unsigned char value = static_cast<unsigned char>(output[i]);
    if (value == '.' || value == '\0') {
      if (labelLength == 0 || labelLength > 63 || output[i - labelLength] == '-' || output[i - 1] == '-') return false;
      ++labelCount;
      if (labelCount > 4 || !labelNumeric || numericValue > 255) possibleIpv4 = false;
      if (value == '.') hasDot = true;
      labelLength = 0;
      numericValue = 0;
      labelNumeric = true;
      continue;
    }
    if (!(isAsciiAlpha(value) || isAsciiDigit(value) || value == '-')) return false;
    ++labelLength;
    if (!isAsciiDigit(value)) {
      labelNumeric = false;
      possibleIpv4 = false;
    } else if (numericValue <= 255) {
      numericValue = numericValue * 10 + (value - '0');
    }
  }
  if (!hasDot || (possibleIpv4 && labelCount == 4)) return false;
  return true;
}

inline bool exactMatch(const char* query, const char* normalizedEntry) {
  return query && normalizedEntry && strcmp(query, normalizedEntry) == 0;
}

// The callback receives one suffix and its length. Keeping the suffix walk here
// preserves the existing rule: a domain and its parent are checked, but the
// final single-label suffix is not checked.
typedef bool (*SuffixMatcher)(const char*, size_t, void*);
inline bool suffixDenied(const char* domain, SuffixMatcher matcher, void* context) {
  if (!domain || !matcher) return false;
  const char* suffix = domain;
  while (*suffix) {
    if (matcher(suffix, strlen(suffix), context)) return true;
    const char* dot = strchr(suffix, '.');
    if (!dot) break;
    const char* next = dot + 1;
    if (!strchr(next, '.')) break;
    suffix = next;
  }
  return false;
}

// Rule precedence is intentionally separate from matching: a client ban is
// unconditional, pause bypasses domain rules, and an exact allow bypasses every
// domain deny for this query only.
inline bool shouldBlock(bool clientBanned, bool blockingOn, bool exactAllowed, bool domainDenied) {
  if (clientBanned) return true;
  if (!blockingOn) return false;
  if (exactAllowed) return false;
  return domainDenied;
}

}  // namespace domain_rules
