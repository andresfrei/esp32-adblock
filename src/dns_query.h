#pragma once

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "domain_rules.h"

namespace dns_query {

// Decode one uncompressed question name into the same normalized shape used by
// the allowlist. The caller supplies the output size so the NUL bound remains
// explicit even when this helper is exercised outside the firmware buffer.
inline size_t parseQuery(const uint8_t* pkt, int len, char* out, size_t outSize,
                         uint16_t* qtype, int* qend) {
  if (!pkt || len < 13 || !out || !qtype || !qend || outSize == 0) return 0;
  int i = 12;
  size_t outputLength = 0;
  bool terminated = false;
  while (i < len) {
    const uint8_t labelLength = pkt[i++];
    if (labelLength == 0) {
      terminated = true;
      break;
    }
    if (labelLength & 0xC0 || labelLength > 63) return 0;
    const size_t needed = outputLength + (outputLength ? 1 : 0) + labelLength;
    if (needed > domain_rules::MAX_DOMAIN_LENGTH || needed + 1 > outSize || i + labelLength > len) return 0;
    if (outputLength) out[outputLength++] = '.';
    for (uint8_t k = 0; k < labelLength; ++k)
      out[outputLength++] = static_cast<char>(tolower(pkt[i++]));
  }
  if (!terminated) return 0;
  out[outputLength] = '\0';
  if (i + 4 > len) return 0;
  *qtype = (static_cast<uint16_t>(pkt[i]) << 8) | pkt[i + 1];
  *qend = i + 4;
  if (outputLength > 4 && strncmp(out, "www.", 4) == 0) {
    memmove(out, out + 4, outputLength - 3);
    outputLength -= 4;
  }
  return outputLength;
}

}  // namespace dns_query
