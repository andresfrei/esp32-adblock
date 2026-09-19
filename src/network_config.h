#pragma once

#include "network_profile.h"

// Compatibility seam for the pre-N1 station setup code. New integration
// should use network_profile::Profile and its transactional state machine.
namespace network_config {

using IPv4 = network_profile::IPv4;

enum class Error {
  none,
  malformed,
  unspecified,
  broadcast,
  multicast,
  loopback,
  invalidNetmask,
  localNetwork,
  localBroadcast,
  gatewayNetwork,
  gatewayBroadcast,
  gatewayOutsideSubnet,
  gatewayIsLocal,
  dnsIsLocal,
};

struct StaticConfig {
  bool enabled;
  IPv4 local;
  IPv4 gateway;
  IPv4 netmask;
  IPv4 dns;
  StaticConfig() : enabled(false), local(), gateway(), netmask(), dns() {}
};

inline bool same(const IPv4& left, const IPv4& right) { return network_profile::same(left, right); }
inline bool parseIPv4(const char* input, IPv4& output) {
  return network_profile::parseIPv4(input, output);
}
inline bool validHostAddress(const IPv4& address) { return network_profile::validUnicast(address); }
inline bool validNetmask(const IPv4& mask) { return network_profile::validNetmask(mask); }

inline Error fromValidation(network_profile::ValidationError error) {
  switch (error) {
    case network_profile::ValidationError::none: return Error::none;
    case network_profile::ValidationError::malformedIPv4: return Error::malformed;
    case network_profile::ValidationError::unspecified: return Error::unspecified;
    // Preserve the original compatibility API's single host-address error;
    // network_profile exposes the more precise labels to new integration.
    case network_profile::ValidationError::broadcast: return Error::unspecified;
    case network_profile::ValidationError::multicast: return Error::unspecified;
    case network_profile::ValidationError::loopback: return Error::unspecified;
    case network_profile::ValidationError::invalidNetmask: return Error::invalidNetmask;
    case network_profile::ValidationError::localNetwork: return Error::localNetwork;
    case network_profile::ValidationError::localBroadcast: return Error::localBroadcast;
    case network_profile::ValidationError::gatewayNetwork: return Error::gatewayNetwork;
    case network_profile::ValidationError::gatewayBroadcast: return Error::gatewayBroadcast;
    case network_profile::ValidationError::gatewayOutsideSubnet: return Error::gatewayOutsideSubnet;
    case network_profile::ValidationError::gatewayIsLocal: return Error::gatewayIsLocal;
    case network_profile::ValidationError::dnsIsLocal: return Error::dnsIsLocal;
  }
  return Error::malformed;
}

inline Error validate(const StaticConfig& config) {
  if (!config.enabled) return Error::none;
  const network_profile::Profile profile = network_profile::Profile::staticProfile(
      config.local, config.gateway, config.netmask, config.dns);
  return fromValidation(network_profile::validate(profile));
}

inline const char* errorText(Error error) {
  switch (error) {
    case Error::none: return "ok";
    case Error::malformed: return "malformed IPv4 configuration";
    case Error::unspecified: return "unspecified, broadcast, multicast, or loopback address";
    case Error::broadcast: return "broadcast address is not allowed";
    case Error::multicast: return "multicast address is not allowed";
    case Error::loopback: return "loopback address is not allowed";
    case Error::invalidNetmask: return "invalid contiguous IPv4 netmask";
    case Error::localNetwork: return "local IPv4 address is the subnet network";
    case Error::localBroadcast: return "local IPv4 address is the subnet broadcast";
    case Error::gatewayNetwork: return "gateway IPv4 address is the subnet network";
    case Error::gatewayBroadcast: return "gateway IPv4 address is the subnet broadcast";
    case Error::gatewayOutsideSubnet: return "gateway is outside the local subnet";
    case Error::gatewayIsLocal: return "gateway must differ from local IPv4 address";
    case Error::dnsIsLocal: return "DNS server must differ from local IPv4 address";
  }
  return "invalid IPv4 configuration";
}

inline bool select(bool enabled, const char* localText, const char* gatewayText,
                   const char* netmaskText, const char* dnsText,
                   StaticConfig& output, Error& error) {
  output = StaticConfig();
  output.enabled = enabled;
  error = Error::none;
  if (!enabled) return true;
  if (!network_config::parseIPv4(localText, output.local) ||
      !network_config::parseIPv4(gatewayText, output.gateway) ||
      !network_config::parseIPv4(netmaskText, output.netmask) ||
      !network_config::parseIPv4(dnsText, output.dns)) {
    error = Error::malformed;
    return false;
  }
  error = validate(output);
  return error == Error::none;
}

template <typename Configurer>
bool apply(const StaticConfig& config, Configurer configurer) {
  if (!config.enabled || validate(config) != Error::none) return !config.enabled;
  return configurer(config.local, config.gateway, config.netmask, config.dns);
}

template <typename Configurer, typename Begin>
bool configureBeforeBegin(const StaticConfig& config, Configurer configurer, Begin begin) {
  if (!apply(config, configurer)) return false;
  begin();
  return true;
}

}  // namespace network_config
