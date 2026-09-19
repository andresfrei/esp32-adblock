#pragma once

#include "network_profile.h"

// Integration seam for the N1 transactional profile helper. The controller does
// not know about Arduino, sockets, or reboot APIs; the board integration owns
// those side effects and must call boot exactly once before WiFi.config/begin.
namespace network_control {

enum class ApplyAction { none, applyCandidate, applyPrevious, useDhcp };

enum class Status { unavailable, stable, trial, recoveryRequired, storageError };

template <typename Store>
class Controller {
 public:
  explicit Controller(Store& store) : store_(store), bootCalled_(false), trialActive_(false),
                                      status_(Status::unavailable), bootResult_(), current_() {}

  network_profile::BootResult boot(uint32_t now) {
    if (bootCalled_) return bootResult_;
    bootCalled_ = true;
    bootResult_ = network_profile::boot(store_, now);
    current_ = bootResult_.profile;
    if (bootResult_.action == network_profile::BootAction::applyCandidate &&
        bootResult_.result == network_profile::Result::pending) {
      trial_ = bootResult_.trial;
      trialActive_ = true;
      status_ = Status::trial;
    } else if (bootResult_.result == network_profile::Result::committed ||
               bootResult_.result == network_profile::Result::reverted) {
      status_ = Status::stable;
    } else {
      status_ = Status::storageError;
    }
    return bootResult_;
  }

  bool bootCalled() const { return bootCalled_; }
  bool storageUsable() const { return bootCalled_ && status_ != Status::unavailable; }
  bool trialActive() const { return trialActive_; }
  const network_profile::TrialSession& trial() const { return trial_; }
  const network_profile::Profile& current() const { return current_; }
  const network_profile::BootResult& bootResult() const { return bootResult_; }
  Status status() const { return status_; }

  network_profile::StageResult stage(const network_profile::Profile& candidate) {
    if (!bootCalled_) return network_profile::StageResult(network_profile::Result::ioerror);
    if (status_ == Status::trial || status_ == Status::storageError) {
      return network_profile::StageResult(network_profile::Result::ioerror);
    }
    const network_profile::StageResult result = network_profile::stage(store_, candidate);
    if (result.result == network_profile::Result::indeterminate ||
        result.result == network_profile::Result::ioerror) {
      status_ = Status::storageError;
    }
    return result;
  }

  network_profile::ConfirmResult confirm(const network_profile::ConfirmationToken& token,
                                         const network_profile::IPv4& actual) {
    network_profile::ConfirmResult result;
    if (!bootCalled_ || status_ == Status::unavailable) {
      result.result = network_profile::Result::ioerror;
      result.error = network_profile::ConfirmError::storage;
      return result;
    }
    result = network_profile::confirm(store_, token, actual);
    if (result.result == network_profile::Result::committed &&
        result.error == network_profile::ConfirmError::none) {
      current_ = result.profile;
      trialActive_ = false;
      status_ = Status::stable;
    } else if (result.error == network_profile::ConfirmError::storage) {
      // A storage read or write fault occurred inside confirm() itself
      // (indeterminate readback, a broken record, or a failed write).
      // Surface it the same way service() does so the dashboard/portal
      // never keeps reporting an in-progress trial the store can no
      // longer vouch for. An ordinary rejection (wrong token/IP, no
      // trial) leaves nothing changed in storage, so it correctly leaves
      // this cached state untouched.
      status_ = Status::storageError;
    }
    return result;
  }

  network_profile::ExpireResult service(uint32_t now) {
    network_profile::ExpireResult result;
    if (!trialActive_ || status_ == Status::storageError) {
      result.result = network_profile::Result::committed;
      result.profile = current_;
      return result;
    }
    result = network_profile::expire(store_, trial_, now);
    if (result.result == network_profile::Result::reverted) {
      current_ = result.profile;
      trialActive_ = false;
      status_ = Status::recoveryRequired;
    } else if (result.result == network_profile::Result::ioerror ||
               result.result == network_profile::Result::indeterminate) {
      // Never reboot on an unverified write. Keep the state visible so the
      // portal/dashboard can report the recovery condition, and stop
      // re-entering expire() on every subsequent service() tick: the top
      // guard now also checks storageError, so a persistent fault cannot
      // turn into an unbounded flash/NVS retry storm from the board's main
      // loop.
      status_ = Status::storageError;
    }
    return result;
  }

  static ApplyAction action(network_profile::BootAction action) {
    switch (action) {
      case network_profile::BootAction::applyCandidate: return ApplyAction::applyCandidate;
      case network_profile::BootAction::applyPrevious: return ApplyAction::applyPrevious;
      case network_profile::BootAction::useDhcp: return ApplyAction::useDhcp;
      case network_profile::BootAction::none: return ApplyAction::none;
    }
    return ApplyAction::none;
  }

 private:
  Store& store_;
  bool bootCalled_;
  bool trialActive_;
  Status status_;
  network_profile::BootResult bootResult_;
  network_profile::TrialSession trial_;
  network_profile::Profile current_;
};

// Adapter contract used by the board layer: applyProfile() configures the
// station without beginning association, and useDhcp() selects DHCP. Keeping
// this action switch in production code prevents a boot marker from being
// silently treated as a generic WiFi reset.
template <typename Adapter>
bool handleAction(network_profile::BootAction action, const network_profile::Profile& profile,
                  Adapter& adapter) {
  switch (action) {
    case network_profile::BootAction::applyCandidate:
    case network_profile::BootAction::applyPrevious:
    case network_profile::BootAction::none:
      return adapter.applyProfile(profile);
    case network_profile::BootAction::useDhcp:
      return adapter.useDhcp();
  }
  return false;
}

inline bool expectedTrialIP(const network_profile::TrialSession& trial,
                            const network_profile::IPv4& actual,
                            network_profile::IPv4& expected) {
  if (trial.revision == 0) return false;
  expected = trial.candidate.dhcp ? actual : trial.candidate.local;
  return network_profile::validUnicast(expected);
}

inline bool matchesExpectedTrialIP(const network_profile::TrialSession& trial,
                                   const network_profile::IPv4& actual) {
  network_profile::IPv4 expected;
  return expectedTrialIP(trial, actual, expected) && network_profile::same(expected, actual);
}

inline const char* statusText(Status status) {
  switch (status) {
    case Status::unavailable: return "unavailable";
    case Status::stable: return "stable";
    case Status::trial: return "trial";
    case Status::recoveryRequired: return "rollback-persisted";
    case Status::storageError: return "storage-error";
  }
  return "unknown";
}

}  // namespace network_control
