#pragma once

// A managed session must never ask the host for microphone capture: the reviewed
// common-c managed port policy rejects enableMic (LI_MANAGED_POLICY_ERR_MODE).
// The user's LAN preference is only read here, never rewritten.
namespace StreamConfigPolicy {

constexpr bool requestHostMicrophone(bool preferenceEnabled, bool managedSession)
{
    return preferenceEnabled && !managedSession;
}

} // namespace StreamConfigPolicy
