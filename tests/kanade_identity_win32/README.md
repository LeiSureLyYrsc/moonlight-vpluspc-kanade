# kanade_identity_win32

Windows-only acceptance tests for the real Kanade client installation identity
store (`moonlight-qt/app/backend/kanade/kanadeidentity.cpp`).

This is the lane that verifies the properties the product store relies on, so
that a Windows build no longer ships the store disabled:

| Property | Test |
| --- | --- |
| Store compiled in and usable | `platformStoreIsAvailable` |
| Root rules (fixed local volume, GUID-differs from Windows volume, outside the Windows dir, no UNC/device/relative) | `rootRulesRejectUnsafeTrees`, `rootOnSystemVolumeIsRejected` |
| DPAPI round trip, replace of the pending key | `saveLoadRoundTrip` |
| Private DACL (current user + SYSTEM, protected) on root and file | `storedFileIsPrivateAndPlain` |
| No readable staging file, no inherited-ACL window | `fileNeverExistsWithInheritedAcl` |
| One file per (origin, user); no cross-scope leak | `scopeIsolationByOrigin`, `scopeIsolationByUser` |
| installation id / key version bound into the sealed blob | `installationIdIsBoundToBlob`, `replacedBlobFailsClosed` |
| Tampering (public key, garbage, empty file) fails closed, never NotFound | `tamperedEnvelopeFailsClosed` |
| forget is idempotent and scope-limited | `forgetIsIdempotentAndScoped` |
| Junction at the root is refused | `reparseRootIsRejected` |
| Junction on an ANCESTOR / intermediate of the root is refused | `ancestorJunctionIsRejected`, `intermediateJunctionIsRejected` |
| Junction at the store file name is refused (read, save, delete) | `reparseStoreFileIsRejected` |
| Pre-existing root with a widened DACL is refused, **not silently re-ACLed** | `nonPrivateRootIsRejected` |
| Pin actually blocks rename/delete (platform contract) | `pinnedRootBlocksRename` |
| Concurrent saves leave exactly one complete envelope | `concurrentSavesNeverCorrupt` |
| Load concurrent with replace never sees a torn file | `concurrentSaveAndLoad` |
| forget racing save leaves a loadable or empty store | `concurrentForgetAndSave` |
| Scope validation | `invalidScopesAreRejected` |

## Running in CI

The test is registered in `.github/workflows/kanade-validation.yml`:

```
call scripts\run-test.bat kanade_identity_win32 kanade_identity_win32_test
```

Junction cases use `fsutil reparsepoint`.  If the runner cannot create a
junction (no NTFS, or the privilege is unavailable) those slots report
**SKIP**; a skip is not a pass and must be reported as unverified.

## Cross-user isolation (not automatable in one process)

`dumpState` and `printCrossUserCommand` are the affordances for the two-account
check.  On a runner with a second local account:

1. As account A:
   ```
   set KANADE_IDENTITY_WRITE_ROOT=D:\tmp\kanade-crossuser
   kanade_identity_win32_test.exe printCrossUserCommand
   ```
2. As account B:
   ```
   set KANADE_IDENTITY_DUMP_ROOT=D:\tmp\kanade-crossuser
   kanade_identity_win32_test.exe dumpState
   ```
3. Account B must observe `root_private=0` (or `root_accepted=0`) and
   `load_outcome=3` (`Error`) — never `0` (`Ok`) and never `1` (`NotFound`,
   which would mint a new key over inaccessible storage).

This is a manual/runner-only affordance; nothing here creates a second account,
changes a password, or touches an existing profile.

## Boundaries

* Synthetic throwaway Ed25519 keys only; no real account, service or secret.
* Roots are `QTemporaryDir`s under the runner temp directory.
* No network, TLS material, CA, or OS trust store is used.
* Not covered: a real Windows build of the full app, real dual-machine
  streaming, and an interactive DPAPI prompt path (there is none:
  `CRYPTPROTECT_UI_FORBIDDEN` is always set).
