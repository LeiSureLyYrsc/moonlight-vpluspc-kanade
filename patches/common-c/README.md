# REM-2 managed GameStream pre-send guard

This patch is against `moonlight-common-c/moonlight-common-c` at
`733025a254e6e166a4afb577cbe056c10257f950`. The adjacent JSON lists the exact
input and output Git blobs and the patch SHA-256. The Windows validation
workflow checks these, applies the patch to its clean ephemeral submodule
checkout, verifies the changed path set, and builds the fixture and client
from the same result. The main repository does not change its gitlink.

`LiStartConnection()` preserves the unqualified LAN entry. The separate
`LiStartConnectionWithPortPolicy()` requires a complete policy and a live
callback; it cannot fall back to LAN. The single common-c run copies the
policy, not its context. Callers own the context until `LiStopConnection()`
has joined the stream workers. The callback is synchronous, nonblocking and
thread-safe; it must not throw or call back into common-c.

The managed path uses literal IPv4 loopback and protected TCP RTSP on 48010.
It does not run address-resolution probes. It accepts a unique canonical
`Transport: server_port=N` for audio 48000, video 47998 and control 47999.
Managed audio probing is deferred until all SETUP replies pass, and the
actual audio/video probe and control startup recheck the lease before sending.
Legacy SETUP fallback and audio probe ordering are unchanged. Mic, legacy
RTSP/stream variants and unexpected ports fail closed. This patch does not
change TLS, RTSP protection, GameStream encryption, or host source pinning.

`tests/kanade_commonc_port_policy` extracts the locked guard bodies and SETUP
branches at qmake time. It substitutes a real isolated UDP loopback sink at
the downstream send seam; negative cases count attempts and writes, and a
positive control must reach the sink. It does not emulate an encrypted RTSP
server or certify a Windows GameStream session.
