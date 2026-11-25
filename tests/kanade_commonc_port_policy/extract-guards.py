"""Compile the actual guard bodies against an isolated sink, not rewritten predicates."""

import sys
from pathlib import Path
import re


def function(text: str, signature: str) -> str:
    start = text.index(signature)
    stop = text.index("\n}", start) + 2
    return text[start:stop]


def main() -> None:
    src, out = map(Path, sys.argv[1:])
    c = (src / "Connection.c").read_text(encoding="utf-8")
    rtsp = (src / "RtspConnection.c").read_text(encoding="utf-8")
    audio = (src / "AudioStream.c").read_text(encoding="utf-8")
    audio_loop_start = audio.index("int pingCount = 0;")
    audio_loop = re.search(
        r"while\s*\(\s*!PltIsThreadInterrupted\(&udpPingThread\)\s*&&\s*"
        r"LiManagedPortAllowed\(AudioPortNumber,\s*48000\)\s*\)\s*\{",
        audio[audio_loop_start:],
    )
    if audio_loop is None:
        raise ValueError("could not extract the AudioStream send-loop guard")
    audio_guard = audio_loop.group(0)
    bodies = [
        "static LI_MANAGED_PORT_POLICY managedPorts;",
        function(c, "bool LiManagedPortsEnabled("),
        function(c, "bool LiManagedPortAllowed("),
        function(c, "int LiStartConnectionWithPortPolicy("),
        function(rtsp, "static int matHeaderEqual("),
        function(rtsp, "static char* uniqueMatOption("),
        function(rtsp, "static bool managedSetupPort("),
    ]
    for name, port in (("Audio", 48000), ("Video", 47998), ("Control", 47999)):
        check = rtsp.index(f"if (!managedSetupPort(&response, &{name}PortNumber, {port}))")
        end = rtsp.index("goto Exit;", check) + len("goto Exit;")
        bodies.append((name, rtsp[check:end] + "\n}"))
    assert rtsp.index("managedSetupPort(&response, &ControlPortNumber") < rtsp.index(
        "ret = notifyAudioPortNegotiationComplete()"
    )
    assert rtsp.index("if (!LiManagedPortAllowed(RtspPortNumber, 48010))") < rtsp.index(
        "sock = connectTcpSocket(&RemoteAddr"
    )
    assert audio.index(audio_guard, audio_loop_start) < audio.index("sendto(rtpSocket", audio_loop_start)
    guard_bodies, checks = bodies[:-3], bodies[-3:]
    probe_start = rtsp.index("if (LiManagedPortsEnabled()) {", rtsp.index(
        "// No managed UDP probe is attempted until ALL SETUP ports have passed."
    ))
    probe_end = rtsp.index("\n    }", probe_start) + len("\n    }")
    # Retain the actual rejection branches and notification call. Only input
    # delivery, cleanup and the notifier's socket are replaced by the fixture.
    start = ["static int runSetupFixture(RTSP_MESSAGE responses[3]) {", "int ret = 0;",
             "uint16_t AudioPortNumber = 0, VideoPortNumber = 0, ControlPortNumber = 0;",
             "RTSP_MESSAGE response;"]
    for i, (_, check) in enumerate(checks):
        start.extend((f"response = responses[{i}];", check))
    start += [rtsp[probe_start:probe_end], "Exit:", "return ret;", "}"]
    # The extracted production condition controls this bounded fixture loop.
    # Its sole body is the same loopback sink used by the SETUP fixture; this
    # does not reproduce the full GameStream/audio worker or RTP send loop.
    audio_fixture = "\n".join([
        "static int audioGuardChecks;",
        "#define PltIsThreadInterrupted(thread) (++audioGuardChecks > 1)",
        "static int runAudioGuardFixture(unsigned short port) {",
        "    unsigned short AudioPortNumber = port;",
        "    int udpPingThread = 0;",
        "    int iterations = 0;",
        "    audioGuardChecks = 0;",
        "    " + audio_guard,
        "        ++iterations;",
        "        if (emitProbe() != 0) return -1;",
        "    }",
        "    return iterations;",
        "}",
        "#undef PltIsThreadInterrupted",
    ])
    out.write_text("\n\n".join(guard_bodies + [audio_fixture, "\n".join(start)]) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
