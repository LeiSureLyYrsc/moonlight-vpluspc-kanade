QT += core network testlib concurrent
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle

TARGET = kanade_https_test
TEMPLATE = app

# CI-only real-HTTPS lane for the Kanade client control plane.
#
# This target compiles the PRODUCTION sources and exercises them against an
# in-process Kanade control-plane mock that speaks real TLS over 127.0.0.1 on an
# ephemeral port.  TLS material is generated at run time into memory: no PEM
# file, private key or certificate is checked in, written to disk, or installed
# as system trust.  The client gets only the synthetic CA through an injected
# QSslConfiguration; verification stays on (never VerifyNone on the client side,
# never ignoreSslErrors()).
#
# KANADE_CONTROLLER_TEST exposes KanadeController::setSslConfigurationForTesting.
# It exists ONLY in this test target; product builds never define it.
#
# The Win32 identity store is compiled into Windows desktop builds by default
# (opt out with KANADE_DISABLE_WIN32_IDENTITY).  This lane deliberately does NOT
# opt out: exercising the real DPAPI + private-DACL store is the point, so no
# identity-store macro is defined here at all.
#
# The store refuses the OS volume and every non-fixed volume, so the runner must
# provide an approved scratch root through KANADE_DPAPI_TEST_ROOT (one absolute
# drive path on a fixed non-system volume, created and checked by the CI job).
# main.cpp fails -- it does not skip -- when that variable is missing.
#
# Nothing here contacts a real account, host, Kanade service or the OS trust
# store.  Do not point this target at a real deployment.

win32:!winrt {
    INCLUDEPATH += $$PWD/../../app

    DEFINES += KANADE_CONTROLLER_TEST KANADE_CONTROL_PLANE_TEST_ONLY

    # kanadecontroller.cpp pulls in the managed online session: the runtime
    # manifest validator, the session state machine, the sidecar protocol and the
    # HTTPS transport adapter are all linked here so this lane tracks the real
    # controller rather than a trimmed copy.
    SOURCES += \
        main.cpp \
        mockkanadeserver.cpp \
        testpki.cpp \
        ../../app/backend/kanade/kanadeapi.cpp \
        ../../app/backend/kanade/kanadecontroller.cpp \
        ../../app/backend/kanade/kanadehttptransport.cpp \
        ../../app/backend/kanade/kanadeidentity.cpp \
        ../../app/backend/kanade/kanaderuntime.cpp \
        ../../app/backend/kanade/kanadesession.cpp \
        ../../app/backend/kanade/kanadesidecar.cpp \
        ../../app/backend/kanade/managedendpoint.cpp

    HEADERS += \
        mockkanadeserver.h \
        testpki.h \
        ../../app/backend/kanade/kanadeapi.h \
        ../../app/backend/kanade/kanadecontroller.h \
        ../../app/backend/kanade/kanadehttptransport.h \
        ../../app/backend/kanade/kanadeidentity.h \
        ../../app/backend/kanade/kanaderuntime.h \
        ../../app/backend/kanade/kanadesession.h \
        ../../app/backend/kanade/kanadesidecar.h \
        ../../app/backend/kanade/managedendpoint.h

    # Same bundled OpenSSL the app links; no new dependency.  Only libcrypto is
    # used directly (X509/EVP for the runtime fixture); libssl is the Qt TLS
    # backend's own runtime dependency and is shipped for the OpenSSL backend.
    INCLUDEPATH += $$PWD/../../libs/windows/include $$PWD/../../libs/windows/include/x64
    LIBS += -L$$PWD/../../libs/windows/lib/x64
    LIBS += -llibcrypto
    LIBS += crypt32.lib advapi32.lib

    # The iOS-style backend cannot serve TLS and server-side TLS needs OpenSSL, so
    # ship the OpenSSL DLLs next to the binary instead of relying on PATH.
    contains(QT_ARCH, arm64): kanadeHttpsArch = arm64
    else: kanadeHttpsArch = x64
    CONFIG(debug, debug|release): kanadeHttpsConfig = debug
    else: kanadeHttpsConfig = release
    kanadeHttpsTlsDlls = $$files($$PWD/../../libs/windows/lib/$$kanadeHttpsArch/libcrypto*.dll)
    kanadeHttpsTlsDlls += $$files($$PWD/../../libs/windows/lib/$$kanadeHttpsArch/libssl*.dll)
    for(kanadeHttpsTlsDll, kanadeHttpsTlsDlls) {
        QMAKE_POST_LINK += $$escape_expand(\\n\\t) $$QMAKE_COPY $$shell_quote($$shell_path($$kanadeHttpsTlsDll)) $$shell_quote($$shell_path($$OUT_PWD/$$kanadeHttpsConfig/))
    }
} else {
    # The control plane's identity store and the DPAPI root rules are Windows
    # desktop behaviour.  Keep qmake honest instead of producing a target that
    # would only ever skip.
    error("kanade_https is a Windows-only target")
}
