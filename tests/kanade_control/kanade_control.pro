QT += core network concurrent
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = kanade_control_test
TEMPLATE = app

# Focused, offline tests for the Kanade client control plane that do NOT need a
# live service, a QML engine, DPAPI enrollment, or a real account:
#
#   * KanadeApi::normalizeOrigin strict HTTPS origin contract (the single funnel
#     every request goes through): https only, bare host, no userinfo/path/
#     query/fragment, default port stripped, host lowercased.
#   * KanadeController defaults and inert behaviour when the platform/storage
#     gate is closed: no login, no device rows, no error leakage, no crash.
#   * The runtime manifest validator and the sidecar framing/proof helpers, which
#     are pure and need no Windows handle, process or socket.
#
# Deliberately NOT covered here (needs a Qt build + an isolation harness, and is
# deferred to a separate lane): an in-process loopback mock HTTPS server, pairing
# races, and DPAPI/DACL storage.  No TLS material, CA, private key or certificate
# is committed for this lane; anything of that kind must be generated into a temp
# directory at run time and never installed as OS trust.  This target never
# touches the OS trust store and never contacts a real host.
#
# The Win32 identity store is compiled in by default on Windows desktop builds
# (opt out with KANADE_DISABLE_WIN32_IDENTITY).  This target OPTS OUT explicitly
# so it can never create, load or delete a real sealed identity, and so the
# controller legitimately reports supported()==false here.

DEFINES += KANADE_DISABLE_WIN32_IDENTITY

# This fixture has no GameStream/NvHTTP/Session/common-c, so the product's native
# binding cannot be linked.  The guard compiles it out; the controller then
# reports native "unavailable" and can never report onlineReady==true, which is
# the honest answer for a build with no native path.
DEFINES += KANADE_CONTROL_PLANE_TEST_ONLY

INCLUDEPATH += $$PWD/../../app

SOURCES += \
    main.cpp \
    ../../app/backend/kanade/kanadeapi.cpp \
    ../../app/backend/kanade/kanadecontroller.cpp \
    ../../app/backend/kanade/kanadehttptransport.cpp \
    ../../app/backend/kanade/kanadeidentity.cpp \
    ../../app/backend/kanade/kanaderuntime.cpp \
    ../../app/backend/kanade/kanadesession.cpp \
    ../../app/backend/kanade/kanadesidecar.cpp \
    ../../app/backend/kanade/managedendpoint.cpp

HEADERS += \
    ../../app/backend/kanade/kanadeapi.h \
    ../../app/backend/kanade/kanadecontroller.h \
    ../../app/backend/kanade/kanadehttptransport.h \
    ../../app/backend/kanade/kanadeidentity.h \
    ../../app/backend/kanade/kanaderuntime.h \
    ../../app/backend/kanade/kanadesession.h \
    ../../app/backend/kanade/kanadesidecar.h \
    ../../app/backend/kanade/managedendpoint.h \
    ../../app/backend/kanade/managednative.h

win32 {
    INCLUDEPATH += $$PWD/../../libs/windows/include $$PWD/../../libs/windows/include/x64
    LIBS += -L$$PWD/../../libs/windows/lib/x64
    LIBS += -llibcrypto
    LIBS += crypt32.lib advapi32.lib
}

unix:!macx {
    PKGCONFIG += openssl
}
