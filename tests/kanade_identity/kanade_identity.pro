QT += core
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = kanade_identity_test
TEMPLATE = app

# Focused, offline tests for the Kanade client installation identity:
#   * the canonical enrollment / device-login messages (byte-exact with
#     Kanade security/identity.py, sorted keys, compact separators, UTF-8,
#     "label":null for enrollment),
#   * strict scope rejection (non-https origin, path/query/userinfo, IPv6
#     literal, bad UUID/nonce/expiry, role echo, key/label mismatch),
#   * proof failure semantics (empty proof, never signs a mismatched message).
#
# Nothing here touches the network, DPAPI, the filesystem store, Kanade or any
# service; the IdentityStore tests that need Win32 DACLs live in the separate
# control lane.  This target must never be pointed at a real account.

INCLUDEPATH += $$PWD/../../app

SOURCES += \
    main.cpp \
    ../../app/backend/kanade/kanadeidentity.cpp

HEADERS += \
    ../../app/backend/kanade/kanadeidentity.h

# Same bundled OpenSSL the app links (app.pro); no new dependency.
win32 {
    INCLUDEPATH += $$PWD/../../libs/windows/include $$PWD/../../libs/windows/include/x64
    LIBS += -L$$PWD/../../libs/windows/lib/x64
    LIBS += -llibcrypto
    LIBS += crypt32.lib advapi32.lib
}

unix:!macx {
    PKGCONFIG += openssl
}
