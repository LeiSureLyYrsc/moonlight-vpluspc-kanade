QT += core testlib
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle

TARGET = kanade_session_test
TEMPLATE = app
DEFINES += KANADE_SESSION_TEST

INCLUDEPATH += $$PWD/../../app

# kanadesession.cpp validates the HTTPS origin and canonical ids through
# ManagedEndpointContext, so that unit is compiled in as well.  None of these
# files uses QtNetwork: no socket, no TLS, no live streaming object is linked.
SOURCES += \
    main.cpp \
    ../../app/backend/kanade/kanadesession.cpp \
    ../../app/backend/kanade/managedendpoint.cpp

HEADERS += \
    ../../app/backend/kanade/kanadesession.h \
    ../../app/backend/kanade/managedendpoint.h
