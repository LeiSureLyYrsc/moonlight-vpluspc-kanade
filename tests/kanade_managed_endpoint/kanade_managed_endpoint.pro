QT += core testlib
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle

TARGET = kanade_managed_endpoint_test
TEMPLATE = app

INCLUDEPATH += $$PWD/../../app

SOURCES += \
    main.cpp \
    ../../app/backend/kanade/managedendpoint.cpp

HEADERS += \
    ../../app/backend/kanade/managedendpoint.h \
    ../../app/backend/kanade/managednative.h
