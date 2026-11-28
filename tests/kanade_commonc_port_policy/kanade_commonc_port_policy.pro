QT += network
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = kanade_commonc_port_policy_test
COMMON = $$PWD/../../moonlight-common-c/moonlight-common-c/src
INCLUDEPATH += $$COMMON
!exists($$COMMON/ManagedPortPolicy.h): error("Apply and verify the locked managed port policy patch first")
!system(python -B $$shell_quote($$PWD/extract-guards.py) $$shell_quote($$COMMON) $$shell_quote($$OUT_PWD/managed-port-guards.inc)): error("Could not bind test to patched guard source")
INCLUDEPATH += $$OUT_PWD
INCLUDEPATH += $$PWD/../../app
SOURCES += main.cpp
