TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap

SOURCES += logmsg.cpp main.c oam.c


HEADERS += logmsg.h oam.h

