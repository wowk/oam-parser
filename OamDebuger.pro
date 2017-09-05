TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap

SOURCES += main.c oam.c


HEADERS += logmsg.h oam.h \
    oamdefs.h

