# Makefile for simple test client
CC=g++
CFLAGS+=-g --std=c++1y -I/usr/local/opt/openssl/include -I../../include -I/usr/local/Cellar/glib/2.44.0/include/glib-2.0 -I/usr/local/Cellar/glib/2.44.0/lib/glib-2.0/include -I/usr/local/opt/gettext/include
LDFLAGS+=-lssl -lwebsockets -lusrsctp -llog4cxx -L/usr/local/Cellar/glib/2.44.0/lib -L/usr/local/opt/gettext/lib -L/usr/local/lib -lnice -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lintl -lcrypto
SOURCES=testclient.cpp WebSocketWrapper.cpp easywsclient.cpp jsoncpp.cpp \
	../../src/PeerConnection.cpp ../../src/NiceWrapper.cpp ../../src/DTLSWrapper.cpp ../../src/SCTPWrapper.cpp ../../src/DataChannel.cpp
OBJECTS=$(SOURCES:.cpp=.o)
NAME=testclient

TARGET=$(NAME)

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm *.o
