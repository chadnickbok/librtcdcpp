# Makefile for simple test client
CC=g++
CFLAGS+=-g --std=c++1y -DINET -DINET6 -I/usr/local/opt/openssl/include -I../../include -I/usr/local/Cellar/glib/2.44.0/include/glib-2.0 -I/usr/local/Cellar/glib/2.44.0/lib/glib-2.0/include -I/usr/local/opt/gettext/include -pthread -I/usr/include/nice -I/usr/include/gupnp-igd-1.0 -I/usr/include/gupnp-1.0 -I/usr/include/gssdp-1.0 -I/usr/include/libsoup-2.4 -I/usr/include/libxml2 -I/usr/include/uuid -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
LDFLAGS+=-pthread -lssl -lwebsockets -lusrsctp -llog4cxx -lnice -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lcrypto
SOURCES=testclient.cpp WebSocketWrapper.cpp easywsclient.cpp jsoncpp.cpp \
	../../src/PeerConnection.cpp ../../src/NiceWrapper.cpp ../../src/DTLSWrapper.cpp ../../src/SCTPWrapper.cpp ../../src/DataChannel.cpp
OBJECTS=$(SOURCES:.cpp=.o)
NAME=testclient

TARGET=$(NAME)

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.cpp.o:
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm *.o
