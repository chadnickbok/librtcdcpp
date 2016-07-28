# Makefile for simple test client
CC=g++
CFLAGS+=-g --std=c++11 -Wall -I/usr/local/opt/openssl/include
LDFLAGS+=-lssl -lwebsockets
SOURCES=testclient.cpp WebSocketWrapper.cpp easywsclient.cpp
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
