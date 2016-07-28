# Makefile for simple test client

CFLAGS+=-g -I/usr/local/opt/openssl/include -I/usr/local/include
LDFLAGS+=-lssl -lwebsockets
SOURCES=wsclient.c
OBJECTS=$(SOURCES:.c=.o)
NAME=testclient

TARGET=$(NAME)

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm *.o
