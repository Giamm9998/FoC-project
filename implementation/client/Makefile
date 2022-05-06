CC=g++
CFLAGS=-Wall -Wextra -ansi -pedantic -lcrypto -g
LDFLAGS=
SOURCES=client.cpp
OBJECTS=$(SOURCES:.cpp=.o)
BINARY=client

.PHONY : clean

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BINARY) $(OBJECTS)