CC=g++
CFLAGS=-Wall -Wextra -ansi -pedantic -lcrypto -g
LDFLAGS=
SOURCES=server.cpp
OBJECTS=$(SOURCES:.cpp=.o)
BINARY=server

.PHONY : clean

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BINARY) $(OBJECTS)