CC=g++
CFLAGS=-Wall -Wextra -ansi -pedantic -lcrypto -std=c++17
SOURCES=server.cpp ../common/utils.cpp
OBJECTS=$(SOURCES:.cpp=.o)
BINARY=server

# Debug build flags. Use `make DEBUG=1` to build in debug mode
# Defaults to zero (i.e. release)
DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG -g
else
    CFLAGS += -DNDEBUG -O3
endif

.PHONY : clean

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BINARY) $(OBJECTS)
