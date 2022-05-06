SHELL=/bin/zsh
TERM=kitty
TERM_FLAGS=--detach --hold
TERM_CFLAGS=--title client
TERM_SFLAGS=--title server

.PHONY : run-all build-all make-server make-client

# Order is crucial, as the server must start before the client
run-all:	make-server make-client
	$(TERM) $(TERM_FLAGS) $(TERM_SFLAGS) server/server
	$(TERM) $(TERM_FLAGS) $(TERM_CFLAGS) client/client

build-all:	server client

# Compile server and client using their respective Makefiles
make-server:
	make -C server

make-client:
	make -C client
