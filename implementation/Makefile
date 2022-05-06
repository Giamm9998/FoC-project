TERM=kitty
TERM_FLAGS=--detach --hold
TERM_CFLAGS=--title client
TERM_SFLAGS=--title server

.PHONY : run-all build-all make-server make-client

# Order is crucial, as the server must start before the client
run-all:	run-server run-client	

run-server:	make-server
	$(TERM) $(TERM_FLAGS) $(TERM_SFLAGS) server/server

run-client:	make-client
	$(TERM) $(TERM_FLAGS) $(TERM_CFLAGS) client/client

# Compile server and client using their respective Makefiles
make-server:
	make -C server

make-client:
	make -C client
