REDIS_SRC_DIR ?= ../redis/src

# find the OS
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

# Compile flags for linux / osx
ifeq ($(uname_S),Linux)
	SHOBJ_CFLAGS ?=  -fno-common -g -ggdb
	SHOBJ_LDFLAGS ?= -shared -Bsymbolic
else
	SHOBJ_CFLAGS ?= -dynamic -fno-common -g -ggdb
	SHOBJ_LDFLAGS ?= -bundle -undefined dynamic_lookup
endif
CFLAGS = -I$(REDIS_SRC_DIR) -I$(REDIS_SRC_DIR)/../deps/lua/src $(DEFS) -Wall -g -fPIC -Og -std=gnu99  
LIBS = -lpam
CC=gcc
.SUFFIXES: .c .so .xo .o

all: pam_auth.so 

pam_auth.so: pam_auth.o
	$(LD) -o $@ pam_auth.o $(SHOBJ_LDFLAGS) $(LIBS) -lc 

clean:
	rm -rf *.xo *.so *.o

