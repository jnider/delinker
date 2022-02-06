C_SRC_UNLINKER = delinker.c backend.c pe.c elf.c ll.c mz.c lz.c x86.c
CPP_SRC_UNLINKER = reconstruct.cpp
C_OBJS_UNLINKER = $(C_SRC_UNLINKER:%.c=%.o)
CPP_OBJS_UNLINKER += $(CPP_SRC_UNLINKER:%.cpp=%.o)
OBJS_UNLINKER = $(C_OBJS_UNLINKER) $(CPP_OBJS_UNLINKER)

INCLUDE_PATH = -Icapstone/include -Inucleus
LIBRARY_PATH = -Lcapstone -Lnucleus

CC = gcc
CFLAGS = $(INCLUDE_PATH)
CXXFLAGS = $(INCLUDE_PATH)
CPPFLAGS = -O2

ifeq ($(DEBUG), 1)
CFLAGS+=-DDEBUG
CXXFLAGS+=-DDEBUG
endif

.PRECIOUS: *.o

.PHONY: tags

all: delinker

capstone/libcapstone.a:
	cd capstone && ./make.sh

nucleus/libnucleus.a:
	make -C nucleus libnucleus.a

delinker: capstone/libcapstone.a nucleus/libnucleus.a $(C_OBJS_UNLINKER) $(CPP_OBJS_UNLINKER)
	g++ $(C_OBJS_UNLINKER) $(CPP_OBJS_UNLINKER) $(INCLUDE_PATH) $(LIBRARY_PATH) -lcapstone -lnucleus -o delinker

clean:
	rm -rf $(OBJS_UNLINKER) delinker $(OBJS_OTOC) otoc

tags:
	ctags -R -f tags . /usr/local/include
