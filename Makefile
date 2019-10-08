SRC_UNLINKER = delinker.c backend.c pe.c elf.c ll.c
OBJS_UNLINKER = $(SRC_UNLINKER:%.c=%.o)

INCLUDE_PATH = -Icapstone/include -Inucleus
LIBRARY_PATH = -Lcapstone -Lnucleus

CPPFLAGS = -O2

.PRECIOUS: *.o

.PHONY: tags

all: delinker

capstone/libcapstone.a:
	cd capstone && ./make.sh

nucleus/libnucleus.a:
	make -C nucleus libnucleus.a

delinker: capstone/libcapstone.a nucleus/libnucleus.a $(SRC_UNLINKER)
	g++ $(CPPFLAGS) $(SRC_UNLINKER) $(INCLUDE_PATH) $(LIBRARY_PATH) -lcapstone -lnucleus -o delinker

clean:
	rm -rf $(OBJS_UNLINKER) delinker $(OBJS_OTOC) otoc

tags:
	ctags -R -f tags . /usr/local/include
