SRC_UNLINKER = delinker.c backend.c pe.c elf.c ll.c
OBJS_UNLINKER = $(SRC_UNLINKER:%.c=%.o)

INCLUDE_PATH = -Icapstone/include
LIBRARY_PATH = -Lcapstone

OBJS = $(SRC:%.c=%.o)

.PRECIOUS: *.o

.PHONY: tags

all: delinker

capstone/libcapstone.a:
	cd capstone && ./make.sh

delinker: capstone/libcapstone.a $(SRC_UNLINKER)
	gcc $(CFLAGS) $(SRC_UNLINKER) $(INCLUDE_PATH) $(LIBRARY_PATH) -lcapstone -o delinker

clean:
	rm -rf $(OBJS_UNLINKER) delinker $(OBJS_OTOC) otoc

tags:
	ctags -R -f tags . /usr/local/include
