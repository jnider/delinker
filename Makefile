SRC_UNLINKER = unlinker.c backend.c pe.c elf.c ll.c
OBJS_UNLINKER = $(SRC_UNLINKER:%.c=%.o)

SRC_OTOC = otoc.c backend.c elf.c pe.c ll.c
OBJS_OTOC = $(SRC_OTOC:%.c=%.o)

.PRECIOUS: *.o

all: unlinker otoc

otoc: $(SRC_OTOC)
	gcc $(SRC_OTOC) -o otoc -ludis86 -o otoc

unlinker: $(SRC_UNLINKER)
	gcc $(SRC_UNLINKER) -ludis86 -o unlinker

clean:
	rm -rf $(OBJS_UNLINKER) unlinker $(OBJS_OTOC) otoc

ctags:
	ctags -R -f tags . /usr/local/include ~/projects/udis86/libudis86
