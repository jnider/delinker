SRC_UNLINKER = delinker.c backend.c pe.c elf.c ll.c
OBJS_UNLINKER = $(SRC_UNLINKER:%.c=%.o)

OBJS = $(SRC:%.c=%.o)

.PRECIOUS: *.o

.PHONY: tags

all: delinker

delinker: $(SRC_UNLINKER)
	gcc $(SRC_UNLINKER) -ludis86 -o delinker

clean:
	rm -rf $(OBJS_UNLINKER) delinker $(OBJS_OTOC) otoc

tags:
	ctags -R -f tags . /usr/local/include ~/projects/udis86/libudis86
