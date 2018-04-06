SRC = unlinker.c backend.c pe.c elf.c ll.c

OBJS = $(SRC:%.c=%.o)

.PRECIOUS: *.o

unlinker: $(SRC)
	gcc $(CFLAGS) $(SRC) -ludis86 -o unlinker

clean:
	rm -rf $(OBJS) unlinker

ctags:
	ctags -R -f tags . /usr/include
