SRC = unlinker.c backend.c pe.c elf.c ll.c

OBJS = $(SRC:%.c=%.o)

.PRECIOUS: *.o

unlinker: $(SRC)
	gcc $(SRC) -ludis86 -o unlinker 

clean:
	rm -rf $(OBJS)

ctags:
	ctags -R -f tags . /usr/local/include
