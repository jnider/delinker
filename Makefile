SRC = unlinker.c backend.c pe.c

OBJS = $(SRC:%.c=%.o)

unlinker: $(SRC)
	gcc $(SRC) -o unlinker

clean:
	rm -rf $(OBJS)
