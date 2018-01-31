OBJS = upboe.o

all: upboe

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

pboecfg: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -f upboe *.o
