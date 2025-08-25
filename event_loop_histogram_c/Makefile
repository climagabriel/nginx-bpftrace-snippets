CC = gcc
CLANG = clang
CFLAGS = -O2 -Wall
BPF_CFLAGS = -O2 -target bpf -g

LIBBPF_PATH = /usr/include/bpf
INCLUDES = -I$(LIBBPF_PATH) -I/usr/include/x86_64-linux-gnu
LIBS = -lbpf -lelf -lz

BPF_PROG = objs/event_loop_histogram.bpf.o
LOADER_PROG = event_loop_hist
#SKEL_HEADER = event_loop_histogram.skel.h

all: $(LOADER_PROG) $(BPF_PROG)


$(BPF_PROG): event_loop_histogram.bpf.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c event_loop_histogram.bpf.c -o objs/event_loop_histogram.bpf.o

$(LOADER_PROG): event_loop_histogram_loader.c
	$(CC) $(CFLAGS) event_loop_histogram_loader.c -o event_loop_hist $(LIBS)


clean:
	rm -f $(BPF_PROG) $(LOADER_PROG)

.PHONY: all clean