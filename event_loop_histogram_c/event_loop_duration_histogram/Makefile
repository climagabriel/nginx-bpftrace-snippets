CC = gcc
CLANG = clang

CFLAGS = -O2 -Wall -lelf
BPF_CFLAGS = -O2 -target bpf -g -Wall

INCLUDES = -I/usr/include/x86_64-linux-gnu
LIBS = -lelf -lz

NAME = ngx_event_loop_histogram

BUILD_DIR = objs

BPF_PROGRAM = $(BUILD_DIR)/$(NAME).bpf.o
LOADER_PROGRAM = $(BUILD_DIR)/$(NAME)

all: $(BUILD_DIR) $(BPF_PROGRAM)  $(LOADER_PROGRAM)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

$(BPF_PROGRAM): $(BUILD_DIR) $(NAME).bpf.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $(NAME).bpf.c -o $(BUILD_DIR)/$(NAME).bpf.o

$(LOADER_PROGRAM): $(BUILD_DIR) $(NAME).c /usr/lib/x86_64-linux-gnu/libbpf.a
	$(CC) $(CFLAGS) $(NAME).c /usr/lib/x86_64-linux-gnu/libbpf.a -o $(LOADER_PROGRAM) $(LIBS)


clean:
	rm -rf $(BUILD_DIR) $(BPF_PROGRAM) $(LOADER_PROGRAM)

.PHONY: all clean
