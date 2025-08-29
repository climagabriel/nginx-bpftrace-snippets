PACKAGE_NAME = ngx-bpf-stats
LOADER_PROGRAM_PATH = $(PACKAGE_NAME)/usr/local/sbin/
BPF_PROGRAM_PATH = $(PACKAGE_NAME)/var/lib/ngx-bpf-stats/
NAME = ngx_event_loop_histogram

BPF_PROGRAM = $(BPF_PROGRAM_PATH)/$(NAME).bpf.o
LOADER_PROGRAM = $(LOADER_PROGRAM_PATH)/$(NAME)

BUILD_DIR = event_loop_duration_histogram/objs/
BUILD_BPF_PROGRAM = $(BUILD_DIR)/$(NAME).bpf.o
BUILD_LOADER_PROGRAM = $(BUILD_DIR)/$(NAME)


all: build $(LOADER_PROGRAM_PATH) $(BPF_PROGRAM_PATH) $(BPF_PROGRAM) $(LOADER_PROGRAM)

build: $(BUILD_BPF_PROGRAM) $(BUILD_LOADER_PROGRAM)
$(BUILD_BPF_PROGRAM) $(BUILD_LOADER_PROGRAM):
	make -C event_loop_duration_histogram

$(LOADER_PROGRAM_PATH):
	mkdir -p $(LOADER_PROGRAM_PATH)

$(BPF_PROGRAM_PATH):
	mkdir -p $(BPF_PROGRAM_PATH)


$(BPF_PROGRAM):
	cp event_loop_duration_histogram/objs/ngx_event_loop_histogram.bpf.o $(BPF_PROGRAM)

$(LOADER_PROGRAM):
	cp event_loop_duration_histogram/objs/ngx_event_loop_histogram $(LOADER_PROGRAM)

clean:
	make clean -C event_loop_duration_histogram
	rm -f $(BPF_PROGRAM)
	rm -f $(LOADER_PROGRAM)
	rm -rf event_loop_duration_histogram/.pytest_cache
	rm -rf event_loop_duration_histogram/test/__pycache__


.PHONY: all clean
