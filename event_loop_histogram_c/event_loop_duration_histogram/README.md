llvm-objdump -d -r -S --print-imm-hex objs/event_loop_histogram.bpf.o

bpftool prog load objs/event_loop_histogram.bpf.o /sys/fs/bpf/trace_epoll_wait type tracepoint autoattach

rm /sys/fs/bpf/trace_epoll_wait to unpin

bpftool prog list

bpftool map dump name <NAME>

gcc -o event_loop_hist event_loop_histogram_loader.c -lbpf
