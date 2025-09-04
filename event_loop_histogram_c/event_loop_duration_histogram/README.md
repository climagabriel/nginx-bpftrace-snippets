llvm-objdump -d -r -S --print-imm-hex objs/event_loop_histogram.bpf.o

bpftool prog load objs/event_loop_histogram.bpf.o /sys/fs/bpf/trace_epoll_wait type tracepoint autoattach

rm /sys/fs/bpf/trace_epoll_wait to unpin

bpftool prog list

bpftool prog show name exit_epoll_wait
bpftool prog show name ngx_ev_loop_buckets

bpftool map dump name start_map
bpftool map dump name buckets_map

bpftool prog profile name exit_epoll_wait cycles instructions
bpftool prog profile name ngx_ev_loop_buckets cycles instructions

https://www.kernel.org/doc/html/latest/bpf/map_array.html

ngx_event_loop_histogram -b
ngx_event_loop_histogram -c