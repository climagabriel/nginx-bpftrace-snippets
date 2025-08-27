#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} duration_map SEC(".maps");


SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int exit_epoll_wait(void *ctx)
{
    __u32 pid;
    __u64 ts;
    char comm[6];

    bpf_get_current_comm(comm, sizeof(comm));

    if (comm[0] != 'n' || comm[1] != 'g' || comm[2] != 'i' |
        comm[3] != 'n' || comm[4] != 'x' || comm[5] != '\0')
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start_map, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ngx_ev_loop_end)
{
    __u32 pid;
    __u64 start_ts, current_ts, current_duration, prev_duration;
    void *start_ts_p, *prev_duration_p;

    pid = bpf_get_current_pid_tgid() >> 32;

    start_ts_p = bpf_map_lookup_elem(&start_map, &pid);
    if (!start_ts_p)
        return 0;

    bpf_map_delete_elem(&start_map, &pid);

    start_ts = *(__u64 *)start_ts_p;
    current_ts = bpf_ktime_get_ns();

    current_duration = (current_ts - start_ts) / 1000;

    prev_duration_p = bpf_map_lookup_elem(&duration_map, &pid);

    if (!prev_duration_p) {
        bpf_map_update_elem(&duration_map, &pid, &current_duration, BPF_ANY);
    } else {
        prev_duration = *(__u64 *)prev_duration_p;
        if (current_duration > prev_duration) {
            bpf_map_update_elem(&duration_map, &pid, &current_duration, BPF_ANY);
            return 0;
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";