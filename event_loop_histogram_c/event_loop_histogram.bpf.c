#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} counter_map SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_epoll_wait")
int trace_epoll_wait(void *ctx)
{
    __u32 pid;
    __u64 *value, newval;
    __u64 initial_value = 1;
    char comm[6];

    bpf_get_current_comm(comm, sizeof(comm));

    if (comm[0] != 'n' || comm[1] != 'g' || comm[2] != 'i' |
        comm[3] != 'n' || comm[4] != 'x' || comm[5] != '\0')
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;

    value = bpf_map_lookup_elem(&counter_map, &pid);

    if (value) {
        newval = (*value) + 1;
        bpf_map_update_elem(&counter_map, &pid, &newval, BPF_ANY);
    } else {
        bpf_map_update_elem(&counter_map, &pid, &initial_value, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";