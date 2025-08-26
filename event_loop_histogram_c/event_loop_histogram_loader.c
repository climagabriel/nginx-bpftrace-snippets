#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <libelf.h>

#define RETPROBE 1
#define ALL_PIDS -1

int main() {
    struct bpf_object *obj;
    struct bpf_program *exit_epoll_wait, *ngx_ev_loop_end;
    struct bpf_map *start_map, *duration_map;
    int start_map_fd, duration_map_fd;
    const char *path = "/usr/sbin/nginx";
    __u64 ngxoffset = 0x00000000002049e0;
    struct bpf_link *link;

    obj = bpf_object__open_file("objs/event_loop_histogram.bpf.o", NULL);
    bpf_object__load(obj);

    exit_epoll_wait = bpf_object__find_program_by_name(obj, "exit_epoll_wait");
    bpf_program__attach(exit_epoll_wait);

    start_map = bpf_object__find_map_by_name(obj, "start_map");
    start_map_fd = bpf_map__fd(start_map);

    ngx_ev_loop_end = bpf_object__find_program_by_name(obj, "ngx_ev_loop_end");
    link = bpf_program__attach_uprobe(ngx_ev_loop_end, RETPROBE, ALL_PIDS, path,
                                                                     ngxoffset);

    duration_map = bpf_object__find_map_by_name(obj, "duration_map");
    duration_map_fd = bpf_map__fd(duration_map);

    //struct bpf_link * bpf_program__attach_uprobe(const struct bpf_program *prog, bool retprobe, pid_t pid, const char *binary_path, size_t func_offset);

    while (1) {
        __u32 key = 0, next_key;
        __u64 value;

        while (bpf_map_get_next_key(duration_map_fd, &key, &next_key) == 0) {
            bpf_map_lookup_elem(duration_map_fd, &next_key, &value);
            printf("PID %u: %llu usec\n", next_key, value);
            key = next_key;
        }
        sleep(1);
    }

    return 0;
}