#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, map_fd;

    obj = bpf_object__open_file("event_loop_histogram.bpf.o", NULL);
    bpf_object__load(obj);

    prog = bpf_object__find_program_by_name(obj, "trace_epoll_wait_enter");
    bpf_program__attach(prog);

    map = bpf_object__find_map_by_name(obj, "pid_count_map");
    map_fd = bpf_map__fd(map);

    while (1) {
        __u32 key = 0, next_key;
        __u64 value;

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            bpf_map_lookup_elem(map_fd, &next_key, &value);
            printf("PID %u: %llu calls\n", next_key, value);
            key = next_key;
        }
        sleep(1);
    }

    return 0;
}