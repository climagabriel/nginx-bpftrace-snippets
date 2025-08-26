#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <libelf.h>
#include <errno.h>

#define RETPROBE 1
#define ALL_PIDS -1
#define OK 0
#define ERR -1

int main() {
    const char *path = "/usr/sbin/nginx";
    struct bpf_object *obj;
    struct bpf_program *exit_epoll_wait, *ngx_ev_loop_end;
    int duration_map_fd;
    __u64 ngxoffset = 0x00000000002049e0; //TODO DYNAMIC
    struct bpf_link *uprobe_link, *tracepoint_link;

    obj = bpf_object__open("objs/event_loop_histogram.bpf.o");
    if (!obj) {
        perror("event_loop_histogram.bpf.o open fail");
        return ERR;
    }

    int bpf_obj_load_status = bpf_object__load(obj);
    if (bpf_obj_load_status) {
        perror("event_loop_histogram.bpf.o open fail");
        return ERR;
    }

    exit_epoll_wait = bpf_object__find_program_by_name(obj, "exit_epoll_wait");
    if (!exit_epoll_wait) {
        fprintf(stderr, "ngx_ev_loop_end bpf prog not found");
        return ERR;
    }

    tracepoint_link = bpf_program__attach(exit_epoll_wait);
    if(!tracepoint_link) {
        perror("tracepoint attach failed");
        return ERR;
    }

    ngx_ev_loop_end = bpf_object__find_program_by_name(obj, "ngx_ev_loop_end");
    if (!ngx_ev_loop_end) {
        fprintf(stderr, "ngx_ev_loop_end bpf prog not found");
        return ERR;
    }

    uprobe_link = bpf_program__attach_uprobe(ngx_ev_loop_end, RETPROBE, ALL_PIDS, 
        path, ngxoffset);
    if (!uprobe_link) {
        perror("uprobe attach failed");
        return ERR;
    }

    duration_map_fd = bpf_object__find_map_fd_by_name(obj, "duration_map");
    if (duration_map_fd == ERR) {
        fprintf(stderr, "find map fd failed");
        return ERR;
    }

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

    return OK;
}