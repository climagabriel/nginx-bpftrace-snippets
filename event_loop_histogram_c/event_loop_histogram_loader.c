#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>

const char *argp_program_version = "event_loop_histogram 0.01";
const char *argp_program_bug_address = "<gabriel.clima@gcore.com>";
static char doc[] =  "Nginx event loop duration histogram / live feed";
static char args_doc[] = "c, v";

static struct argp_option options[] = {
  {"cli",  'c', 0,      0,  "max event loop duration per nginx pid since invocation, one per second" },
  {"version",  'v', 0,      0,  "version" },
  { 0 }
};

struct arguments
{
  char *args[1];
  int cli;
  int ver;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'c':
      arguments->cli = 1;
      break;

    case 'v':
      arguments->ver = 1;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

#define RETPROBE 1
#define ALL_PIDS -1
#define OK 0
#define ERR -1

int cli_invocation_mode(struct bpf_object *obj);

int main(int argc, char **argv) {
    struct arguments arguments;
    arguments.cli = 0;
    arguments.ver = 0;
    argp_parse (&argp, argc, argv, 0, 0, &arguments);

    if (arguments.ver) {
        fprintf(stderr, "%s\n", argp_program_version);
        fprintf(stderr, "libbpf: %s\n", libbpf_version_string());
        return OK;
    }

    struct bpf_object *obj;
    struct bpf_program *exit_epoll_wait;
    struct bpf_link *tracepoint_link;

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

    if (arguments.cli) {
        cli_invocation_mode(obj);
    }

    return OK;
}

int cli_invocation_mode(struct bpf_object *obj)
{
    const char *path = "/usr/sbin/nginx";
    struct bpf_program *ngx_ev_loop_end;
    int duration_map_fd;
    __u64 ngxoffset = 0x00000000002049e0; //TODO DYNAMIC
    struct bpf_link *uprobe_link;

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
        printf("\n"); //TODO aggregate stats 
        sleep(1);
    }

    return OK;
}