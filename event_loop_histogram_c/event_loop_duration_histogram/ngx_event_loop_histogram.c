#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>

#define RETPROBE 1
#define ALL_PIDS -1
#define OK 0
#define ERR -1

const char *argp_program_version = "ngx_event_loop_histogram 0.01";
const char *argp_program_bug_address = "<gabriel.clima@gcore.com>";
static char doc[] =  "Nginx event loop duration histogram / live feed";
static char args_doc[] = "c, v, b, q";

static struct argp_option options[] = {
  {"cli",  'c', 0,      0,  "max event loop duration per nginx pid since invocation, one per second" },
  {"buckets",  'b', 0,      0,  "buckets live one per sec" },
  {"version",  'v', 0,      0,  "version" },
  {"quiet",  'q', 0,      0,  "quiet, disable some stderr messages" },
  {"object",   'o', "PATH", 0, "bpf object file path" },
  { 0 }
};

struct arguments
{
  char *args[1];
  int cli;
  int buckets;
  int ver;
  int quiet;
  char *object_path; /*TODO you should be able to combine it with other flags*/
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

    case 'b':
      arguments->buckets = 1;
      break;

    case 'q':
      arguments->quiet = 1;
      break;

    case 'o':
      if (access(arg, F_OK) != F_OK) {
            perror("");
            exit(ERR);
      }
      arguments->object_path = arg;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };


const char *ngx_epoll_process_events = "ngx_epoll_process_events";
const char *path = "/usr/sbin/nginx";
const char *bpf_obj_path_dev = "objs/ngx_event_loop_histogram.bpf.o";
const char *bpf_obj_path_prod = "/var/lib/ngx-bpf-stats/ngx_event_loop_histogram.bpf.o";

int cli_invocation_mode(struct bpf_object *obj);
int print_buckets_mode(struct bpf_object *obj);
int prometheus_histogram_mode(struct bpf_object *obj);
__u64 find_function_offset(const char *path, const char *func);

struct arguments arguments;

int main(int argc, char **argv) {
    arguments.cli = 0;
    arguments.ver = 0;
    arguments.buckets = 0;
    arguments.quiet = 0;
    arguments.object_path = NULL;
    argp_parse (&argp, argc, argv, 0, 0, &arguments);

    if (arguments.ver) {
        fprintf(stderr, "%s\n", argp_program_version);
        fprintf(stderr, "libbpf: %s\n", libbpf_version_string());
        return OK;
    }

    struct bpf_object *obj;
    struct bpf_program *exit_epoll_wait;
    struct bpf_link *tracepoint_link;

    if (arguments.object_path) {
        obj = bpf_object__open(arguments.object_path);
    } else if (access(bpf_obj_path_dev, F_OK) == OK) {
        obj = bpf_object__open(bpf_obj_path_dev);
    } else if (access(bpf_obj_path_prod, F_OK) == OK) {
        obj = bpf_object__open(bpf_obj_path_prod);
    } else {
        fprintf(stderr, "expected bpf object at %s or %s \n", bpf_obj_path_dev, bpf_obj_path_prod);
        fprintf(stderr, "gimme the path as -o path/..bpf.o \n");
        return ERR;
    }

    if (!obj) {
        perror("ngx_event_loop_histogram.bpf.o open fail");
        return ERR;
    }

    int bpf_obj_load_status = bpf_object__load(obj);
    if (bpf_obj_load_status) {
        perror("ngx_event_loop_histogram.bpf.o load fail");
        return ERR;
    }
    exit_epoll_wait = bpf_object__find_program_by_name(obj, "exit_epoll_wait");
    if (!exit_epoll_wait) {
        fprintf(stderr, "exit_epoll_wait bpf prog not found");
        return ERR;
    }

    tracepoint_link = bpf_program__attach(exit_epoll_wait);
    if(!tracepoint_link) {
        perror("tracepoint attach failed");
        return ERR;
    }

    if (arguments.cli) {
        fprintf(stderr, "max event loop duration per nginx pid since invocation, per-second refresh\n");
        cli_invocation_mode(obj);
    }

    if (arguments.buckets) {
        fprintf(stderr, "live event loop duration buckets\n");
        print_buckets_mode(obj);
    }

    prometheus_histogram_mode(obj);
    bpf_object__close(obj);
    return OK;
}

int cli_invocation_mode(struct bpf_object *obj)
{
    struct bpf_program *ngx_ev_loop_duration;
    int duration_map_fd;
    struct bpf_link *uprobe_link;
    __u64 ngxoffset = find_function_offset(path, ngx_epoll_process_events);

    ngx_ev_loop_duration = bpf_object__find_program_by_name(obj, "ngx_ev_loop_duration");
    if (!ngx_ev_loop_duration) {
        fprintf(stderr, "ngx_ev_loop_duration bpf prog not found");
        return ERR;
    }

    duration_map_fd = bpf_object__find_map_fd_by_name(obj, "duration_map");
    if (duration_map_fd == ERR) {
        fprintf(stderr, "find map fd failed");
        return ERR;
    }

    uprobe_link = bpf_program__attach_uprobe(ngx_ev_loop_duration, RETPROBE, ALL_PIDS,
        path, ngxoffset);
    if (!uprobe_link) {
        perror("uprobe attach failed");
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

int print_buckets_mode(struct bpf_object *obj)
{
    struct bpf_program *ngx_ev_loop_buckets;
    int buckets_map_fd;
    struct bpf_link *uprobe_link;
    __u32 bucket_min, bucket_max;
    __u64 ngxoffset = find_function_offset(path, ngx_epoll_process_events);

    ngx_ev_loop_buckets = bpf_object__find_program_by_name(obj, "ngx_ev_loop_buckets");
    if (!ngx_ev_loop_buckets) {
        fprintf(stderr, "ngx_ev_loop_buckets bpf prog not found");
        return ERR;
    }

    buckets_map_fd = bpf_object__find_map_fd_by_name(obj, "buckets_map");
    if (buckets_map_fd == ERR) {
        fprintf(stderr, "find map fd failed");
        return ERR;
    }

    uprobe_link = bpf_program__attach_uprobe(ngx_ev_loop_buckets, RETPROBE, ALL_PIDS,
        path, ngxoffset);
    if (!uprobe_link) {
        perror("uprobe attach failed");
        return ERR;
    }


    while (1) { // TODO: switch to explicit for loop up to max buckets_map
        __u32 key = 0, next_key;
        __u64 value;

        while (bpf_map_get_next_key(buckets_map_fd, &key, &next_key) == 0) {
            bpf_map_lookup_elem(buckets_map_fd, &next_key, &value);

            if (1) {
                bucket_min = 1 << (next_key -1);
                bucket_max = 1 << (next_key);
                printf("[%u .. %u] %llu\n", bucket_min, bucket_max, value);
            }
            key = next_key;
        }
        printf("\n");
        sleep(1);
    }

    return OK;
}

int prometheus_histogram_mode(struct bpf_object *obj)
{
    struct bpf_program *ngx_ev_loop_buckets;
    int buckets_map_fd;
    struct bpf_link *uprobe_link;
    __u64 ngxoffset = find_function_offset(path, ngx_epoll_process_events);

    ngx_ev_loop_buckets = bpf_object__find_program_by_name(obj, "ngx_ev_loop_buckets");
    if (!ngx_ev_loop_buckets) {
        fprintf(stderr, "ngx_ev_loop_buckets bpf prog not found");
        return ERR;
    }

    buckets_map_fd = bpf_object__find_map_fd_by_name(obj, "buckets_map");
    if (buckets_map_fd == ERR) {
        fprintf(stderr, "find map fd failed");
        return ERR;
    }

    uprobe_link = bpf_program__attach_uprobe(ngx_ev_loop_buckets, RETPROBE, ALL_PIDS,
        path, ngxoffset);
    if (!uprobe_link) {
        perror("uprobe attach failed");
        return ERR;
    }


    if (!arguments.quiet) {
        fprintf(stderr, "wait for 17 seconds; this is the prometheus histogram mode\nyou may want to use -c , -b , --help instead\n\n\n");
    }

    sleep(17);  /* Protmehteus agent scrape_interval: 20s
                 * Eventually this should be a continuously running service
                 * that exposes the metric on :port/metric
                 * and deliver a target file to /etc/prometheus-agent/targets/
                 * but be careful with long-running bpf programs, they can crash your kernel
                 */
    fprintf(stdout, "# HELP nginx_event_loop_duration_usec Histogram of nginx event loop duration\n");
    fprintf(stdout, "# TYPE nginx_event_loop_duration_usec histogram\n");

    __u64 cum = 0;

     /* buckets_map array has 26 max entries
      * so 2^26 microseconds ~ 33 seconds is the largest bucket
      * and that's already way higher than critically large event loop duration
      */
    for ( __u32 i = 0 ; i < 26 ; i++ ) {
        __u64 value;
        bpf_map_lookup_elem(buckets_map_fd, &i, &value);
        cum += value;
        __u32 le = 1 << (i);
        printf("nginx_event_loop_duration_usec_bucket{le=\"%u\"} %llu\n", le, cum);
    }
    printf("nginx_event_loop_duration_usec_bucket{le=\"+Inf\"} %llu\n", cum);

    /* a pid is removed from the start_map when it returns from ngx_epoll_process_events()
     * so you want to check that map periodically, check for pids that have been in there too long
     * then log some ustacks and increment a counter to alert on if the proc is still executing
     * and hope that the ustacks you collected tell you why the worker was having such a long event loop
     */

    close(buckets_map_fd);
    bpf_link__destroy(uprobe_link);
    return OK;
}

__u64 find_function_offset(const char *path, const char *func)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1)  {
        perror("nginx binary");
        exit(-1);
    }
    size_t shstrndx;

    Elf *elf;
    Elf_Scn *scn = NULL;
    const char *sh_name;

    GElf_Shdr shdr;
    if (elf_version(EV_CURRENT) == EV_NONE)
        goto failure;

    if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
        goto failure;

    if (elf_kind(elf) != ELF_K_ELF)
        goto failure;

    elf_getshdrstrndx(elf, &shstrndx);

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            goto failure;

        if ((sh_name = elf_strptr(elf, shstrndx, shdr.sh_name)) == NULL)
            goto failure;

        if (shdr.sh_type == SHT_SYMTAB) {
            if (!arguments.quiet)
                fprintf(stderr, "Found symbol table: %s in %s\n", sh_name, path);

            Elf_Data *data = elf_getdata(scn, NULL);
            if (data == NULL)
                continue;

            size_t symbol_count = shdr.sh_size / shdr.sh_entsize;

            Elf_Scn *str_scn = elf_getscn(elf, shdr.sh_link);
            if (str_scn == NULL)
                continue;

            for (size_t i = 0; i < symbol_count; i++) {
                GElf_Sym sym;
                if (gelf_getsym(data, i, &sym) != &sym)
                    continue;

                const char *sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (sym_name == NULL)
                    continue;

                if (GELF_ST_TYPE(sym.st_info) == STT_FUNC) {

                    //printf("Function: %s, Offset: 0x%lx, Size: %lu\n",
                    //       sym_name, sym.st_value, sym.st_size);

                    if (strcmp(sym_name, func) == 0) {
                        if (!arguments.quiet)
                            fprintf(stderr, "%s offset: 0x%lx %ld\n",sym_name, sym.st_value, sym.st_value);
                        return sym.st_value;
                    }
                }
            }
        }
    }

    elf_end(elf);
    close(fd);
    return 0;
failure:
    fprintf(stderr, "Elf error: %s\n", elf_errmsg(-1));
    close(fd);
    exit(-1);

}
