#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "event.h"

#define OBJ_ELF_PATH "build/probe.bpf.o"

static struct bpf_link *link_openat;

//SIGINT handler for cleanup
void handle_SIGINT(int _sig) {
    (void)_sig;
    printf("SIGINT: stopping\n");
    if (link_openat)
        bpf_link__destroy(link_openat);

    exit(0);
}

//Main callback for handling openat syscall related events
int callback(void *_ctx, void *data, size_t size) {
    (void)_ctx;
    if (size + 1 != sizeof(struct openat_event)) {
        fprintf(stderr, "error: event cannot be processed since received data does not have the correct length for the expected struct (had %lu, expected %lu)\n",
            size, sizeof(struct openat_event));
        return 1;
    }
    struct openat_event *event = (struct openat_event*)data;
    printf(" > data extracted from event: comm: %s, pid: %u, tgid: %d, \n",
        event->comm, event->pid, event->tgid);
    printf(" > > filename: %s, dirfd: %d, flags: 0x%x, mode: 0x%o\n\n",
        event->filename, event->dirfd, event->flags, event->mode);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, handle_SIGINT);

    if (argc < 2) {
        fprintf(stderr, "error: No program name given\n");
        printf("usage: main handle_openat\n");
        return 1;
    }

    char *program_name = argv[1];

    struct bpf_object *obj = bpf_object__open_file(OBJ_ELF_PATH, NULL);
    if (!obj) {
        perror("bpf_object__open_file:");
        return 1;
    }
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "bpf_object__load: %s\n", strerror(-err));
        return 1;
    }

    struct bpf_program * program_openat = bpf_object__find_program_by_name(obj, program_name);
    if (!program_openat) {
        fprintf(stderr, "bpf_object__find_program_by_name: failed, given name '%s' has not been found inside the ELF\n", program_name);
        return 1;
    }

    link_openat = bpf_program__attach(program_openat);
    if (!link_openat) {
        perror("bpf_program__attach");
        return 1;
    }

    struct bpf_map *map_events = bpf_object__find_map_by_name(obj, "events");
    if (!map_events) {
        fprintf(stderr, "bpf_object__find_map_by_name: failed, 'events' map was not found inside the ELF\n");
        return 1;
    }

    if (bpf_map__type(map_events) != BPF_MAP_TYPE_RINGBUF) {
        fprintf(stderr, "map 'events' from the ELF is not a ring buffer\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map_events), callback, NULL, 0);

    for(;;) {
        ring_buffer__poll(rb, 1000);
    }
}
