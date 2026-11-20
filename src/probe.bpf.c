#include "event.h"
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(void *ctx)
{
    struct openat_event* data = bpf_ringbuf_reserve(&events, sizeof(struct openat_event), 0);
    if (!data) {
        bpf_printk("failed to reserve memory in the ring buffer for the data");
        return 0;
    }

    __u64 __pid_tgid = bpf_get_current_pid_tgid();
    data->pid = (__u32)(__pid_tgid & 0xffffffff);
    data->tgid = (__u32)(__pid_tgid >> 32);

    if (bpf_get_current_comm(data->comm, TASK_COMM_LEN)) {
        bpf_printk("failed to get comm\n");
        goto defer;
    }

    //ctx
    struct trace_event_raw_sys_enter *t_ctx = (struct trace_event_raw_sys_enter*)ctx;

    data->dirfd = (__s32)t_ctx->args[0];

    long res = bpf_probe_read_user_str(data->filename, 256, (const void*)t_ctx->args[1]);
    if (res <= 0) {
        bpf_printk("failed to read filename, error: %d", (__s32)res);
        goto defer;
    }

    data->flags = (__u32)t_ctx->args[2];

    data->mode = (__u32)t_ctx->args[3];

    bpf_ringbuf_submit(data, 0);
    goto end;

    defer:
        bpf_ringbuf_discard(data, 0);
    end:
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
