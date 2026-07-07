#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct suspicious_event {
    u32 pid;
    u32 syscall_type;
    u64 timestamp_ns;
    char filename[256];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} suspicious_events SEC(".maps");

static __always_inline bool is_suspicious_file(const char *filename) {
    if (bpf_strncmp(filename, 4, "/tmp") == 0) return true;
    if (bpf_strncmp(filename, 9, "/dev/shm/") == 0) return true;

    int len = 0;
    while (filename[len] != '\0' && len < 255) len++;

    if (len >= 3 && filename[len-3] == '.' && filename[len-2] == 's' && filename[len-1] == 'o') return true;
    if (len >= 4 && filename[len-4] == '.' && filename[len-3] == 'd' && filename[len-2] == 'l' && filename[len-1] == 'l') return true;

    return false;
}

static __always_inline void send_event(struct trace_event_raw_sys_enter *ctx, u32 type, const char *fname) {
    struct suspicious_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.syscall_type = type;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    if (fname) {
        bpf_probe_read_kernel_str(&evt.filename, sizeof(evt.filename), fname);
    }

    bpf_perf_event_output(ctx, &suspicious_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *args) {
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)args->args[1]);

    if (is_suspicious_file(filename)) {
        send_event(args, 1, filename);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *args) {
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)args->args[0]);

    if (is_suspicious_file(filename)) {
        send_event(args, 2, filename);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *args) {
    long request = args->args[0];
    if (request == 0 || request == 16) {
        send_event(args, 3, NULL);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *args) {
    send_event(args, 4, NULL);
    return 0;
}
