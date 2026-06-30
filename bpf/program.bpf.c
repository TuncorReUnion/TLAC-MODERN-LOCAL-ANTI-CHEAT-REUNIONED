#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long args[6];
};

char LICENSE[] SEC("license") = "GPL";

static inline int is_suspicious_file(const char *filename) {
    if (filename[0] == '/' && filename[1] == 'p' && filename[2] == 'r') return 1;
    if (filename[0] == '/' && filename[1] == 's' && filename[2] == 'y') return 1;
    int len = 0;
    while (filename[len] != '\0' && len < 255) len++;
    if (len > 4) {
        if (filename[len-3] == 's' && filename[len-2] == 'o') return 1;
        if (filename[len-3] == 'd' && filename[len-2] == 'l') return 1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *args) {
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)args->args[1]);
    if (is_suspicious_file(filename)) {
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *args) {
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)args->args[0]);
    if (is_suspicious_file(filename)) {
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *args) {
    long request = args->args[0];
    if (request == 16 || request == 0) {
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_fork(struct trace_event_raw_sys_enter *args) {
    return 0;
}
