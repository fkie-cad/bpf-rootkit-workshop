// this file does not exists in the beginning and will be generated via BPF Type
// Format (BTF)
#include "vmlinux.h"
// this comes with libbpf-dev(el) package on your Linux distribution
#include <bpf/bpf_helpers.h>

// see details here: cat /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
struct sys_enter_execve_ctx {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  int __syscall_nr;
  const char *filename;
  const char *const *argv;
  const char *const *envp;
};

// here we define the hook for an event
// tp: type is tracepoint
// syscall: it's a system call tracepoint (see /sys/kernel/tracing/events/syscalls/ for more events)
// sys_enter_execve: execve() system call when entered (there is also sys_exit_execve)
SEC("tp/syscalls/sys_enter_execve")
// here we get some context information
// find details here: cat /sys/kernel/tracing/events/syscalls/sys_enter_execve/format function
// handle_execve can be named arbitrarily
int handle_execve(struct sys_enter_execve_ctx *ctx) {
  // run sudo cat /sys/kernel/debug/tracing/trace_pipe to see the output
  bpf_printk("filename: %s", ctx->filename);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
