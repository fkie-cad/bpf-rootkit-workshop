/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Adapted from: Pat Hogan @pathtofile, "exechijack"
 */

#ifndef _EXECA_USER_H
#define _EXECA_USER_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>

static volatile sig_atomic_t exiting;

void sig_int(int signo)
{
  exiting = 1;
}

static bool setup_sig_handler()
{
  // add handlers for SIGINT and SIGTERM so we shutdown cleanly
  __sighandler_t sighandler = signal(SIGINT, sig_int);
  if (sighandler == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n",
	strerror(errno));
    return false;
  }
  sighandler = signal(SIGTERM, sig_int);
  if (sighandler == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n",
	strerror(errno));
    return false;
  }
  return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args)
{
  return vfprintf(stderr, format, args);
}

static bool bump_memlock_rlimit(void)
{
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "bump_memlock_rlimit: failed "
	"to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
    return false;
  }
  return true;
}

static bool setup()
{
  // set up libbpf errors and debug info callback
  libbpf_set_print(libbpf_print_fn);

  // bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything
  if (!bump_memlock_rlimit()) {
    return false;
  };

  // setup signal handler so we exit cleanly
  if (!setup_sig_handler()) {
    return false;
  }

  return true;
}

#endif // _EXECA_USER_H
