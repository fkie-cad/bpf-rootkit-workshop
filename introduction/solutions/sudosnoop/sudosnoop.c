#include "sudosnoop.skel.h"
#include "sudosnoop.h"

#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>

static volatile bool exiting = false;

static int
libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args)
{
  return vfprintf(stderr, format, args);
}

static void
sig_handler(int sig)
{
  exiting = true;
}

static int
handle_event(void* ctx, void* data, size_t data_sz)
{
  const struct event* e = (struct event*)data;

  printf("handle_event: received password char: <%c>\n", e->c);

  return 0;
}

int main(int argc, char** argv)
{
  struct ring_buffer* rb = NULL;
  struct sudosnoop_bpf* skel = NULL;
  int err = 0;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  skel = sudosnoop_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = sudosnoop_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = sudosnoop_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Process events */
  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  /* Clean up */
  ring_buffer__free(rb);
  sudosnoop_bpf__destroy(skel);

  return err < 0 ? -err : 0;
}
