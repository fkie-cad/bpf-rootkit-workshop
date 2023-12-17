#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

// copies filename to readonly memory area s.t. BPF can't overwrite it
static const char* alloc_filename(const char* filename)
{
  int ret;

  char* buf = (char*)mmap(NULL, 4096,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1, 0);
  if (buf == MAP_FAILED) {
    perror("alloc_filename: failed to alloc mem for "
	"filename: ");
    exit(EXIT_FAILURE);
  }
  strncpy(buf, filename, 4096);

  /* TODO
   * use `mprotect` to change the memory permissions of the filename
   * buffer to readonly; this prevents the BPF program from overwriting
   * it again
   */

  if (ret) {
    perror("alloc_filename: failed to protect mem for "
	"filename: ");
    exit(EXIT_FAILURE);
  }

  return buf;
}

static int do_evil_stuff(void)
{
  printf("Doing evil stuff...\n");
  return 42;
}

int main(int argc, char** argv, char** envp)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  printf("Hello, here's 'a' :)\n");
  printf("User %d\nargc: %d\n", getuid(), argc);
  for (int i = 0; i < argc; i++) {
    printf("argv[%d]: %s\n", i, argv[i]);
  }

  if (fork()) {
    // execute the original program in the parent

    /* TODO
     * issue the `execve` syscall to execute the original program
     */

    perror("main: execve: ");   /* execve() returns only on error */
    exit(EXIT_FAILURE);
  }

  // child
  do_evil_stuff();

  return 0;
}
