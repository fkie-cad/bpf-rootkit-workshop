#include <stdio.h>

#include "exec.skel.h"

int main(void) {
  // these functions are auto-generated!
  // they open, load and attach the eBPF program as the name suggests
  // see exec.skel.h for more details after you ran make (skel)
  struct exec *skel = exec__open();
  exec__load(skel);
  exec__attach(skel);

  puts("press enter key to stop");
  getchar();

  exec__detach(skel);
  exec__destroy(skel);

  return 0;
}
