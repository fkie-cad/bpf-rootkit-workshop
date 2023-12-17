// https://github.com/qmonnet/echo-bpftool/blob/main/counter.c

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

// documentation:
//   - https://kernel.org/doc/html//next/bpf/btf.html
//   - https://docs.kernel.org/next/bpf/map_array.html
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY); // map is a simple array
  __type(key, __u32);               // 4 byte key size
  __type(value, __u32);             // 4 byte value size
  __uint(max_entries, 1);           // one entry
} counter_map SEC(".maps");

// we use a hook for eXpress Data Path (XDP) that currently can intercept
// incoming network packets
// documentation:
//   - https://docs.cilium.io/en/latest/bpf/progtypes/#xdp
SEC("xdp")
// this function can be named arbitrarily
int xdp_count(struct xdp_md *ctx) {
    // our key is just a constant index into the array (this would be different for e.g. hash maps)
    __u32 key = 0;
    // pointer to the counter
    __u32 *counter;

    // get a pointer to the counter from the counter map
    counter = bpf_map_lookup_elem(&counter_map, &key);

    // error, e.g., wrong key
    if (!counter)
      return XDP_PASS; // let the packet pass anyway

    // increment the counter
    // there's no need to update the maps/array explicitly
    *counter = *counter + 1;
    
    // let all packets pass
    // XDP_DROP or XDP_REDIRECT would be other possible return values
    return XDP_PASS;
}
