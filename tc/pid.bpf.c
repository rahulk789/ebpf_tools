// +build ignore

#include "vmlinux.h"
#include <bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/*struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} pipe SEC(".maps");
*/
/*struct info {
    u32 pid;
    u8 comm[32];
    u16 lport;
    u16 rport;
};
*/
const struct info *unused __attribute__((unused));

SEC("tc")
int traffic_control(struct __sk_buff* skb) {
    char hi[50]="im just trolling lol";
    bpf_printk("%s",hi);
    return 0;
}
