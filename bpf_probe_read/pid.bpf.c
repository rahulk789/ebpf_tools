// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def {
      unsigned int type;
      unsigned int key_size;
      unsigned int value_size;
      unsigned int max_entries;
      unsigned int map_flags;
};
struct bpf_map_def SEC("maps") pidcheck = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 3,
};

const struct pidstruct *unused __attribute__((unused));

SEC("kprobe/sys_execve")
int pid_matcher(struct pt_regs *ctx) {
    u64 p,*boolval,*matchval,present=2,empty=1;
    u32 index0 = 0; //value at index0 current pid
    u32 index1 = 1; //value at index1 is 2 if matched 1 if not matched
    u32 index2 = 2; //value at index2 has user asked pid
    
    p=bpf_get_current_pid_tgid();
    p = p >> 32 ;
    bpf_map_update_elem(&pidcheck,&index0,&p,BPF_ANY);
    
    
    matchval = bpf_map_lookup_elem(&pidcheck,&index2); //user pid
    if (matchval){
        if (p==*matchval){
            boolval = bpf_map_lookup_elem(&pidcheck,&index1); // matched or not
            if (boolval){
                bpf_map_update_elem(&pidcheck, &index1, &present, BPF_ANY); //update if matched
                return 0;}
            }
        }
    bpf_map_update_elem(&pidcheck,&index1,&empty,BPF_ANY); //no match
    return 0;
}
