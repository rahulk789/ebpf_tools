// +build ignore

#include "vmlinux.h"
#include <bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf_endian.h>
char __license[] SEC("license") = "Dual MIT/GPL";

#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_core_read((void *) &_val, sizeof(_val), &ptr);                                     \
        _val;                                                                                  \
    })

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)

# define __bpf_ntohs(x)			__builtin_bswap16(x)

struct info {
    u32 pid;
    u8 comm[32];
    u16 lport;
    u16 rport;
}x;

struct bpf_map_def {
      unsigned int type;
      unsigned int key_size;
      unsigned int value_size;
      unsigned int max_entries;
      unsigned int map_flags;
};
struct bpf_map_def SEC("maps") eventmap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
    .value_size = sizeof(x),
    .max_entries = 3,
};

const struct info *unused __attribute__((unused));

SEC("kprobe/security_socket_bind")
int bind_intercept(struct pt_regs *ctx,  const struct sockaddr *addr) {

    struct info infostruct;
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    struct sock_common conn = READ_KERN(sk->__sk_common);

    u64 p= bpf_get_current_pid_tgid();
    p = p >>32;
    
    infostruct.pid=p;
    bpf_get_current_comm(&infostruct.comm,sizeof(infostruct.comm));
    
    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    struct sockaddr_in *in_addr = (struct sockaddr_in *) address;
    
    // checking bind port address
    u16 x = READ_KERN(in_addr->sin_port);
    infostruct.lport= bpf_ntohs(x);
    infostruct.rport  = READ_KERN(sk->__sk_common.skc_num);

    u32 key = 0;
    bpf_map_update_elem(&eventmap,&key,&infostruct,BPF_ANY);
    return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *skb) {
    
    struct info *s;
    u32 key = 0;
    u16 valuecheck= 4040;
    s = bpf_map_lookup_elem(&eventmap,&key);
    if (!s) return 0;
    
    //checking if the process comm is the one we want
    bool commcheck =  s->comm[0]=='m' && s->comm[1]=='y' && s->comm[2]=='p' && s->comm[3]=='r' && s->comm[4]=='o' && s->comm[5]=='c' && s->comm[6]=='e' && s->comm[7]=='s' && s->comm[8]=='s';
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    
    if (commcheck){
        if ((void *)eth + sizeof(*eth) <= data_end) {
            struct iphdr *ip = data + sizeof(*eth);
            if ((void *)ip + sizeof(*ip) <= data_end) {
                if (ip->protocol == IPPROTO_TCP) {
                    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                    if ((void *)tcp + sizeof(*tcp) <= data_end) {
                        
                        u16 value,valuex = tcp->dest;
                        value = bpf_ntohs(valuex);
                        
                        // uncomment the following lines for debugging, output received in " sudo cat  /sys/kernel/debug/tracing/trace_pipe "
                        // const char fmt_str[] = "Hello, world, from BPF! My PORT is %d\n";
                        // bpf_trace_printk(fmt_str, sizeof(fmt_str),value);
                        
                        if (value == valuecheck || (value>=35000 && value<=65535) )
                        return XDP_PASS;
                        else 
                        return XDP_DROP;

                    }
                }
            }
        }
    }
    return XDP_PASS;
}
