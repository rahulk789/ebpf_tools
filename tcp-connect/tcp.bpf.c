// +build ignore

#include "vmlinux.h"
#include <bpf_core_read.h>
#include <bpf/bpf_helpers.h>

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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} pipe SEC(".maps");

struct info {
    u32 pid;
    u8 comm[32];
    u16 lport;
    u16 rport;
};

const struct info *unused __attribute__((unused));

SEC("kprobe/sys_tcp_connect")
int bind_intercept(struct pt_regs *ctx) {

    struct info infostruct;
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    struct sock_common conn = READ_KERN(sk->__sk_common);

    u64 p= bpf_get_current_pid_tgid();
    p = p >>32;
    
    infostruct.pid=p;
    bpf_get_current_comm(&infostruct.comm,sizeof(infostruct.comm));
    infostruct.lport  = BPF_CORE_READ(sk, __sk_common.skc_num),
	infostruct.rport  = BPF_CORE_READ(sk, __sk_common.skc_dport),     
    
    bpf_perf_event_output(ctx,&pipe, BPF_F_CURRENT_CPU, &infostruct, sizeof(infostruct));
    return 0;
}
