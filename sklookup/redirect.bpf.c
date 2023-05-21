
#include "vmlinux.h"
#include <bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf_endian.h>
#define AF_INET		2
char __license[] SEC("license") = "Dual MIT/GPL";
static const __u16 DST_PORT = 4040; 

// uncomment the following lines for debugging, output received in " sudo cat  /sys/kernel/debug/tracing/trace_pipe "

SEC("sk_lookup")
int redir_ip4(struct bpf_sk_lookup *ctx)
{
    struct task_struct *s;
    char comm[16];
    int err;
    if (ctx->family == AF_INET) {
            s = (struct task_struct*)bpf_get_current_task();
            err = bpf_core_read(&comm, sizeof(comm), &s->comm);
            if (!err) {
            bool commcheck = comm[0]=='m' && comm[1]=='y' && comm[2]=='p' && comm[3]=='r' && comm[4]=='o' && comm[5]=='c' && comm[6]=='e' && comm[7]=='s' && comm[8]=='s' && comm[9]=='\0';
            const char fmt_str[] = "Hello, world, from BPF! My COMM is %s\n";
            bpf_trace_printk(fmt_str, sizeof(fmt_str),comm) ;
            if (commcheck) {
                if (ctx->local_port == DST_PORT){
                    return SK_PASS; }
            else {
                return SK_DROP;
            }
            }
    }}
    return SK_PASS;
}
