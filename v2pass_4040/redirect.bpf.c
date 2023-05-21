// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define AF_INET		2
char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} redir_map SEC(".maps");

static const __u16 DST_PORT = 4000; /* Host byte order */
static const __u32 KEY_SERVER_A = 0;

/* Redirect packets destined for DST_IP4 address to socket at redir_map[0]. */
SEC("sk_lookup")
int redir_ip4(struct bpf_sk_lookup *ctx)
{
    struct bpf_sock *sk;
    int err;

    if (ctx->family != AF_INET)
        return SK_PASS;
    if (ctx->local_port != DST_PORT)
        return SK_PASS;
            s = (struct task_struct*)bpf_get_current_task();
            err = bpf_core_read(&comm, sizeof(comm), &s->comm);
            if (!err) {
            bool commcheck = comm[0]=='m' && comm[1]=='y' && comm[2]=='p' && comm[3]=='r' && comm[4]=='o' && comm[5]=='c' && comm[6]=='e' && comm[7]=='s' && comm[8]=='s' && comm[9]=='\0';
            const char fmt_str[] = "Hello, world, from BPF! My COMM is %s\n";
            bpf_trace_printk(fmt_str, sizeof(fmt_str),comm) ;
            if (commcheck) {
 
    sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if (!sk)
        return SK_PASS;

    err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return err ? SK_DROP : SK_PASS;
}
