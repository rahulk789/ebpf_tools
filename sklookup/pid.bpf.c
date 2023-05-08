// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";
/*
struct bpf_map_def {
      unsigned int type;
      unsigned int key_size;
      unsigned int value_size;
      unsigned int max_entries;
      unsigned int map_flags;
};
struct bpf_map_def SEC("maps") all_ports = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 3,
}
*/
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} redir_map SEC(".maps");

static const __u16 DST_PORT = 4000; /* Host byte order */
static const __u32 DST_IP4 = IP4(127, 0, 0, 1);
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
    if (ctx->local_ip4 != DST_IP4)
        return SK_PASS;

    sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if (!sk)
        return SK_PASS;

    err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return err ? SK_DROP : SK_PASS;
}
