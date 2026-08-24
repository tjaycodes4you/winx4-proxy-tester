#!/usr/bin/env python3
"""Per-TCP-connection byte accounting via eBPF kprobes (BCC).

Prints one line per closed IPv4 connection: pid, local ip:port -> remote
ip:port, bytes in/out, duration. Filter with --pid to watch one process
(e.g. a winx4-proxytest run). Modeled on BCC's tcplife.

Usage (root, system python with python3-bpfcc installed):
  python3 conn_bytes.py --pid $(pgrep -f winx4-proxytest)
"""
import argparse
import socket
import struct
import time

from bcc import BPF

PROG = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct conn_info_t {
    u64 ts;
    u64 pid;
    u16 lport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u64 bytes_out;
    u64 bytes_in;
};

BPF_HASH(starts, struct sock *, struct conn_info_t);
BPF_PERF_OUTPUT(conn_events);

static struct conn_info_t *get_info(struct sock *sk) {
    struct conn_info_t *info = starts.lookup(&sk);
    if (info)
        return info;
    struct conn_info_t zero = {};
    zero.ts = bpf_ktime_get_ns();
    zero.pid = bpf_get_current_pid_tgid() >> 32;
    zero.lport = sk->__sk_common.skc_num;
    zero.dport = bpf_ntohs(sk->__sk_common.skc_dport);
    zero.saddr = bpf_ntohl(sk->__sk_common.skc_rcv_saddr);
    zero.daddr = bpf_ntohl(sk->__sk_common.skc_daddr);
    starts.update(&sk, &zero);
    return starts.lookup(&sk);
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk || sk->__sk_common.skc_family != AF_INET)
        return 0;
    struct conn_info_t *info = get_info(sk);
    info->bytes_out += size;
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (!sk || copied <= 0 || sk->__sk_common.skc_family != AF_INET)
        return 0;
    struct conn_info_t *info = get_info(sk);
    info->bytes_in += copied;
    return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk, long timeout) {
    if (!sk || sk->__sk_common.skc_family != AF_INET)
        return 0;
    struct conn_info_t *info = starts.lookup(&sk);
    if (!info)
        return 0;
    conn_events.perf_submit(ctx, info, sizeof(*info));
    starts.delete(&sk);
    return 0;
}
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pid", type=int, help="only show connections from this pid")
    args = ap.parse_args()

    b = BPF(text=PROG)
    print("watching... (ctrl+c to stop)")

    def cb(cpu, data, size):
        e = b["conn_events"].event(data)
        if args.pid and e.pid != args.pid:
            return
        saddr = socket.inet_ntoa(struct.pack("!I", e.saddr))
        daddr = socket.inet_ntoa(struct.pack("!I", e.daddr))
        dur_ms = (time.time_ns() - e.ts) / 1e6
        print(
            f"pid={e.pid} {saddr}:{e.lport} -> {daddr}:{e.dport} "
            f"in={e.bytes_in}B out={e.bytes_out}B dur={dur_ms:.1f}ms"
        )

    b["conn_events"].open_perf_buffer(cb)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
