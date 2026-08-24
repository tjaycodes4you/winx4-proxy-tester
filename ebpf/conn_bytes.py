#!/usr/bin/env python3
"""Per-TCP-connection byte accounting via eBPF kprobes (BCC).

Prints one line per closed IPv4 connection: pid, local ip:port -> remote
ip:port, bytes in/out, duration. Filter with --pid to watch one process
(e.g. a winx4-proxytest run). Modeled on BCC's tcplife.

Usage (root, system python with python3-bpfcc installed):
  python3 conn_bytes.py --pid $(pgrep -f winx4-proxytest)
"""
import argparse
import json
import socket
import struct

from bcc import BPF

PROG = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>

#define TCP_CLOSE 7

struct conn_info_t {
    u64 ts;
    u64 pid;
    u16 lport;
    u16 dport;
    u32 saddr;
    u32 daddr;
    u64 bytes_out;
    u64 bytes_in;
    u64 dur_ns;
};

BPF_HASH(starts, u64, struct conn_info_t);
BPF_PERF_OUTPUT(conn_events);

int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u64 sk = PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    struct conn_info_t zero = {};
    zero.ts = bpf_ktime_get_ns();
    zero.pid = bpf_get_current_pid_tgid() >> 32;
    struct conn_info_t *info = starts.lookup_or_try_init(&sk, &zero);
    if (!info)
        return 0;
    info->bytes_out += size;
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx) {
    u64 sk = PT_REGS_PARM1(ctx);
    int copied = (int)PT_REGS_PARM2(ctx);
    if (!sk || copied <= 0)
        return 0;
    struct conn_info_t zero = {};
    zero.ts = bpf_ktime_get_ns();
    zero.pid = bpf_get_current_pid_tgid() >> 32;
    struct conn_info_t *info = starts.lookup_or_try_init(&sk, &zero);
    if (!info)
        return 0;
    info->bytes_in += copied;
    return 0;
}

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    u64 sk = (u64)args->skaddr;
    if (args->family != AF_INET)
        return 0;
    if (args->newstate == BPF_TCP_SYN_SENT) {
        struct conn_info_t zero = {};
        zero.ts = bpf_ktime_get_ns();
        zero.pid = bpf_get_current_pid_tgid() >> 32;
        starts.lookup_or_try_init(&sk, &zero);
        return 0;
    }
    if (args->newstate != TCP_CLOSE)
        return 0;
    struct conn_info_t *info = starts.lookup(&sk);
    if (!info)
        return 0;
    info->lport = args->sport;
    info->dport = args->dport;
    u32 saddr = 0;
    u32 daddr = 0;
    bpf_probe_read_kernel(&saddr, 4, args->saddr);
    bpf_probe_read_kernel(&daddr, 4, args->daddr);
    info->saddr = bpf_ntohl(saddr);
    info->daddr = bpf_ntohl(daddr);
    info->dur_ns = bpf_ktime_get_ns() - info->ts;
    conn_events.perf_submit(args, info, sizeof(*info));
    starts.delete(&sk);
    return 0;
}
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pid", type=int, help="only show connections from this pid")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON lines")
    args = ap.parse_args()

    b = BPF(text=PROG)
    print("watching... (ctrl+c to stop)")

    def cb(cpu, data, size):
        e = b["conn_events"].event(data)
        if args.pid and e.pid != args.pid:
            return
        saddr = socket.inet_ntoa(struct.pack("!I", e.saddr))
        daddr = socket.inet_ntoa(struct.pack("!I", e.daddr))
        if args.json:
            print(json.dumps({
                "pid": int(e.pid),
                "saddr": saddr,
                "lport": int(e.lport),
                "daddr": daddr,
                "dport": int(e.dport),
                "bytes_in": int(e.bytes_in),
                "bytes_out": int(e.bytes_out),
                "start": int(e.ts),
                "dur_ms": round(float(e.dur_ns) / 1e6, 3),
            }), flush=True)
        else:
            print(
                f"pid={e.pid} {saddr}:{e.lport} -> {daddr}:{e.dport} "
                f"in={e.bytes_in}B out={e.bytes_out}B dur={e.dur_ns / 1e6:.1f}ms"
            )

    b["conn_events"].open_perf_buffer(cb)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
