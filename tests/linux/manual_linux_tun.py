
"""Manual Linux TUN packet capture test.

Run from the PQVPN repository root:

    sudo python3 -m tests.linux.manual_linux_tun

This test does not change system routes or DNS.
"""

from __future__ import annotations

import argparse

from modules.networking.host.linux_tun import LinuxTunAdapter
from modules.networking.host.packet_reader import inspect_ipv4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="pqvpn0")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be positive")

    if args.timeout < 0:
        parser.error("--timeout cannot be negative")

    print("[PQVPN] Opening Linux TUN...", flush=True)

    with LinuxTunAdapter(args.name) as tun:
        print(f"[PQVPN] Interface: {tun.name}", flush=True)
        print("[PQVPN] Waiting for IPv4 packets...", flush=True)

        received = 0

        while received < args.count:
            packet = tun.read_packet(timeout=args.timeout)

            if packet is None:
                print("[PQVPN] Capture timeout.", flush=True)
                break

            try:
                info = inspect_ipv4(packet)
            except (TypeError, ValueError) as exc:
                print(f"[PQVPN] Rejected: {exc}", flush=True)
                continue

            received += 1

            print(
                f"[{received}] "
                f"{info.source} -> {info.destination} "
                f"protocol={info.protocol} "
                f"bytes={info.total_length}",
                flush=True,
            )

    print("[PQVPN] Adapter closed.", flush=True)


if __name__ == "__main__":
    main()
