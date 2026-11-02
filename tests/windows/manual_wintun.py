"""Manual Windows Wintun packet capture test."""

import argparse

from modules.networking.host.wintun_adapter import WintunAdapter
from modules.networking.host.packet_reader import inspect_ipv4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="PQVPN")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be positive")

    print("[PQVPN] Opening Wintun adapter...", flush=True)

    with WintunAdapter(name=args.name) as tun:
        print(f"[PQVPN] Adapter created: {tun.name}", flush=True)
        print("[PQVPN] Waiting for IPv4 packets...", flush=True)

        received = 0

        while received < args.count:
            packet = tun.read_packet(timeout=args.timeout)

            if packet is None:
                print("[PQVPN] Capture timeout.")
                break

            try:
                info = inspect_ipv4(packet)
            except (ValueError, TypeError) as exc:
                print(f"[PQVPN] Rejected: {exc}")
                continue

            received += 1

            print(
                f"[{received}] "
                f"{info.source} -> {info.destination} "
                f"protocol={info.protocol} "
                f"bytes={info.total_length}",
                flush=True,
            )

    print("[PQVPN] Adapter closed.")


if __name__ == "__main__":
    main()
