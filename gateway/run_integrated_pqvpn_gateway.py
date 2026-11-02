
"""PQVPN integrated multi-client TCP + UDP/TUN gateway.

Experimental FYP lab runner.

- Identity-bound authenticated TCP handshake
- Shared multi-client session registry
- Shared encrypted UDP engine
- Authenticated IPv4 TUN forwarding
- Client-scoped session isolation

Does not configure host interfaces, routes, NAT, or firewall.
Run only inside the preconfigured pqvpn-gw namespace.
"""

import argparse
import select
import signal
import socket
import threading

from gateway.client_config import load_client_config
from gateway.handshake_server import load_identity
from gateway.multi_client_tcp_server import MultiClientTCPServer
from gateway.multi_client_unified_dispatch import process_one
from gateway.multi_client_ipv4_udp import MultiClientIPv4UDPError

from modules.networking.host.linux_tun import LinuxTunAdapter
from modules.networking.transport.udp_transport import UDPTransport
from modules.networking.transport.packet_framing import TYPE_DATA


running = True


def stop(signum, frame):
    global running
    running = False


def tcp_listener(host, port, server):
    """Accept authenticated client handshakes.

    The TCP server shares the same UDP engine and registry
    used by the live gateway data plane.
    """
    global running

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as listener:

        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )

        listener.bind((host, port))
        listener.listen(16)
        listener.settimeout(0.5)

        print(
            f"[READY] TCP {host}:{port}",
            flush=True,
        )

        def worker(connection):
            with connection:
                try:
                    client_id, session_id = (
                        server.handle_connection(connection)
                    )

                    print(
                        "[AUTHENTICATED]",
                        client_id,
                        session_id.hex(),
                        flush=True,
                    )

                except Exception as exc:
                    print(
                        "[HANDSHAKE REJECTED]",
                        type(exc).__name__,
                        flush=True,
                    )

        while running:
            try:
                connection, _address = listener.accept()

            except socket.timeout:
                continue

            except OSError:
                if not running:
                    break
                raise

            threading.Thread(
                target=worker,
                args=(connection,),
                daemon=True,
            ).start()


def parse_assignments(items):
    assignments = {}

    for item in items:
        if "=" not in item:
            raise ValueError(
                "Assignment must be CLIENT_ID=IPv4"
            )

        client_id, tunnel_ip = item.split("=", 1)

        if not client_id or not tunnel_ip:
            raise ValueError(
                "Invalid client assignment"
            )

        if client_id in assignments:
            raise ValueError(
                "Duplicate client assignment"
            )

        assignments[client_id] = tunnel_ip

    return assignments


def main():
    global running

    parser = argparse.ArgumentParser(
        description=(
            "PQVPN integrated experimental "
            "multi-client gateway"
        )
    )

    parser.add_argument(
        "--host",
        default="172.30.77.1",
    )

    parser.add_argument(
        "--tcp-port",
        type=int,
        default=51831,
    )

    parser.add_argument(
        "--udp-port",
        type=int,
        default=51821,
    )

    parser.add_argument(
        "--tun",
        default="pqgw0",
    )

    parser.add_argument(
        "--credentials",
        required=True,
    )

    parser.add_argument(
        "--assign",
        action="append",
        required=True,
        metavar="CLIENT_ID=IPv4",
    )

    args = parser.parse_args()

    if not 1 <= args.tcp_port <= 65535:
        parser.error("Invalid TCP port")

    if not 1 <= args.udp_port <= 65535:
        parser.error("Invalid UDP port")

    assignments = parse_assignments(args.assign)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # One TCP server owns one shared registry and UDP engine.
    server = MultiClientTCPServer(
        load_identity(),
        load_client_config(args.credentials),
        assignments,
    )

    engine = server.udp_engine

    listener_thread = None

    try:
        # Initialize data-plane resources before accepting
        # authenticated TCP sessions.
        with (
            LinuxTunAdapter(args.tun) as tun,
            UDPTransport(
                host=args.host,
                port=args.udp_port,
                timeout=1.0,
            ) as udp,
        ):
            listener_thread = threading.Thread(
                target=tcp_listener,
                args=(
                    args.host,
                    args.tcp_port,
                    server,
                ),
                daemon=True,
            )

            listener_thread.start()

            print(
                "[READY] UDP",
                udp.address,
                "TUN",
                tun.name,
                flush=True,
            )

            print(
                "[READY] Fresh TCP sessions share "
                "live UDP/TUN state",
                flush=True,
            )

            while running:
                readable, _, _ = select.select(
                    [udp.socket, tun._fd],
                    [],
                    [],
                    0.5,
                )

                if udp.socket in readable:
                    try:
                        result = process_one(
                            udp,
                            engine,
                            tun,
                        )

                        if result == "ipv4":
                            print(
                                "[UDP -> TUN] Authenticated IPv4",
                                flush=True,
                            )

                        elif result == "ping":
                            print(
                                "[PING] Authenticated",
                                flush=True,
                            )

                        else:
                            print(
                                "[DROP] UDP rejected",
                                flush=True,
                            )

                    except (
                        socket.timeout,
                        OSError,
                    ) as exc:
                        print(
                            "[UDP ERROR]",
                            type(exc).__name__,
                            flush=True,
                        )

                if tun._fd in readable:
                    packet = tun.read_packet(timeout=0)

                    if packet is None:
                        continue

                    try:
                        peer, encrypted = (
                            engine.encrypt_ipv4_reply(packet)
                        )

                        udp.send(
                            peer,
                            TYPE_DATA,
                            encrypted,
                        )

                        print(
                            "[TUN -> UDP] Reply",
                            flush=True,
                        )

                    except (
                        MultiClientIPv4UDPError,
                        ValueError,
                        TypeError,
                        OSError,
                    ) as exc:
                        print(
                            "[DROP] Outbound:",
                            type(exc).__name__,
                            flush=True,
                        )

                # Periodic cleanup of cached transports
                # whose registry sessions have expired.
                engine.prune_expired_transports()

    finally:
        running = False

        if listener_thread is not None:
            listener_thread.join(timeout=2.0)

        print(
            "[STOP] Integrated gateway closed",
            flush=True,
        )


if __name__ == "__main__":
    main()
