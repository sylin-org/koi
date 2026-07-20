#!/usr/bin/env python3
"""Run-owned Unix stream relay for interrupting one Koi Docker connection."""

import argparse
import os
import selectors
import signal
import socket
import stat
import threading


def relay(client: socket.socket, upstream_path: str) -> None:
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(upstream_path)
        selector = selectors.DefaultSelector()
        selector.register(client, selectors.EVENT_READ, upstream)
        selector.register(upstream, selectors.EVENT_READ, client)
        while True:
            ready = selector.select()
            for key, _ in ready:
                data = key.fileobj.recv(64 * 1024)
                if not data:
                    return
                key.data.sendall(data)
    finally:
        client.close()
        upstream.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--upstream", required=True)
    args = parser.parse_args()

    if os.path.lexists(args.listen):
        mode = os.lstat(args.listen).st_mode
        if not stat.S_ISSOCK(mode):
            raise RuntimeError(f"refusing to replace non-socket path: {args.listen}")
        os.unlink(args.listen)

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(args.listen)
    os.chmod(args.listen, 0o600)
    listener.listen(32)

    def stop(_signum: int, _frame: object) -> None:
        listener.close()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                break
            threading.Thread(
                target=relay,
                args=(client, args.upstream),
                daemon=True,
            ).start()
    finally:
        listener.close()
        if os.path.lexists(args.listen) and stat.S_ISSOCK(os.lstat(args.listen).st_mode):
            os.unlink(args.listen)


if __name__ == "__main__":
    main()
