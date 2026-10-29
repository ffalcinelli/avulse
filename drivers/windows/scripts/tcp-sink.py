#!/usr/bin/env python3
"""A TCP sink for the Windows capture tests' large upload (`lso_reinject`): it reads each
connection to its end, then answers with the number of bytes it read, in decimal.

Run it on the host, then pass the port to the VM, which reaches the host as 10.0.2.2:

    python3 drivers/windows/scripts/tcp-sink.py 9500 &
    vagrant winrm windows -e -c '$env:AVULSE_TCP_PEER = "10.0.2.2:9500"; C:\\avulse\\drivers\\windows\\scripts\\test.ps1'
"""

import socket
import sys
import threading


def serve(conn: socket.socket) -> None:
    with conn:
        n = 0
        while chunk := conn.recv(1 << 16):
            n += len(chunk)
        conn.sendall(str(n).encode())


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9500
    with socket.create_server(("127.0.0.1", port)) as s:
        while True:
            conn, _ = s.accept()
            threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
