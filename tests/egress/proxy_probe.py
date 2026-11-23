"""Send one CONNECT through an HTTP proxy and print the status code.

Usage: python3 proxy_probe.py PROXY_HOST PROXY_PORT TARGET_HOST:PORT
Prints the numeric status (e.g. 200, 407, 502) or "none" if the proxy did
not answer. Used by tests/egress/run.sh against the real Smokescreen image.
"""

import re
import socket
import sys


def main() -> int:
    proxy_host, proxy_port, target = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    try:
        with socket.create_connection((proxy_host, proxy_port), timeout=15) as s:
            s.settimeout(15)
            s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            data = s.recv(512).decode("latin-1", "replace")
    except OSError:
        print("none")
        return 0
    m = re.match(r"HTTP/1\.[01] (\d{3})", data)
    print(m.group(1) if m else "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
