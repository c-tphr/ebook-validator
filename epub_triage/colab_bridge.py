"""Inside the reviewer namespace, forward the private loopback listener to one Unix relay."""

import os
import select
import socket
import subprocess
import sys
import threading


def handle(connection, endpoint):
    try:
        with connection, socket.socket(socket.AF_UNIX) as relay:
            relay.settimeout(100)
            relay.connect(endpoint)
            remaining = 4 * 1024 * 1024
            while remaining:
                available, _, _ = select.select((connection, relay), (), (), 100)
                if not available:
                    break
                for stream in available:
                    block = stream.recv(min(65536, remaining))
                    if not block:
                        return
                    remaining -= len(block)
                    other = relay if stream is connection else connection
                    other.sendall(block)
    except OSError:
        return


def main():
    endpoint = sys.argv[1]
    # If the outer network isolation is missing, the only interface check
    # catches it before launching a credential-bearing provider request.
    if (os.readlink("/proc/self/ns/net") == sys.argv[2]
            or {name for _, name in socket.if_nameindex()} != {"lo"}):
        raise RuntimeError("Reviewer relay namespace was not isolated.")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        args = [part.replace("{PORT}", str(port)) for part in sys.argv[3:]]
        with subprocess.Popen(args) as process:
            try:
                remaining = 6
                while process.poll() is None and remaining:
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    remaining -= 1
                    threading.Thread(target=handle, args=(connection, endpoint), daemon=True).start()
                if not remaining and process.poll() is None:
                    process.terminate()
                return process.wait()
            except BaseException:
                if process.poll() is None:
                    process.kill()
                raise


if __name__ == "__main__":
    raise SystemExit(main())
