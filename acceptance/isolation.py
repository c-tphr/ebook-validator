"""Independent live canary. Run as an unprivileged user with python3 -m acceptance.isolation."""

import json
from pathlib import Path
import socket
import tempfile

from epub_triage.backend import Backend


def main():
    with tempfile.TemporaryDirectory() as name, socket.socket() as listener:
        private = Path(name)
        book = private / "probe.epub"
        book.write_bytes(b"read-only canary")
        marker = private / "private-marker"
        marker.write_text("visible only to supervisor")
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        addr = listener.getsockname()
        with socket.create_connection(addr, timeout=1):
            control, _ = listener.accept()
            control.close()
        backend = Backend({}, private)
        # Extend the trusted worker with observations. The production launcher builds
        # the namespace and production mount_probe performs its normal write attempt.
        import textwrap

        probe = textwrap.dedent(f"""
            import socket
            import json
            import os
            import sys
            from pathlib import Path
            from .worker import mount_probe, BOOK
            evidence = mount_probe(sys.argv[2])
            evidence['host_namespace'] = sys.argv[2]
            evidence['input_readable'] = BOOK.read_bytes() == b'read-only canary'
            evidence['host_marker_hidden'] = not Path({str(marker)!r}).exists()
            try:
                connected = socket.create_connection({addr!r}, timeout=1)
            except OSError:
                evidence['host_listener_blocked'] = True
            else:
                connected.close()
                evidence['host_listener_blocked'] = False
            print(json.dumps(evidence))
        """)
        worker = backend.worker_source / "worker.py"
        (backend.worker_source / "original_worker.py").write_bytes(worker.read_bytes())
        worker.write_text(probe.replace("from .worker import", "from .original_worker import"))
        evidence = backend.invoke("isolation", book, timeout=30)
        print(json.dumps(evidence, sort_keys=True))
        return int(
            not all(
                evidence.get(k) is True
                for k in (
                    "input_readable",
                    "host_marker_hidden",
                    "host_listener_blocked",
                    "offline",
                    "read_only",
                )
            )
        )


if __name__ == "__main__":
    raise SystemExit(main())
