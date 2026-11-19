"""Repair attempts and immutable, content-addressed publication records."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import uuid

from .state import absolute_directory, file_at, snap


SCHEMA = """
CREATE TABLE IF NOT EXISTS repair_attempts (
    sequence INTEGER PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES repair_queue(operation_id),
    revision TEXT NOT NULL,
    decision TEXT NOT NULL,
    report TEXT NOT NULL,
    UNIQUE(operation_id, revision)
);
CREATE TABLE IF NOT EXISTS repair_versions (
    sequence INTEGER PRIMARY KEY REFERENCES repair_attempts(sequence),
    operation_id TEXT NOT NULL REFERENCES repair_queue(operation_id),
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    ready INTEGER NOT NULL DEFAULT 0,
    temp_name TEXT,
    temp_device INTEGER,
    temp_inode INTEGER,
    UNIQUE(operation_id, sha256)
);
"""


class PublicationCollision(RuntimeError):
    pass


class RepairState:
    def __init__(self, state, behavior):
        self.state = state
        self.behavior = behavior
        self.connection = state.connection
        self.output = state.config["repaired_output"]
        if not state.preview:
            self.connection.executescript(SCHEMA)
        self.available = self.connection is not None and self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'repair_attempts'"
        ).fetchone() is not None

    def entries(self, scanned=None):
        if self.connection is None:
            return []
        replacements = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'repair_replacements'"
        ).fetchone()
        link = "LEFT JOIN repair_replacements r ON r.operation_id = o.id" if replacements else ""
        lineage = "COALESCE(r.lineage, o.id)" if replacements else "o.id"
        where = "o.complete = 1"
        values = ()
        if scanned is not None:
            where += " AND o.target = ? AND o.sha256 = ? AND o.relative = ? AND o.root = ? AND o.root_identity = ?"
            values = (scanned["destination"], scanned["sha256"], scanned["path"],
                      str(self.state.root), self.state.root_identity)
        if replacements:
            where += f""" AND NOT EXISTS (
                SELECT 1 FROM repair_replacements successor JOIN operations after ON after.id = successor.operation_id
                WHERE successor.lineage = {lineage} AND successor.generation > COALESCE(r.generation, 0)
                AND after.complete = 1
            )"""
        return self.connection.execute(
            f"""SELECT o.*, q.repair_copy, q.source, {lineage} AS operation_id, q.sha256 AS queued_sha256
            FROM repair_queue q JOIN operations o ON o.id = q.operation_id
            {link} WHERE {where} ORDER BY o.root, o.relative, o.id""", values,
        )

    def previous(self, operation, revision):
        if self.available:
            return self.connection.execute(
                "SELECT report FROM repair_attempts WHERE operation_id = ? AND revision = ?",
                (operation, revision),
            ).fetchone()

    def latest(self, operation):
        if self.available:
            return self.connection.execute(
                """SELECT v.*, a.report FROM repair_versions v JOIN repair_attempts a USING(sequence)
                WHERE v.operation_id = ? AND v.ready = 1 ORDER BY v.sequence DESC LIMIT 1""",
                (operation,),
            ).fetchone()

    def check_path(self, row):
        sha256 = row["sha256"]
        if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
            raise RuntimeError("Invalid repair object hash")
        if Path(row["path"]) != self.output / (sha256 + ".epub"):
            raise RuntimeError("Repaired output differs from recorded configuration")

    @contextmanager
    def latest_bytes(self, row):
        self.check_path(row)
        with absolute_directory(self.output, preserve_atime=self.state.preview) as parent:
            with file_at(parent, Path(row["path"]).name, self.state.preview) as source:
                yield source

    def record(self, operation, revision, report):
        self.connection.execute(
            "INSERT INTO repair_attempts (operation_id, revision, decision, report) VALUES (?, ?, ?, ?)",
            (operation, revision, report["decision"], json.dumps(report)),
        )

    def remember(self, operation, revision, report):
        with self.connection:
            self.record(operation, revision, report)

    def recover(self, operation, review_revision=None, inspect=None):
        behavior = self.behavior
        if self.state.preview or not self.available:
            return
        rows = self.connection.execute(
            """SELECT v.*, a.revision, a.report FROM repair_versions v JOIN repair_attempts a USING(sequence)
            WHERE v.operation_id = ?""", (operation,),
        )
        for row in rows.fetchall():
            if row["temp_name"] is None:
                continue
            self.check_path(row)
            with absolute_directory(self.output) as parent:
                if not row["ready"]:
                    if json.loads(row["report"]).get("review_id") and row["revision"] != review_revision:
                        continue
                    if behavior is not None:
                        report = json.loads(row["report"])
                        cached = report.get("behavior", {})
                        if (cached.get("configuration_id") != behavior.identifier
                                or cached.get("effective") != "release" or cached.get("sha256") != row["sha256"]):
                            pending = behavior.private / "pending-publication.epub"
                            try:
                                try:
                                    stream = file_at(parent, row["temp_name"], preserve_atime=True)
                                    with stream as source:
                                        actual, _, oversized = snap(source, pending, behavior.limits["max_book_bytes"])
                                except FileNotFoundError:
                                    with file_at(parent, Path(row["path"]).name, preserve_atime=True) as source:
                                        actual, _, oversized = snap(source, pending, behavior.limits["max_book_bytes"])
                                if oversized or actual != row["sha256"]:
                                    raise RuntimeError("Publication journal bytes differ from recorded SHA-256")
                                if inspect is None:
                                    raise RuntimeError("Publication recovery requires current static inspection")
                                inspect(pending)
                                gate = behavior.assess(pending, actual)
                            finally:
                                pending.unlink(missing_ok=True)
                            if gate["effective"] != "release":
                                return gate
                            report["behavior"] = gate
                            with self.connection:
                                self.connection.execute("UPDATE repair_attempts SET report=? WHERE sequence=?",
                                                        (json.dumps(report), row["sequence"]))
                    try:
                        self.finish(parent, row)
                    except PublicationCollision:
                        self.discard(parent, row)
                        continue
                self.clean(parent, row)

    def discard(self, parent, row):
        self.clean(parent, row)
        with self.connection:
            self.connection.execute("DELETE FROM repair_versions WHERE sequence = ?", (row["sequence"],))
            self.connection.execute("DELETE FROM repair_attempts WHERE sequence = ?", (row["sequence"],))

    def clean(self, parent, row):
        self.state.clean_temp(row, parent)
        with self.connection:
            self.connection.execute(
                "UPDATE repair_versions SET temp_name = NULL, temp_device = NULL, temp_inode = NULL WHERE sequence = ?",
                (row["sequence"],),
            )

    def verify(self, parent, name, expected):
        try:
            return self.state.verify_target(parent, name, expected, preserve_atime=True)
        except FileNotFoundError:
            raise
        except (OSError, RuntimeError, ValueError) as error:
            raise PublicationCollision(f"Repaired output collision at {name}: {error}") from error

    def finish(self, parent, row):
        final = Path(row["path"]).name
        expected = row["sha256"]
        try:
            self.verify(parent, final, expected)
        except FileNotFoundError:
            verified = self.state.verify_target(parent, row["temp_name"], expected, preserve_atime=True)
            if not self.state.owns_temp(row, verified):
                raise RuntimeError("Repair publication temporary object identity changed")
            try:
                os.link(row["temp_name"], final, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                self.verify(parent, final, expected)
        os.fsync(parent)
        with self.connection:
            self.connection.execute("UPDATE repair_versions SET ready = 1 WHERE sequence = ?", (row["sequence"],))

    def publish(self, operation, revision, report, candidate):
        sha256 = report["output_sha256"]
        gate = report.get("behavior", {})
        if (gate.get("sha256") != sha256 or gate.get("effective") != "release"
                or not self.behavior.identifier or gate.get("configuration_id") != self.behavior.identifier):
            raise RuntimeError("Publication requires behavioral clearance for the exact candidate and current configuration")
        destination = self.output / (sha256 + ".epub")
        report["destination"] = str(destination)
        report["latest"] = {"sha256": sha256, "path": str(destination)}
        with absolute_directory(self.output, create=True) as parent:
            try:
                self.verify(parent, destination.name, sha256)
            except FileNotFoundError:
                pass
            # Named staging, recorded only after the complete file is durable.
            # An interruption before journaling can leave an unreferenced .part.
            temp = ".epub-triage-" + uuid.uuid4().hex + ".part"
            descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
            row = None
            try:
                with os.fdopen(descriptor, "wb") as target, candidate.open("rb") as source:
                    shutil.copyfileobj(source, target, 1024 * 1024)
                    target.flush()
                    os.fchmod(target.fileno(), 0o400)
                    os.fsync(target.fileno())
                    info = os.fstat(target.fileno())
                self.state.verify_target(parent, temp, sha256, preserve_atime=True)
                os.fsync(parent)
                with self.connection:
                    self.record(operation, revision, report)
                    sequence = self.connection.execute("SELECT last_insert_rowid()").fetchone()[0]
                    self.connection.execute(
                        """INSERT INTO repair_versions
                        (sequence, operation_id, sha256, path, temp_name, temp_device, temp_inode)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (sequence, operation, sha256, str(destination), temp, info.st_dev, info.st_ino),
                    )
                row = self.connection.execute("SELECT * FROM repair_versions WHERE sequence = ?", (sequence,)).fetchone()
                try:
                    self.finish(parent, row)
                except PublicationCollision:
                    self.discard(parent, row)
                    raise
                self.clean(parent, row)
            finally:
                if row is None:
                    os.unlink(temp, dir_fd=parent)
                    os.fsync(parent)
