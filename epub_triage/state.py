"""Descriptor-relative file handling and durable, no-replace disposition."""

from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import uuid


DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@contextmanager
def directory(start, parts, create=False, preserve_atime=False):
    flags = DIR | (os.O_NOATIME if preserve_atime else 0)
    descriptor = os.dup(start)
    try:
        for index, part in enumerate(parts):
            if part in {"", ".", ".."} or "/" in part:
                raise ValueError("Unsafe directory component")
            child_flags = flags if index == len(parts) - 1 else DIR
            try:
                child = os.open(part, child_flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                os.fsync(descriptor)
                child = os.open(part, child_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def absolute_directory(path, create=False, preserve_atime=False):
    root = os.open("/", DIR)
    try:
        with directory(root, path.parts[1:], create, preserve_atime) as descriptor:
            yield descriptor
    finally:
        os.close(root)


@contextmanager
def file_at(parent, name, preserve_atime=False):
    flags = FILE | (os.O_NOATIME if preserve_atime else 0)
    descriptor = os.open(name, flags, dir_fd=parent)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"Expected a regular file at {name}")
        yield stream


def digest(stream):
    return hashlib.file_digest(stream, "sha256").hexdigest()


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def check_source(stream, parent, name, expected_hash, expected_identity=None):
    before = identity(os.fstat(stream.fileno()))
    if expected_identity is not None and before != expected_identity:
        raise RuntimeError("Source identity changed after snapshot")
    stream.seek(0)
    if digest(stream) != expected_hash:
        raise RuntimeError("Source bytes changed after snapshot")
    if (identity(os.fstat(stream.fileno())) != before or
            identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before):
        raise RuntimeError("Source pathname changed during disposition")


class SnapshotChanged(RuntimeError):
    pass


def snap(source, path, limit):
    first = identity(os.fstat(source.fileno()))
    hasher = hashlib.sha256()
    length = 0
    oversized = first[2] > limit
    with path.open("xb") as output:
        while block := source.read(1024 * 1024):
            hasher.update(block)
            length += len(block)
            if length <= limit and not oversized:
                output.write(block)
            else:
                oversized = True
    if first != identity(os.fstat(source.fileno())) or length != first[2]:
        raise SnapshotChanged("Source changed while taking snapshot")
    return hasher.hexdigest(), first, oversized


SCHEMA = """
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    root_identity TEXT NOT NULL,
    relative TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    target TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    findings TEXT NOT NULL,
    complete INTEGER NOT NULL DEFAULT 0,
    temp_name TEXT,
    temp_device INTEGER,
    temp_inode INTEGER
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS source_heads (
    root TEXT NOT NULL,
    root_identity TEXT NOT NULL,
    relative TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    action TEXT NOT NULL,
    PRIMARY KEY(root, root_identity, relative)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS repair_queue (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id),
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    findings TEXT NOT NULL,
    status TEXT NOT NULL,
    repair_copy TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS repair_replacements (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id),
    lineage TEXT NOT NULL REFERENCES operations(id),
    generation INTEGER NOT NULL,
    UNIQUE(lineage, generation)
) WITHOUT ROWID;
"""


class State:
    def __init__(self, config, root, root_fd, preview, private=None):
        self.config, self.root, self.root_fd, self.preview = config, root, root_fd, preview
        self.private = private
        self.connection = None
        self.root_identity = None
        if root_fd is not None:
            metadata = os.fstat(root_fd)
            self.root_identity = f"{metadata.st_dev}:{metadata.st_ino}"

    def __enter__(self):
        queue = self.config["queue"]
        if self.preview and not queue.exists():
            return self
        try:
            with absolute_directory(queue.parent, create=not self.preview) as parent:
                try:
                    metadata = os.stat(queue.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    metadata = None
                if metadata and not stat.S_ISREG(metadata.st_mode):
                    raise RuntimeError("Queue must be a regular file")
                if self.preview:
                    if queue.with_name(queue.name + "-journal").exists():
                        raise RuntimeError("Queue has an interrupted SQLite transaction; normal recovery is required")
                    try:
                        wal = os.stat(queue.name + "-wal", dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        if wal.st_size or not stat.S_ISREG(wal.st_mode):
                            raise RuntimeError("Queue has a SQLite WAL; normal recovery is required")
                    preview_copy = self.private / "queue-preview.sqlite"
                    with file_at(parent, queue.name, preserve_atime=True) as source:
                        with preview_copy.open("xb") as target:
                            shutil.copyfileobj(source, target, 1024 * 1024)
                    self.connection = sqlite3.connect(preview_copy.as_uri() + "?mode=ro&immutable=1", uri=True)
                else:
                    if metadata is None:
                        descriptor = os.open(queue.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                             0o600, dir_fd=parent)
                        os.close(descriptor)
                    self.connection = sqlite3.connect(queue)
                    self.connection.execute("PRAGMA journal_mode=DELETE")
                    self.connection.execute("PRAGMA synchronous=EXTRA")
                    self.connection.execute("PRAGMA foreign_keys=ON")
                    self.connection.executescript(SCHEMA)
                    os.fsync(parent)
            self.connection.row_factory = sqlite3.Row
            return self
        except BaseException:
            self.__exit__()
            raise

    def __exit__(self, *_):
        if self.connection:
            self.connection.close()

    def get(self, key):
        if self.connection is None:
            return None
        return self.connection.execute("SELECT * FROM operations WHERE id = ?", (key,)).fetchone()

    def record_head(self, relative, sha256, action):
        self.connection.execute(
            """INSERT INTO source_heads VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(root, root_identity, relative) DO UPDATE
            SET sha256 = excluded.sha256, action = excluded.action""",
            (str(self.root), self.root_identity, relative, sha256, action),
        )

    def remember_head(self, record):
        if not self.preview:
            with self.connection:
                self.record_head(record["path"], record["sha256"], record["action"])

    def choose(self, dest_root, relative, key):
        relative = Path(relative)
        parent = dest_root / relative.parent
        for suffix in range(1000):
            if suffix == 0:
                candidate = relative.name
            else:
                identifier = f".{key[:12]}" + (f".{suffix}" if suffix > 1 else "")
                stem = relative.stem
                while len(os.fsencode(stem + identifier + relative.suffix)) > 255:
                    stem = stem[:-1]
                candidate = stem + identifier + relative.suffix
            target = parent / candidate
            try:
                with absolute_directory(parent) as folder:
                    os.stat(candidate, dir_fd=folder, follow_symlinks=False)
            except FileNotFoundError:
                if self.connection is None or self.connection.execute(
                    "SELECT 1 FROM operations WHERE target = ?", (str(target),)
                ).fetchone() is None:
                    return target
        raise RuntimeError("No free destination name")

    def apply(self, record, snapshot, expected_identity):
        scope = f"{self.root}:{self.root_identity}"
        key = hashlib.sha256(json.dumps([scope, record["path"], record["sha256"],
                                        record["action"], 1]).encode()).hexdigest()
        previous = self.get(key)
        original_key = key
        iteration = 0
        if previous and record["action"] == "stage_repair" and self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'repair_replacements'"
        ).fetchone():
            successor = self.connection.execute(
                """SELECT o.*, r.generation FROM repair_replacements r JOIN operations o ON o.id = r.operation_id
                WHERE r.lineage = ? ORDER BY r.generation DESC LIMIT 1""",
                (original_key,),
            ).fetchone()
            if successor:
                previous, key, iteration = successor, successor["id"], successor["generation"]
        if previous and previous["complete"] and record["action"] == "stage_repair":
            self.validate_target(previous)
            destination = Path(previous["target"])
            try:
                with absolute_directory(destination.parent) as parent:
                    self.verify_target(parent, destination.name, record["sha256"], preserve_atime=True)
            except (OSError, RuntimeError, ValueError) as error:
                if isinstance(error, OSError) and error.errno not in {errno.ENOENT, errno.ELOOP, errno.ENOTDIR}:
                    raise
                iteration += 1
                key = hashlib.sha256(f"{original_key}:{iteration}".encode()).hexdigest()
                previous = None
        if previous:
            destination = Path(previous["target"])
            self.validate_target(previous)
        else:
            output = self.config["quarantine" if record["action"] == "quarantine" else "repair"]
            destination = self.choose(output, record["path"], key)
        record["destination"] = str(destination)
        if self.preview:
            if previous:
                with absolute_directory(destination.parent) as parent:
                    self.verify_target(parent, destination.name, record["sha256"], preserve_atime=True)
            return
        if not previous:
            findings = json.dumps({key: record[key] for key in ("security", "quality", "behavior") if key in record},
                                  ensure_ascii=True)
            with self.connection:
                self.connection.execute("INSERT INTO operations (id,root,root_identity,relative,sha256,target,action,status,findings) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                        (key, str(self.root), self.root_identity, record["path"], record["sha256"],
                                         str(destination), record["action"], record["status"], findings))
                if iteration:
                    self.connection.execute("INSERT INTO repair_replacements VALUES (?, ?, ?)",
                                            (key, original_key, iteration))
            previous = self.get(key)
        self.finish(previous, snapshot, expected_identity)

    def validate_target(self, row, check_root=True):
        output = self.config["quarantine" if row["action"] == "quarantine" else "repair"]
        relative = Path(row["relative"])
        target = Path(row["target"])
        if ((check_root and row["root_identity"] != self.root_identity) or row["action"] not in {"quarantine", "stage_repair"} or relative.is_absolute()
                or ".." in relative.parts or target.parent != output / relative.parent
                or len(row["id"]) != 64 or any(ch not in "0123456789abcdef" for ch in row["id"])):
            raise RuntimeError("Pending intent is incompatible with current configuration")

    def pending(self, selected):
        if self.connection is None:
            return {}
        rows = self.connection.execute(
            "SELECT * FROM operations WHERE root = ? AND complete = 0 ORDER BY id", (str(self.root),)
        )
        pending = {}
        for row in rows:
            relative = row["relative"]
            if selected(relative):
                self.validate_target(row)
                if relative in pending:
                    raise RuntimeError("Multiple pending operations claim the same source")
                pending[relative] = row
        return pending

    def pending_behavior(self, row, behavior, inspect):
        self.validate_target(row)
        source = Path(row["relative"])
        private = self.private / "pending-behavior.epub"
        try:
            with directory(self.root_fd, source.parts[:-1], preserve_atime=True) as parent:
                with file_at(parent, source.name, preserve_atime=True) as stream:
                    actual, identity, oversized = snap(stream, private, behavior.limits["max_book_bytes"])
            if oversized or actual != row["sha256"]:
                raise RuntimeError("Pending repair bytes differ from the journal")
            static = inspect(private)
            return static, (behavior.assess(private, actual) if not static["security"]["findings"] else None), identity
        except BaseException:
            private.unlink(missing_ok=True)
            raise

    def discard_pending_repair(self, row):
        target = Path(row["target"])
        try:
            with absolute_directory(target.parent) as parent:
                try:
                    info = self.verify_target(parent, target.name, row["sha256"], preserve_atime=True)
                except FileNotFoundError:
                    pass
                else:
                    if not self.owns_temp(row, info):
                        raise RuntimeError("Pending repair destination appeared independently")
                    os.unlink(target.name, dir_fd=parent)
                    os.fsync(parent)
                self.clean_temp(row, parent)
        except FileNotFoundError:
            pass
        with self.connection:
            self.connection.execute("DELETE FROM repair_replacements WHERE operation_id=?", (row["id"],))
            self.connection.execute("DELETE FROM operations WHERE id=? AND complete=0", (row["id"],))

    def preview_pending(self, row):
        relative = Path(row["relative"])
        with directory(self.root_fd, relative.parts[:-1]) as parent:
            try:
                with file_at(parent, relative.name, preserve_atime=True) as source:
                    check_source(source, parent, relative.name, row["sha256"])
            except FileNotFoundError:
                if row["action"] != "quarantine":
                    raise
                source_present = False
            else:
                source_present = True
        destination = Path(row["target"])
        try:
            with absolute_directory(destination.parent) as output:
                info = self.verify_target(output, destination.name, row["sha256"], preserve_atime=True)
        except FileNotFoundError:
            if not source_present:
                raise
        else:
            if not self.owns_temp(row, info):
                raise RuntimeError("Pending destination appeared independently of this operation")

    def finish(self, row, snapshot=None, expected_identity=None):
        self.validate_target(row)
        relative = Path(row["relative"])
        destination = Path(row["target"])
        with directory(self.root_fd, relative.parts[:-1]) as source_parent:
            try:
                with file_at(source_parent, relative.name) as source:
                    check_source(source, source_parent, relative.name, row["sha256"], expected_identity)
            except FileNotFoundError:
                if row["action"] != "quarantine" or snapshot is not None:
                    raise
                source_present = False
            else:
                source_present = True
            with absolute_directory(destination.parent, create=source_present) as target_parent:
                if row["complete"]:
                    self.verify_target(target_parent, destination.name, row["sha256"])
                else:
                    self.publish(row, source_parent, relative.name, source_present, target_parent,
                                 destination.name, snapshot)
                if row["action"] == "quarantine" and source_present:
                    with file_at(source_parent, relative.name) as source:
                        check_source(source, source_parent, relative.name, row["sha256"], expected_identity)
                    os.unlink(relative.name, dir_fd=source_parent)
                if row["action"] == "quarantine":
                    os.fsync(source_parent)
                if not row["complete"]:
                    self.commit(row, relative, destination)
                self.clean_temp(self.get(row["id"]), target_parent)

    @staticmethod
    def owns_temp(row, info):
        return (row["temp_device"], row["temp_inode"]) == (info.st_dev, info.st_ino)

    def clean_temp(self, row, parent):
        name = row["temp_name"]
        if not name or not name.startswith(".epub-triage-") or "/" in name:
            return
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if self.owns_temp(row, info):
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)

    @staticmethod
    def verify_target(parent, name, expected, preserve_atime=False):
        with file_at(parent, name, preserve_atime) as stream:
            if digest(stream) != expected:
                raise RuntimeError("Destination hash differs from recorded bytes")
            return os.fstat(stream.fileno())

    def publish(self, row, source_parent, source_name, source_present, parent, name, snapshot):
        try:
            final_stat = self.verify_target(parent, name, row["sha256"])
        except FileNotFoundError:
            if not source_present:
                raise RuntimeError("Neither source nor published destination is available")
        else:
            if not self.owns_temp(row, final_stat):
                raise RuntimeError("Destination appeared independently of this operation")
            os.fsync(parent)
            return

        self.clean_temp(row, parent)
        for _ in range(10):
            temp = f".epub-triage-{uuid.uuid4().hex}.part"
            try:
                descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=parent)
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError("Could not reserve a private publication path")
        with os.fdopen(descriptor, "wb") as target:
            info = os.fstat(target.fileno())
            with self.connection:
                self.connection.execute(
                    "UPDATE operations SET temp_name = ?, temp_device = ?, temp_inode = ? WHERE id = ?",
                    (temp, info.st_dev, info.st_ino, row["id"]),
                )
            if snapshot is None or snapshot.stat().st_size != os.stat(
                source_name, dir_fd=source_parent, follow_symlinks=False
            ).st_size:
                with file_at(source_parent, source_name) as source:
                    shutil.copyfileobj(source, target, 1024 * 1024)
            else:
                with snapshot.open("rb") as source:
                    shutil.copyfileobj(source, target, 1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        self.verify_target(parent, temp, row["sha256"])
        os.link(temp, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)

    def commit(self, row, relative, destination):
        with self.connection:
            if row["action"] == "stage_repair":
                self.connection.execute("INSERT INTO repair_queue VALUES (?, ?, ?, ?, ?, ?)",
                                        (row["id"], str(self.root / relative), row["sha256"],
                                         row["findings"], row["status"], str(destination)))
            self.connection.execute("UPDATE operations SET complete = 1 WHERE id = ?", (row["id"],))
            self.record_head(str(relative), row["sha256"], row["action"])
