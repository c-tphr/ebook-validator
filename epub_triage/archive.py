"""Reconcile accepted ZIP layouts before exposing any member to a parser."""

import stat
import struct
import unicodedata
import zipfile
import zlib


RESERVED_NAMES = {"con", "prn", "aux", "nul", *(
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in "123456789¹²³"
)}


class BookError(Exception):
    def __init__(self, code, message, member=None, kind="incomplete"):
        super().__init__(message)
        self.code, self.member, self.kind = code, member, kind


def unsafe(message, member=None):
    raise BookError("unsafe_archive", message, member, "unsafe")


def end_record(raw, limits):
    end = raw.seek(0, 2)
    if end < 22:
        unsafe("Missing ZIP end record")
    raw.seek(max(0, end - 65557))
    tail = raw.read()
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or marker + 22 > len(tail):
        unsafe("Missing ZIP end record")
    _, disk, central_disk, disk_count, count, length, offset, comment = struct.unpack_from(
        "<4s4H2IH", tail, marker
    )
    if (disk or central_disk or disk_count != count or count == 65535
            or marker + 22 + comment != len(tail)
            or offset + length != end - len(tail) + marker):
        unsafe("Ambiguous, split, ZIP64, or trailing ZIP data")
    if count > limits["max_entries"]:
        raise BookError("entry_limit", "ZIP member count exceeds limit")
    if length > 32 * 1024 * 1024:
        raise BookError("central_directory_limit", "ZIP central directory exceeds 32 MiB")
    return count, length, offset


def inventory(path, out, limits):
    members = {}
    total = 0
    try:
        with open(path, "rb") as source:
            count, length, offset = end_record(source, limits)
            # Bound the true number of central records before zipfile allocates entries.
            source.seek(offset)
            for _ in range(count):
                fixed = source.read(46)
                if len(fixed) != 46 or fixed[:4] != b"PK\x01\x02":
                    unsafe("Invalid ZIP central directory record")
                name_len, extra_len, comment_len = struct.unpack_from("<3H", fixed, 28)
                source.seek(name_len + extra_len + comment_len, 1)
            if source.tell() != offset + length:
                unsafe("ZIP central directory count or bounds disagree")
        with zipfile.ZipFile(path) as archive, open(path, "rb") as raw:
            if archive.start_dir != offset:
                unsafe("ZIP central directory locations disagree")
            entries = archive.infolist()
            if count != len(entries):
                unsafe("ZIP member counts disagree")
            raw.seek(offset)
            for entry in entries:
                fixed = raw.read(46)
                if len(fixed) != 46 or fixed[:4] != b"PK\x01\x02":
                    unsafe("Invalid central directory record")
                name_len, extra_len, comment_len, start_disk = struct.unpack_from("<4H", fixed, 28)
                if start_disk:
                    unsafe("Split ZIP member")
                raw.read(name_len)
                check_extra(raw.read(extra_len), entry.orig_filename)
                raw.read(comment_len)
            if raw.tell() != offset + length:
                unsafe("Unaccounted central directory bytes")

            cursor = 0
            seen = {}
            for index, entry in enumerate(sorted(entries, key=lambda item: item.header_offset)):
                name = entry.orig_filename
                directory = name.endswith("/")
                parts = name.rstrip("/").split("/")
                if (name != entry.filename or name.endswith("//") or "\\" in name or ":" in name or any(
                        part in {"", ".", ".."} or part.rstrip(" .") != part for part in parts
                ) or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)):
                    unsafe("Unsafe ZIP member path", name)
                if any(part.partition(".")[0].casefold() in RESERVED_NAMES for part in parts):
                    unsafe("Reserved ZIP member path", name)
                normalized = [unicodedata.normalize("NFC", part).casefold() for part in parts]
                key = "/".join(normalized)
                if key in seen:
                    unsafe("Duplicate or normalized ZIP member collision", name)
                seen[key] = directory
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if mode not in (0, stat.S_IFDIR if directory else stat.S_IFREG):
                    unsafe("Special ZIP member", name)
                if entry.flag_bits & 0x41:
                    raise BookError("encrypted_member", "ZIP member is encrypted", name)
                if entry.flag_bits & ~0x80E or entry.compress_type not in (0, 8):
                    raise BookError("unsupported_zip", "Unsupported ZIP flags or compression", name)
                if entry.file_size > limits["max_member_bytes"]:
                    raise BookError("member_limit", "Declared member size exceeds limit", name)
                if entry.header_offset != cursor:
                    unsafe("Hidden, overlapping, or noncontiguous local ZIP records", name)
                raw.seek(cursor)
                fixed = raw.read(30)
                if len(fixed) != 30 or fixed[:4] != b"PK\x03\x04":
                    unsafe("Invalid local ZIP header", name)
                (_, _, flags, method, _, _, crc, compressed, expanded,
                 name_len, extra_len) = struct.unpack("<4s5H3I2H", fixed)
                wire_name = raw.read(name_len)
                check_extra(raw.read(extra_len), name)
                if (wire_name.decode("utf-8" if flags & 0x800 else "cp437") != name
                        or flags != entry.flag_bits or method != entry.compress_type):
                    unsafe("Local and central ZIP headers disagree", name)
                expected = (entry.CRC, entry.compress_size, entry.file_size)
                if flags & 8:
                    if any(actual not in (0, wanted)
                           for actual, wanted in zip((crc, compressed, expanded), expected)):
                        unsafe("Local ZIP sizes or CRC disagree", name)
                elif (crc, compressed, expanded) != expected:
                    unsafe("Local ZIP sizes or CRC disagree", name)
                data_offset = raw.tell()
                cursor = data_offset + entry.compress_size
                if cursor > offset:
                    unsafe("ZIP member extends into central directory", name)
                if flags & 8:
                    raw.seek(cursor)
                    descriptor = raw.read(16)
                    if len(descriptor) == 16 and descriptor[:4] == b"PK\x07\x08" and struct.unpack(
                        "<3I", descriptor[4:]
                    ) == expected:
                        cursor += 16
                    elif len(descriptor) >= 12 and struct.unpack("<3I", descriptor[:12]) == expected:
                        cursor += 12
                    else:
                        unsafe("Invalid ZIP data descriptor", name)
                target = out / f"{index:06d}"
                actual = 0
                crc = 0
                raw.seek(data_offset)
                decoder = zlib.decompressobj(-15) if method == 8 else None
                remaining = entry.compress_size
                with target.open("wb") as destination:
                    while remaining:
                        block = raw.read(min(remaining, 32768))
                        if not block:
                            unsafe("Truncated ZIP member data", name)
                        remaining -= len(block)
                        data = decoder.decompress(block, entry.file_size - actual + 1) if decoder else block
                        actual += len(data)
                        total += len(data)
                        if actual > entry.file_size:
                            unsafe("Expanded ZIP size differs from inventory", name)
                        if total > limits["max_expanded_bytes"]:
                            raise BookError("expansion_limit", "Expanded ZIP bytes exceed limit", name)
                        if decoder and (decoder.unconsumed_tail or decoder.unused_data):
                            unsafe("Unaccounted compressed ZIP bytes", name)
                        crc = zlib.crc32(data, crc)
                        destination.write(data)
                if (decoder and not decoder.eof) or actual != entry.file_size or crc != entry.CRC:
                    unsafe("ZIP member stream, byte count, or CRC failed", name)
                if directory:
                    if actual:
                        unsafe("ZIP directory contains data", name)
                    target.unlink()
                else:
                    members[name] = target
            if cursor != offset:
                unsafe("Unaccounted local ZIP data")
            for key in seen:
                parts = key.split("/")
                if any(seen.get("/".join(parts[:i])) is False for i in range(1, len(parts))):
                    unsafe("ZIP file also used as directory", key)
    except (zipfile.BadZipFile, UnicodeError, EOFError, zlib.error) as error:
        raise BookError("unreadable_zip", str(error)) from error
    return members


def check_extra(data, name):
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            unsafe("Truncated ZIP extra field", name)
        tag, length = struct.unpack_from("<2H", data, offset)
        offset += 4 + length
        if offset > len(data):
            unsafe("Truncated ZIP extra data", name)
        if tag not in {0x000A, 0x5455, 0x5855, 0x7855, 0x7875, 0x6375}:
            raise BookError("unsupported_zip_extra", f"Unsupported ZIP extra field 0x{tag:04x}", name)
