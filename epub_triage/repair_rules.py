"""Bounded, evidence-driven repair planning and byte-preserving ZIP edits."""

import errno
import hashlib
import posixpath
import re
import shutil
import struct
from urllib.parse import urlsplit
import zipfile
import zlib

from .archive import BookError, end_record, inventory
from .content import local, markup

MIME = b"application/epub+zip"
OPF = "{http://www.idpf.org/2007/opf}"
DC = "{http://purl.org/dc/elements/1.1/}"
NCX = "{http://www.daisy.org/z3986/2005/ncx/}"
HTML = "{http://www.w3.org/1999/xhtml}"
CONTAINER = "{urn:oasis:names:tc:opendocument:xmlns:container}"
SIG = "{http://www.w3.org/2000/09/xmldsig#}"
XML = "{http://www.w3.org/XML/1998/namespace}"
PATH = re.compile(r"[A-Za-z0-9_./~-]+")
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")


def ascii_case(value):
    return value.lower() if value.isascii() else value


def internal(owner, value):
    # Deliberately narrow URL subset with byte-for-byte attribute correspondence.
    if not value or len(value) > 8192 or not value.isascii() or any(ord(character) <= 32 for character in value):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if (parts.scheme or parts.netloc or parts.query or not PATH.fullmatch(parts.path)
            or parts.path.startswith("/") or (parts.fragment and not TOKEN.fullmatch(parts.fragment))):
        return None
    target = posixpath.normpath(posixpath.join(posixpath.dirname(owner), parts.path))
    if target == ".." or target.startswith("../"):
        return None
    return target, parts.fragment


def document(members, name):
    if name in members:
        return markup(members[name].read_bytes(), name)
    return None


def has_base(tree):
    return any(isinstance(node.tag, str) and
               (node.get(XML + "base") is not None or local(node.tag) == "base")
               for node in tree.iter())


def attr_spans(data, root, attribute):
    from xml.parsers import expat

    if not data.isascii() and root.getroottree().docinfo.encoding.upper() != "UTF-8":
        return {}
    nodes = [item for item in root.iter() if isinstance(item.tag, str)]
    parser = expat.ParserCreate(namespace_separator="}")
    positions = {}
    index = 0

    def start(tag, attrs):
        nonlocal index
        expected = nodes[index]
        index += 1
        parsed_tag = "{" + tag if "}" in tag else tag
        if expected.tag != parsed_tag:
            raise ValueError("XML element identities differ")
        old = attrs.get(attribute)
        if not old or not old.isascii():
            return
        begin = parser.CurrentByteIndex
        # Tokenize just this start tag so attribute-like text in another value is ignored.
        tag_bytes = re.match(rb"""<(?:[^"'<>]|"[^"]*"|'[^']*')+>""", data[begin:begin + 65536])
        if not tag_bytes:
            return
        tokens = re.finditer(rb"""\s+([^\s=/<>"']+)\s*=\s*(["'])(.*?)\2""",
                             tag_bytes[0], re.DOTALL)
        for match in tokens:
            if match[1] == attribute.encode() and match[3] == old.encode():
                positions[expected] = begin + match.start(3), begin + match.end(3)

    parser.StartElementHandler = start
    parser.ExternalEntityRefHandler = lambda *_: 1
    try:
        parser.Parse(data, True)
    except (expat.ExpatError, ValueError, IndexError, LookupError):
        return {}
    return positions if index == len(nodes) else {}


def xml_edit(members, member, root, node, attribute, new, rule, finding_code, evidence, cache=None):
    old = node.get(attribute)
    if cache is not None and member in cache:
        spans, sha256 = cache[member]
    else:
        data = members[member].read_bytes()
        spans = attr_spans(data, root, attribute)
        sha256 = hashlib.sha256(data).hexdigest()
        if cache is not None:
            cache[member] = spans, sha256
    span = spans.get(node)
    if span is None:
        return None
    return {"rule": rule, "member": member,
            "locator": root.getroottree().getelementpath(node) + "/@" + attribute,
            "byte_span": list(span), "before": old, "after": new,
            "member_sha256": sha256,
            "finding_codes": finding_code, "evidence": evidence}


def package_context(members):
    container = document(members, "META-INF/container.xml")
    if container is None or container.tag != CONTAINER + "container" or has_base(container):
        return None
    roots = container.findall(f"./{CONTAINER}rootfiles/{CONTAINER}rootfile")
    if len(roots) != 1:
        return None
    opf_name = roots[0].get("full-path")
    opf = document(members, opf_name)
    if opf is None or opf.tag != OPF + "package" or has_base(opf):
        return None
    manifests = opf.findall(OPF + "manifest")
    spines = opf.findall(OPF + "spine")
    if len(manifests) != 1 or len(spines) != 1:
        return None
    items = manifests[0].findall(OPF + "item")
    ids = [item.get("id") for item in items]
    if None in ids or len(ids) != len(set(ids)):
        return None
    return opf_name, opf, items, spines[0]


def broader(members):
    context = package_context(members)
    if context is None:
        return []
    opf_name, opf, items, spine = context
    version = opf.get("version", "")
    ncx_items = [item for item in items if item.get("id") == spine.get("toc")
                 and item.get("media-type") == "application/x-dtbncx+xml"]
    nav_items = [item for item in items if "nav" in item.get("properties", "").split()
                 and item.get("media-type") == "application/xhtml+xml"]
    if version == "2.0" and len(ncx_items) == 1:
        nav_item, root_tag, link_tag, attribute = ncx_items[0], NCX + "ncx", NCX + "content", "src"
    elif version in {"3.0", "3.1", "3.2", "3.3"} and len(nav_items) == 1:
        nav_item, root_tag, link_tag, attribute = nav_items[0], HTML + "html", HTML + "a", "href"
    else:
        return []
    resolved = internal(opf_name, nav_item.get("href"))
    if resolved is None or resolved[1]:
        return []
    nav_name = resolved[0]
    nav = document(members, nav_name)
    if nav is None or nav.tag != root_tag or has_base(nav):
        return []
    edits = []
    inventory_case = {}
    for name in members:
        inventory_case.setdefault(ascii_case(name), []).append(name)
    manifest_paths = {}
    for item in items:
        location = internal(opf_name, item.get("href"))
        if location:
            manifest_paths.setdefault(ascii_case(location[0]), []).append((location, item))
    chapters = {}
    spans = {}
    for link in nav.iter(link_tag):
        if version != "2.0" and not any(parent.tag == HTML + "nav" for parent in link.iterancestors()):
            continue
        old = link.get(attribute)
        target = internal(nav_name, old)
        if target is None or target[0] in members:
            continue
        missing, fragment = target
        matches = inventory_case.get(ascii_case(missing), [])
        if len(matches) != 1:
            continue
        match = matches[0]
        if posixpath.dirname(missing) != posixpath.dirname(match):
            continue
        declarations = manifest_paths.get(ascii_case(missing), [])
        if len(declarations) != 1:
            continue
        location, declared = declarations[0]
        if location != (match, "") or declared.get("media-type") != "application/xhtml+xml":
            continue
        if match not in chapters:
            chapters[match] = document(members, match)
        chapter = chapters[match]
        if chapter is None or chapter.tag != HTML + "html":
            continue
        if fragment:
            anchors = [node for node in chapter.iter() if isinstance(node.tag, str) and
                       (fragment in {node.get("id"), node.get(XML + "id")} or
                        (node.tag == HTML + "a" and node.get("name") == fragment))]
            if len(anchors) != 1:
                continue
        raw_path, separator, raw_fragment = old.partition("#")
        prefix = raw_path[:-len(posixpath.basename(raw_path))]
        fixed = prefix + posixpath.basename(match) + separator + raw_fragment
        if internal(nav_name, fixed) != (match, fragment):
            continue
        edit = xml_edit(members, nav_name, nav, link, attribute, fixed, "R1",
                        ["broken_navigation_target"],
                        {"missing_target": missing, "manifest_member": opf_name,
                         "manifest_id": declared.get("id"), "matched_target": match,
                         "unique_fragment": fragment or None}, spans)
        if edit:
            edits.append(edit)
    if version == "2.0":
        edit = identifier_edit(members, opf_name, opf, nav_name, nav)
        if edit:
            edits.append(edit)
    return edits


def identifier_edit(members, opf_name, opf, nav_name, nav):
    if any(ascii_case(name) == "meta-inf/encryption.xml" for name in members):
        return None
    old = opf.get("unique-identifier")
    if not old or not TOKEN.fullmatch(old):
        return None
    ids = [(node, node.get(key)) for node in opf.iter() if isinstance(node.tag, str)
           for key in ("id", XML + "id") if node.get(key) is not None]
    matches = [(node, value) for node, value in ids if ascii_case(value) == ascii_case(old)]
    if len(matches) != 1:
        return None
    node, value = matches[0]
    if value == old or node.tag != DC + "identifier" or node.get("id") != value or len(node):
        return None
    if node.getparent().tag != OPF + "metadata" or node.getparent().getparent() is not opf:
        return None
    uids = [meta.get("content") for meta in nav.findall(f"./{NCX}head/{NCX}meta")
            if meta.get("name") == "dtb:uid"]
    if not node.text or len(node.text) > 8192 or not node.text.strip() or uids != [node.text]:
        return None
    return xml_edit(members, opf_name, opf, opf, "unique-identifier", value, "D1",
                    ["OPF-030", "repair_identifier_pointer"],
                    {"ncx_member": nav_name, "ncx_uid": uids[0], "identifier_id": value,
                     "identifier_value": node.text})


def signature_review(members, edits):
    findings = []
    edited = {edit["member"]: edit["rule"] for edit in edits if edit["rule"] != "M1"}
    for name in members:
        ext = posixpath.splitext(name)[1].lower()
        container_signature = ascii_case(name) == "meta-inf/signatures.xml"
        if ext in {".sig", ".p7s", ".asc", ".sf", ".rsa", ".dsa", ".ec"}:
            findings.append({"member": name, "impact": "unknown",
                             "reason": "Potential opaque signature file",
                             "proposed_edits": [edit["rule"] for edit in edits]})
            continue
        # Declared XML may have any suffix, encoding, or amount of leading whitespace.
        try:
            root = document(members, name)
        except BookError:
            if not container_signature:
                continue
            root = None
        signatures = list(root.iter(SIG + "Signature")) if root is not None else []
        if container_signature and not signatures:
            findings.append({"member": name, "impact": "unknown",
                             "reason": "Container signature document has no recognized signature graph",
                             "proposed_edits": [edit["rule"] for edit in edits]})
        ambiguous_base = bool(signatures) and has_base(root)
        for signature in signatures:
            references = []
            for ref in signature.iter(SIG + "Reference"):
                uri = ref.get("URI", "")
                base = "" if container_signature else name
                target = internal(base, uri)
                whole = (target and not target[1] and target[0] in members
                         and len(ref.findall(SIG + "Transforms")) == 0
                         and not ambiguous_base and ref.get("Type") is None)
                references.append({"uri": uri, "member": target[0] if target else None,
                                   "affected_rule": edited.get(target[0]) if whole else None,
                                   "coverage": "whole-member" if whole else "unknown"})
            findings.append({"member": name, "signature_id": signature.get("Id"),
                             "impact": "affected" if any(i["affected_rule"] for i in references) else "unknown",
                             "reason": "Whole-member reference bytes would change" if any(
                                 i["affected_rule"] for i in references
                             ) else "Complete preservation of the signature graph is unqualified",
                             "references": references,
                             "proposed_edits": [edit["rule"] for edit in edits]})
    return findings


class Layout:
    """Raw local and central record spans from a reconciled archive."""

    def __init__(self, book, limits):
        self.book = book
        with zipfile.ZipFile(book) as zipped, book.open("rb") as raw:
            self.entries = {item.filename: item for item in zipped.infolist()}
            self.order = sorted(self.entries, key=lambda name: self.entries[name].header_offset)
            _, size, end = end_record(raw, limits)
            offsets = [self.entries[name].header_offset for name in self.order] + [end]
            self.local = dict(zip(self.order, zip(offsets, offsets[1:])))
            raw.seek(end)
            self.central = {}
            for name in self.entries:
                header = raw.read(46)
                sizes = struct.unpack_from("<3H", header, 28)
                self.central[name] = header + raw.read(sum(sizes))
            raw.seek(end + size)
            self.end = raw.read()

    def local_header(self, raw, name):
        raw.seek(self.local[name][0])
        fixed = raw.read(30)
        name_size, extra_size = struct.unpack_from("<2H", fixed, 26)
        return fixed + raw.read(name_size + extra_size), extra_size

    @staticmethod
    def record_digest(raw, bounds):
        start, end = bounds
        raw.seek(start)
        digest = hashlib.sha256()
        while raw.tell() < end:
            block = raw.read(min(1024 * 1024, end - raw.tell()))
            if not block:
                raise RuntimeError("Truncated local ZIP record")
            digest.update(block)
        return digest.digest()

    def preserves(self, candidate, edits):
        changed = {edit["member"] for edit in edits}
        packaging = any(edit["rule"] == "M1" for edit in edits)
        if (self.end[22:] != candidate.end[22:] or
                set(self.entries) != set(candidate.entries)):
            return False
        def order(names):
            return [name for name in names if not (packaging and name == "mimetype")]
        if order(self.order) != order(candidate.order) or order(self.entries) != order(candidate.entries):
            return False
        with self.book.open("rb") as original, candidate.book.open("rb") as revised:
            for name in self.entries:
                old, new = self.central[name], candidate.central[name]
                if name not in changed:
                    if (old[:42] + old[46:] != new[:42] + new[46:] or
                            self.record_digest(original, self.local[name]) !=
                            self.record_digest(revised, candidate.local[name])):
                        return False
                    continue
                old_local, _ = self.local_header(original, name)
                new_local, _ = candidate.local_header(revised, name)
                # Flags/method can change only for M1; CRC, lengths and offsets are derived.
                if old[:8] + old[12:16] + old[28:42] + old[46:] != (
                        new[:8] + new[12:16] + new[28:42] + new[46:]):
                    return False
                if old_local[:6] + old_local[10:14] + old_local[26:] != (
                        new_local[:6] + new_local[10:14] + new_local[26:]):
                    return False
                if name != "mimetype" and (old[8:12] != new[8:12] or
                                            old_local[6:10] != new_local[6:10]):
                    return False
        return True

    def mime_edit(self, members):
        info = self.entries.get("mimetype")
        if info is None or info.file_size != len(MIME) or members["mimetype"].read_bytes() != MIME:
            return None
        with self.book.open("rb") as raw:
            _, extra = self.local_header(raw, "mimetype")
        if info.extra or extra or info.flag_bits & 8:
            return None
        if info.header_offset == 0 and info.compress_type == 0:
            return None
        return {"rule": "M1", "member": "mimetype", "locator": "ZIP local header",
                "before": {"offset": info.header_offset, "method": info.compress_type},
                "after": {"offset": 0, "method": 0},
                "member_sha256": hashlib.sha256(MIME).hexdigest(),
                "finding_codes": ["repair_mimetype_layout", "PKG-006", "PKG-007"],
                "evidence": {"exact_payload": MIME.decode(), "extra_fields": False}}

    def build(self, candidate, members, edits):
        from itertools import groupby

        by_member = {name: list(group) for name, group in groupby(
            sorted(edits, key=lambda edit: edit["member"]), key=lambda edit: edit["member"]
        )}
        order = self.order.copy()
        if by_member.get("mimetype"):
            order.remove("mimetype")
            order.insert(0, "mimetype")
        offsets = {}
        headers = {}
        with self.book.open("rb") as raw, candidate.open("wb") as output:
            for name in order:
                start, end = self.local[name]
                offsets[name] = output.tell()
                if name not in by_member:
                    raw.seek(start)
                    remaining = end - start
                    while remaining:
                        block = raw.read(min(remaining, 1024 * 1024))
                        if not block:
                            raise RuntimeError("Input ZIP record was truncated")
                        output.write(block)
                        remaining -= len(block)
                    continue
                data = members[name].read_bytes()
                member_hash = hashlib.sha256(data).hexdigest()
                if any(edit["member_sha256"] != member_hash for edit in by_member[name]):
                    raise RuntimeError("Planned member bytes changed")
                header, _ = self.local_header(raw, name)
                header = bytearray(header)
                info = self.entries[name]
                if name != "mimetype":
                    previous = len(data)
                    for edit in sorted(by_member[name], key=lambda item: item["byte_span"], reverse=True):
                        left, right = edit["byte_span"]
                        if right > previous or data[left:right] != edit["before"].encode():
                            raise RuntimeError("Planned attribute span is invalid or overlaps")
                        data = data[:left] + edit["after"].encode() + data[right:]
                        previous = left
                method = 0 if name == "mimetype" else info.compress_type
                flags = info.flag_bits & ~6 if name == "mimetype" else info.flag_bits
                if method == 8:
                    encoder = zlib.compressobj(6, zlib.DEFLATED, -15)
                    encoded = encoder.compress(data) + encoder.flush()
                else:
                    encoded = data
                checks = zlib.crc32(data), len(encoded), len(data)
                struct.pack_into("<2H", header, 6, flags, method)
                if not flags & 8:
                    struct.pack_into("<3I", header, 14, *checks)
                else:
                    fields = struct.unpack_from("<3I", header, 14)
                    struct.pack_into("<3I", header, 14, *(expected if old else 0
                                     for old, expected in zip(fields, checks)))
                output.write(header)
                output.write(encoded)
                if flags & 8:
                    raw.seek(start + len(header) + info.compress_size)
                    if end - raw.tell() == 16:
                        output.write(b"PK\x07\x08")
                    output.write(struct.pack("<3I", *checks))
                headers[name] = flags, method, checks
            central_start = output.tell()
            central_order = list(self.entries)
            if "mimetype" in by_member:
                central_order.remove("mimetype")
                central_order.insert(0, "mimetype")
            for name in central_order:
                central = bytearray(self.central[name])
                struct.pack_into("<I", central, 42, offsets[name])
                if name in headers:
                    flags, method, checks = headers[name]
                    struct.pack_into("<2H", central, 8, flags, method)
                    struct.pack_into("<3I", central, 16, *checks)
                output.write(central)
            eocd = bytearray(self.end)
            struct.pack_into("<2I", eocd, 12, output.tell() - central_start, central_start)
            output.write(eocd)


def findings(book, members, limits):
    layout = Layout(book, limits)
    mime = layout.mime_edit(members)
    results = []
    if mime:
        results.append({"kind": "verified", "code": "repair_mimetype_layout",
                        "detail": "Canonical mimetype member is misplaced or compressed", "member": "mimetype"})
    try:
        context = package_context(members)
        edits = broader(members) if context and context[1].get("version") == "2.0" else []
    except BookError:
        edits = []
    for edit in edits:
        if edit["rule"] == "D1":
            results.append({"kind": "verified", "code": "repair_identifier_pointer",
                            "detail": "Dangling identifier pointer " + edit["before"], "member": edit["member"],
                            "location": edit["locator"]})
    return results


def plan(book, limits, profile, scratch, candidate=None):
    target = scratch / "repair-input"
    target.mkdir()
    try:
        members = inventory(book, target, limits)
    except BookError as error:
        return {"built": False, "edits": [], "review": [{"member": error.member, "reason": str(error)}]}
    layout = Layout(book, limits)
    edits = [edit for edit in [layout.mime_edit(members)] if edit]
    if profile == "broader":
        try:
            edits.extend(broader(members))
        except BookError:
            # Independent v1 inspection gates the input and identifies syntax defects.
            pass
    review = signature_review(members, edits) if edits else []
    result = {"edits": edits, "review": review, "built": False}
    if candidate is None or not edits or review:
        return result
    hashes = {}
    for name, path in members.items():
        changes = [edit for edit in edits if edit["member"] == name and "byte_span" in edit]
        if not changes:
            with path.open("rb") as stream:
                hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
            continue
        original = path.read_bytes()
        expected = hashlib.sha256()
        position = 0
        for change in sorted(changes, key=lambda item: item["byte_span"]):
            left, right = change["byte_span"]
            expected.update(original[position:left])
            expected.update(change["after"].encode())
            position = right
        expected.update(original[position:])
        hashes[name] = expected.hexdigest()
    try:
        layout.build(candidate, members, edits)
    except OSError as error:
        if error.errno != errno.EFBIG:
            raise
        return {**result, "rejected": "Candidate exceeds worker file limit"}
    if candidate.stat().st_size > limits["max_book_bytes"]:
        return {**result, "rejected": "Candidate exceeds configured book limit"}
    shutil.rmtree(target)
    validation = scratch / "repair-check"
    validation.mkdir()
    try:
        output = inventory(candidate, validation, limits)
    except BookError as error:
        return {**result, "rejected": str(error)}
    if set(output) != set(members):
        return {**result, "rejected": "Candidate member inventory changed"}
    for name, path in output.items():
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != hashes[name]:
            return {**result, "rejected": "Candidate member payload failed byte preservation"}
    candidate_layout = Layout(candidate, limits)
    if not layout.preserves(candidate_layout, edits):
        return {**result, "rejected": "Candidate ZIP records failed metadata preservation"}
    if any(edit["rule"] == "M1" for edit in edits):
        mime = candidate_layout.entries.get("mimetype")
        with candidate.open("rb") as raw:
            _, extra = candidate_layout.local_header(raw, "mimetype")
        if not mime or mime.header_offset or mime.compress_type or extra or mime.extra:
            return {**result, "rejected": "Canonical mimetype postcondition failed"}
    for edit in edits:
        if edit["rule"] == "M1":
            continue
        root = document(output, edit["member"])
        node_path, _, attribute = edit["locator"].rpartition("/@")
        node = root.find(node_path) if node_path != "." else root
        if node is None or node.get(attribute) != edit["after"]:
            return {**result, "rejected": "Repaired XML attribute postcondition failed"}
    with candidate.open("rb") as stream:
        candidate_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {**result, "built": True, "candidate_sha256": candidate_hash}
