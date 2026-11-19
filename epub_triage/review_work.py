"""Offline, bounded review data and exact candidate construction."""

from collections import Counter
import hashlib
import json
from pathlib import PurePosixPath
import re
import unicodedata

from .archive import inventory


SLICE = 4096
FINDING_LIMIT = 300
SEARCH_LIMIT = 20
EXTRA_TEXT_EXT = {".css", ".txt", ".json", ".vtt"}
OCR = "suspected_ocr_corruption"


def stable_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode()).hexdigest()


def text_member(name, path):
    from .content import XML_EXT

    data = path.read_bytes()
    suffix = PurePosixPath(name).suffix.lower()
    if suffix not in XML_EXT and suffix not in EXTRA_TEXT_EXT and not data[:512].lstrip().startswith((b"<", b"\xff\xfe", b"\xfe\xff")):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeError:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                return data.decode("utf-16")
            except UnicodeError:
                pass
        match = re.match(rb"<\?xml[^>]{0,200}?encoding\s*=\s*['\"]([\w-]+)['\"]", data)
        if match:
            try:
                return data.decode(match[1].decode("ascii"))
            except (UnicodeError, LookupError):
                pass
    return None


def excerpt(member, source, start, length=SLICE):
    end = min(len(source), start + length)
    return {"member": member, "start": start, "end": end, "text": source[start:end]}


def diagnostic_key(issue):
    return {key: value for key, value in issue.items() if key != "location"}


TAG = re.compile(r"""<!--.*?-->|<\?.*?\?>|<!\[CDATA\[.*?\]\]>|<(?:[^>"']|"[^"]*"|'[^']*')*>""", re.S)
ELEMENT = re.compile(r"</?([^/\s>]+)")
REPLACEMENT = re.compile(r"\ufffd|&#(?:0*65533|[xX]0*[fF][fF][fF][dD]);")
IDENTIFIER = re.compile(r"""\s(?:xml:)?id\s*=\s*(["'])(.*?)\1""")


SENTENCE_END = re.compile(r"""(?<=[.!?])["'”’»)\]]*(?P<separator>\s+)""")
WORD_CHAR = rf"(?:{REPLACEMENT.pattern}|\w|[\u0300-\u036f])"
WORD = re.compile(rf"{WORD_CHAR}+(?:[’'-]{WORD_CHAR}+)*")


def damaged_words(source, start, end, anchor, output):
    if not REPLACEMENT.search(source, start, end):
        return
    damaged = []
    total = 0
    for total, token in enumerate(WORD.finditer(source, start, end), start=1):
        if REPLACEMENT.search(source, token.start(), token.end()):
            damaged.append((token.start(), token.end(), total))
            if len(damaged) + len(output) > FINDING_LIMIT:
                raise RuntimeError("Review occurrence limit exceeded")
    # If the number of words changes, reopen occurrences in this sentence:
    # an indistinguishable sibling may otherwise inherit the original decision.
    output.extend((left, right, [*anchor, "word", ordinal, total])
                  for left, right, ordinal in damaged)


def damaged_passages(source, start, end, anchor, output):
    if not REPLACEMENT.search(source, start, end):
        return
    matches = []
    index = 0
    cursor = start
    for boundary in SENTENCE_END.finditer(source, start, end):
        damaged_words(source, cursor, boundary.start("separator"), ["sentence", index], matches)
        cursor = boundary.end()
        index += 1
    if cursor < end:
        damaged_words(source, cursor, end, ["sentence", index], matches)
        index += 1
    if len(matches) + len(output) > FINDING_LIMIT:
        raise RuntimeError("Review occurrence limit exceeded")
    output.extend((left, right, [*anchor, *position, index]) for left, right, position in matches)


def ocr_spans(source):
    """Match source text slots, using unique element IDs as stable anchors when present."""
    identifiers = Counter(match[2] for match in IDENTIFIER.finditer(source))
    stack = []
    previous = 0
    output = []
    for token in TAG.finditer(source):
        if stack:
            anchor, _, slot = stack[-1]
            damaged_passages(source, previous, token.start(), [*anchor, "text", slot], output)
            if token[0].startswith("<![CDATA["):
                damaged_passages(source, token.start() + 9, token.end() - 3, [*anchor, "cdata", slot], output)
            stack[-1][2] += 1
        previous = token.end()
        element = ELEMENT.match(token[0])
        if not element or element[1].startswith(("!", "?")):
            continue
        if token[0].startswith("</"):
            if stack:
                stack.pop()
            continue
        name = element[1]
        if stack:
            anchor, children, _ = stack[-1]
            children[name] += 1
            path = [*anchor, [name, children[name]]]
        else:
            path = [[name, 1]]
        identifier = IDENTIFIER.search(token[0])
        if identifier and identifiers[identifier[2]] == 1:
            path = ["id", identifier[2]]
        if not token[0].endswith("/>"):
            stack.append([path, Counter(), 0])
    return output


def ocr_passage(source, start, end):
    # Adjacent punctuation belongs to the passage fingerprint. Keep the
    # editable span restricted to the affected word.
    while start > 0 and unicodedata.category(source[start - 1]).startswith("P"):
        start -= 1
    while end < len(source) and unicodedata.category(source[end]).startswith("P"):
        end += 1
    return source[start:end]



def occurrences(issues, members):
    output = []
    duplicate = Counter()
    sources = {}
    for issue in issues:
        member = issue.get("member")
        if member not in sources:
            sources[member] = text_member(member, members[member]) if member in members else None
        source = sources[member]
        spans = []
        location = issue.get("location")
        if issue["code"] == OCR and source is not None:
            spans = ocr_spans(source)
            if not spans:
                center = source.find("\ufffd")
                if center != -1:
                    spans.append((max(0, center - 96), min(len(source), center + 96), None))
        elif (source is not None and isinstance(location, list) and len(location) == 2
              and type(location[0]) is int and location[0] > 0):
            line = 1
            start = 0
            while line < location[0]:
                end = source.find("\n", start)
                if end == -1:
                    break
                start = end + 1
                line += 1
            offset = min(len(source), start + max(0, (location[1] or 1) - 1))
            spans.append((max(start, offset - 100), min(len(source), offset + 100), location))
        if not spans:
            spans = [(0, min(len(source), 200), location)] if source is not None else [(None, None, location)]
        for start, end, locator in spans:
            diagnostic = diagnostic_key(issue)
            snippet = source[start:end] if start is not None else None
            if snippet is not None and issue["code"] == OCR:
                snippet = ocr_passage(source, start, end)
            anchor = [diagnostic, stable_hash(snippet), locator]
            signature = stable_hash(anchor)
            index = duplicate[signature]
            duplicate[signature] += 1
            if len(output) >= FINDING_LIMIT:
                raise RuntimeError("Review occurrence limit exceeded")
            output.append({"occurrence": stable_hash([signature, index]), "finding": issue,
                           "start": start, "end": end, "locator": locator})
    return output


def offline_scope(members, request):
    action = request["action"]
    name = request.get("member")
    if action in {"read", "validate_edit"}:
        source = text_member(name, members[name]) if name in members else None
        if source is None:
            return {"denied": "Member is outside the selected book's readable text"}
        start = request["start"]
        if start > len(source):
            return {"denied": "Start is outside member"}
        if action == "read":
            return excerpt(name, source, start)
        before = request["before"]
        if members[name].read_bytes() != source.encode("utf-8"):
            return {"denied": "Exact edits require a round-trippable UTF-8 member"}
        if not source.startswith(before, start):
            return {"denied": "Original text does not match this source location"}
        return {"matched": True, "context": excerpt(name, source, max(0, start - 160), len(before) + 320)}
    if action == "occurrences":
        return {"occurrences": occurrences(request["issues"], members)}
    if action == "index":
        names = sorted(members)
        start = request.get("start", 0)
        return {"members": [{"member": name, "bytes": members[name].stat().st_size}
                            for name in names[start:start + 30]],
                "next": start + 30 if len(names) > start + 30 else None}
    if action == "search":
        query = request["query"]
        output = []
        after = tuple(request.get("after", ["", -1]))
        for name, path in sorted(members.items()):
            if name < after[0]:
                continue
            source = text_member(name, path)
            if source is None:
                continue
            start = after[1] + 1 if name == after[0] else 0
            while (position := source.find(query, start)) != -1:
                if len(output) == SEARCH_LIMIT:
                    last = output[-1]
                    return {"matches": output, "next": [last["member"], last["match_start"]]}
                result = excerpt(name, source, max(0, position - 60), len(query) + 120)
                result["match_start"] = position
                output.append(result)
                start = position + 1
        return {"matches": output, "next": None}
    if action == "diagnostic":
        terms = request["terms"]
        counts = dict.fromkeys(terms, 0)
        for name, path in members.items():
            source = text_member(name, path)
            if source is not None:
                for term in terms:
                    counts[term] += source.count(term)
        return {"name": "count_variants", "counts": counts}
    raise RuntimeError("Unknown offline review request")


def build(book, limits, members, request, candidate, scratch):
    from .repair_rules import Layout, signature_review

    edit = request["edit"]
    member = edit["member"]
    check = offline_scope(members, {**edit, "action": "validate_edit"})
    if not check.get("matched") or member == "mimetype":
        return {"rejected": check.get("denied", "Mimetype is outside text review")}
    path = members[member]
    original = path.read_bytes()
    left = len(original.decode("utf-8")[:edit["start"]].encode("utf-8"))
    right = left + len(edit["before"].encode("utf-8"))
    planned = {**edit, "rule": "review", "byte_span": [left, right],
               "member_sha256": hashlib.sha256(original).hexdigest()}
    if signed := signature_review(members, [planned]):
        return {"rejected": "Signed content requires preservation", "signature_review": signed}
    layout = Layout(book, limits)
    layout.build(candidate, members, [planned])
    if candidate.stat().st_size > limits["max_book_bytes"]:
        return {"rejected": "Candidate exceeds configured book limit"}
    checked = scratch / "review-candidate"
    checked.mkdir()
    output = inventory(candidate, checked, limits)
    if set(output) != set(members) or not layout.preserves(Layout(candidate, limits), [planned]):
        return {"rejected": "Candidate failed ZIP record preservation"}
    expected = original[:left] + edit["after"].encode("utf-8") + original[right:]
    if output[member].read_bytes() != expected:
        return {"rejected": "Candidate failed exact edit verification"}
    with candidate.open("rb") as stream:
        return {"built": True, "edit": planned, "candidate_sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def run(book, limits, request, scratch, candidate=None):
    root = scratch / "review-members"
    root.mkdir()
    members = inventory(book, root, limits)
    if candidate is not None:
        return build(book, limits, members, request, candidate, scratch)
    return offline_scope(members, request)
