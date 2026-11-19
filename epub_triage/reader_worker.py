"""Offline EPUB frontends for Qt rich text and WeasyPrint paged HTML."""

from collections import Counter
from dataclasses import dataclass
import ctypes
import errno
import hashlib
from io import BytesIO
from importlib import metadata
import json
import os
from pathlib import Path
import posixpath
import resource
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, unquote, urljoin, urlsplit
from xml.etree import ElementTree

from .archive import BookError, inventory


ENGINES = ("qt5", "weasyprint")
VIEW = (768, 1024)
PASSIVE_NAMES = {"audio", "video", "object", "embed", "iframe", "script", "canvas", "form",
                 "svg", "math", "picture", "source", "track", "input", "button", "table"}
MEDIA = {"application/xhtml+xml", "text/html"}
RESOURCE_MEDIA = {".css": "text/css", ".png": "image/png", ".jpg": "image/jpeg",
                  ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
                  ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf", ".otf": "font/otf"}


def file_target_fingerprint(path):
    if path.startswith("/") and not any(character in path for character in ("\x00", "\n", "\r", "\\")):
        return hashlib.sha256(("local-absolute-file-v1\0" + posixpath.normpath(path)).encode()).hexdigest()
    return None


class CoverageError(ValueError):
    pass


def local(tag):
    return tag.rsplit("}", 1)[-1]


def xml(data):
    if b"\x00" in data or b"<!ENTITY" in data.upper():
        raise CoverageError("Unsupported encoding or XML entity")
    return ElementTree.fromstring(data)


def item_url(base, value):
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith(("/", "\\")):
        raise CoverageError("External or absolute package navigation")
    path = unquote(parsed.path, errors="strict")
    if "\\" in path or "\x00" in path or parsed.query:
        raise CoverageError("Unsupported package navigation path")
    member = posixpath.normpath(posixpath.join(posixpath.dirname(base), path)) if path else base
    if member in {".", ".."} or member.startswith("../"):
        raise CoverageError("Package navigation leaves the archive")
    return member, unquote(parsed.fragment, errors="strict")


class Monitor:
    """The renderer resource callback is the only route from markup to I/O."""

    def __init__(self, members):
        self.members = members
        self.origin = "https://" + secrets.token_hex(16) + ".invalid"
        self.events = []
        self.dependencies = Counter()
        self.step = None
        self.step_member = None
        self.requests = 0
        self.missing = set()

    def url(self, member):
        return self.origin + "/" + quote(member, safe="/")

    def address(self, url):
        target = urlsplit(url)
        if target.scheme == "https" and target.netloc == self.origin[8:]:
            member = unquote(target.path.lstrip("/"), errors="strict")
            return member, unquote(target.fragment, errors="strict")
        return None

    def fetch(self, url):
        self.requests += 1
        if self.requests > 512:
            raise CoverageError("Renderer resource request limit reached")
        address = self.address(url)
        if address is not None:
            member, _ = address
            entry = self.members.get(member)
            media = RESOURCE_MEDIA.get(Path(member).suffix.lower())
            if entry and media and not urlsplit(url).query:
                self.dependencies[media] += 1
                return entry.read_bytes(), media
            self.missing.add(self.step)
            return None
        scheme = urlsplit(url).scheme.lower()
        kind = ("out_of_book_read" if scheme in {"", "file"} else
                "outbound_request" if scheme in {"http", "https", "ftp"} else None)
        if kind is None:
            self.missing.add(self.step)
            return None
        event = {"action": kind, "scheme": scheme, "step": self.step, "attribution": "book",
                 "member": self.step_member, "phase": "navigation", "initiator": "renderer_resource_callback",
                 "evidence": "renderer_resource_request", "blocked": True,
                 "event_id": hashlib.sha256(("renderer-url-v1\0" + url).encode()).hexdigest()}
        parsed = urlsplit(url)
        if scheme == "file" and parsed.netloc in {"", "localhost"}:
            fingerprint = file_target_fingerprint(unquote(parsed.path))
            if fingerprint:
                event["file_target_fingerprint"] = fingerprint
        if event not in self.events:
            self.events.append(event)
            if os.environ.get("EPUB_CALLBACK_RECEIPTS") == "1":
                # A complete callback receipt survives a subsequent renderer
                # crash. Each bounded write has only trusted structured fields.
                wire = json.dumps(event, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
                descriptor = os.open("/callback-receipts", os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
                try:
                    if os.write(descriptor, wire) != len(wire):
                        raise OSError("Incomplete renderer callback receipt")
                finally:
                    os.close(descriptor)
        return None


@dataclass
class Rendered:
    anchors: dict
    links: set
    pages: int
    visit: object


class QtReader:
    def __init__(self, monitor):
        from PyQt5.QtCore import PYQT_VERSION_STR, QT_VERSION_STR, qVersion
        from PyQt5.QtGui import QFont
        from PyQt5.QtWidgets import QApplication

        self.app = QApplication([])
        self.app.setFont(QFont("DejaVu Sans", 12))
        self.monitor = monitor
        self.identity = {"engine": "qt5", "renderer": "Qt QTextDocument",
                         "version": qVersion(), "compiled_version": QT_VERSION_STR, "bindings": PYQT_VERSION_STR}

    def render(self, member, source):
        from PyQt5.QtCore import QSizeF, QUrl
        from PyQt5.QtGui import QImage, QPainter, QTextDocument

        monitor = self.monitor
        base = monitor.url(member)

        class Document(QTextDocument):
            def loadResource(self, kind, name):
                try:
                    result = monitor.fetch(urljoin(base, name.toString()))
                    if result and result[1].startswith("image/"):
                        image = QImage.fromData(result[0])
                        if not image.isNull():
                            return image
                    monitor.missing.add(monitor.step)
                except (ValueError, OSError):
                    monitor.missing.add(monitor.step)
                return None

        document = Document()
        document.setBaseUrl(QUrl(base))
        document.setPageSize(QSizeF(*VIEW))
        document.setHtml(source)
        document.documentLayout().documentSize()
        if document.pageCount() > 100:
            raise CoverageError("Page limit exceeded")
        def paint(page):
            if not 0 <= page < document.pageCount():
                raise CoverageError("Qt destination lies outside the rendered document")
            image = QImage(*VIEW, QImage.Format_RGB32)
            image.fill(0xffffff)
            painter = QPainter(image)
            try:
                painter.translate(0, -page * VIEW[1])
                from PyQt5.QtCore import QRectF
                document.drawContents(painter, QRectF(0, page * VIEW[1], *VIEW))
            finally:
                painter.end()
            return page + 1
        anchors, links = {}, set()
        layout = document.documentLayout()
        block = document.begin()
        while block.isValid():
            iterator = block.begin()
            while not iterator.atEnd():
                fragment = iterator.fragment()
                if fragment.isValid():
                    style = fragment.charFormat()
                    rectangle = layout.blockBoundingRect(block)
                    line = block.layout().lineForTextPosition(fragment.position() - block.position())
                    vertical = rectangle.top() + (line.y() if line.isValid() else 0)
                    for name in style.anchorNames():
                        anchors[name] = max(0, int(vertical // VIEW[1]))
                    if style.anchorHref():
                        links.add(urljoin(base, style.anchorHref()))
                iterator += 1
            block = block.next()
        return Rendered(anchors, links, document.pageCount(), paint)


class WeasyReader:
    def __init__(self, monitor):
        import weasyprint

        self.monitor = monitor
        self.identity = {"engine": "weasyprint", "renderer": "WeasyPrint HTML/CSS",
                         "version": weasyprint.__version__,
                         "packages": {name: metadata.version(name) for name in
                                      ("weasyprint", "pydyf", "tinycss2", "cssselect2", "fonttools",
                                       "Pillow", "cffi", "tinyhtml5")}}

    def render(self, member, source):
        from weasyprint import CSS, HTML
        from weasyprint.urls import URLFetcher, URLFetcherResponse

        monitor = self.monitor
        base = monitor.url(member)

        class Fetcher(URLFetcher):
            def fetch(self, url, headers=None):
                result = monitor.fetch(url)
                if result is None:
                    raise OSError("Reader resource policy blocked the request")
                data, media = result
                return URLFetcherResponse(url, BytesIO(data), {"Content-Type": media}, 200)

        document = HTML(string=source, base_url=base, url_fetcher=Fetcher()).render(
            stylesheets=[CSS(string="@page { size: 768px 1024px !important; margin: 24px; } "
                                    "body { font-family: DejaVu Sans; font-size: 12pt; }")],
            presentational_hints=False)
        if len(document.pages) > 100:
            raise CoverageError("Page limit exceeded")
        anchors, links = {}, set()
        for index, page in enumerate(document.pages):
            anchors.update({name: index for name in page.anchors})
            for kind, target, *_ in page.links:
                if kind == "internal":
                    links.add(urljoin(base, "#" + quote(target)))
                elif kind == "external":
                    links.add(target)
        def paint(index):
            from io import BytesIO
            output = BytesIO()
            document.copy([document.pages[index]]).write_pdf(output)
            if not output.getbuffer()[:5] == b"%PDF-":
                raise CoverageError("WeasyPrint did not paint the destination page")
            return index + 1
        return Rendered(anchors, links, len(document.pages), paint)


def trace_marker(name):
    if ctypes.CDLL(None).prctl(15, name.encode(), 0, 0, 0):
        raise RuntimeError("Reader monitor marker failed")


def session(engine, monitor):
    if engine == "qt5":
        return QtReader(monitor)
    if engine == "weasyprint":
        return WeasyReader(monitor)
    raise ValueError("Unknown rendering engine")


def html_document(entry, engine):
    root = xml(entry.read_bytes())
    if local(root.tag) != "html" or any(child.attrib.get("{http://www.w3.org/XML/1998/namespace}base")
                                      for child in root.iter()):
        raise CoverageError("Unsupported document or base URL")
    links = []
    identifiers = Counter()
    gaps = set()
    author_css = any(local(element.tag) == "style" or element.get("style")
                     or (local(element.tag) == "link" and element.get("rel", "").lower() == "stylesheet")
                     for element in root.iter())
    for element in root.iter():
        original = element.tag
        element.tag = local(original)
        if original.startswith("{") and not original.startswith("{http://www.w3.org/1999/xhtml}"):
            gaps.add("namespace outside the common reading profile")
        # Qt rich text ignores structural EPUB 3 tags. Explicitly map these
        # block containers while preserving their attributes and text.
        if engine == "qt5" and element.tag in {"aside", "section", "article", "nav", "main", "header",
                                               "footer", "figure", "figcaption"}:
            element.tag = "div"
            if author_css:
                gaps.add("Qt semantic container mapping may affect author CSS selectors")
        if element.tag in PASSIVE_NAMES or element.tag == "base" or (
                element.tag == "meta" and "http-equiv" in element.attrib):
            gaps.add("unsupported document feature " + element.tag)
        if any(key.lower().startswith("on") for key in element.attrib):
            gaps.add("unsupported executable document feature")
        if element.tag == "link" and element.get("rel", "").lower() == "stylesheet":
            gaps.add("linked CSS is outside the common rendering profile")
        if element.tag == "a" and element.get("href"):
            epub_type = element.get("{http://www.idpf.org/2007/ops}type", "").split()
            links.append((element.attrib["href"], "footnote" if "noteref" in epub_type
                          or element.get("role") == "doc-noteref" else None))
        if identifier := element.get("id") or (element.get("name") if element.tag == "a" else None):
            identifiers[identifier] += 1
    if any(count > 1 for count in identifiers.values()):
        gaps.add("duplicate navigation anchor")
    # Qt exposes named anchors and HTML IDs on rendered fragments. Preserve both.
    return ElementTree.tostring(root, encoding="unicode", method="html"), links, sorted(gaps)


def package(members):
    container = xml(members["META-INF/container.xml"].read_bytes())
    roots = [node.get("full-path") for node in container.iter() if local(node.tag) == "rootfile"]
    if len(roots) != 1 or roots[0] not in members:
        raise CoverageError("Missing or ambiguous package document")
    opf = roots[0]
    root = xml(members[opf].read_bytes())
    if local(root.tag) != "package" or any(node.get("{http://www.w3.org/XML/1998/namespace}base")
                                          for node in root.iter()):
        raise CoverageError("Unsupported package document")
    manifests = [node for node in root if local(node.tag) == "manifest"]
    spines = [node for node in root if local(node.tag) == "spine"]
    if len(manifests) != 1 or len(spines) != 1:
        raise CoverageError("Missing or ambiguous reading order")
    manifest = {}
    gaps = []
    if any((node.get("property", "").endswith(":layout") and (node.text or "").strip() != "reflowable")
           or "rendition:layout-pre-paginated" in node.get("properties", "").split()
           for node in root.iter()):
        gaps.append("Fixed-layout EPUB is outside the common reading profile")
    nav = []
    for item in manifests[0]:
        if local(item.tag) != "item":
            continue
        identifier = item.get("id")
        if not identifier or identifier in manifest:
            raise CoverageError("Missing or duplicate manifest identifier")
        props = item.get("properties", "").split()
        try:
            member, fragment = item_url(opf, item.attrib["href"])
        except CoverageError:
            member, fragment = None, ""
        media = item.get("media-type")
        manifest[identifier] = member, media, fragment, item.get("fallback")
        if "nav" in props:
            nav.append((member, "toc"))
        if any(value in props for value in ("scripted", "remote-resources", "mathml", "svg")):
            gaps.append("Manifest advertises capabilities outside the common reading profile")
    spine = []
    for item in spines[0]:
        if local(item.tag) != "itemref":
            continue
        entry = manifest.get(item.get("idref"))
        if not entry:
            gaps.append("Reading order references an unknown manifest item")
            continue
        member, media, fragment, fallback = entry
        if member not in members or media not in MEDIA or fragment or fallback:
            gaps.append("Reading order item is unavailable, unsupported or has a fallback")
            continue
        spine.append(member)
    if not spine:
        gaps.append("Empty supported reading order")
    if len(spine) != len(set(spine)):
        gaps.append("Duplicate spine location")
    if len(nav) > 1:
        gaps.append("Ambiguous EPUB navigation documents")
    if not nav and spines[0].get("toc"):
        nav.append((manifest.get(spines[0].get("toc"), (None,))[0], "ncx"))
    documents = {member for member, media, fragment, fallback in manifest.values()
                 if media in MEDIA and member and not fragment and not fallback}
    return list(dict.fromkeys(spine)), nav, gaps, documents


def inspect(book, engine, limits, options, comparison):
    started = time.monotonic()
    monitor = Monitor({})
    reader = session(engine, monitor)
    # Warm up layout, font selection and page painting before any EPUB bytes
    # are read. Syscalls in this phase have an authenticated reader origin.
    reader.render("control.xhtml", "<html><body>Reader startup control</body></html>").visit(0)
    if comparison:
        # Preserve the original run's step numbers, action types, and number of
        # visible pages. All destinations and renderer input here are synthetic.
        steps = []
        for index, kind, count in options.get("control_itinerary", []):
            trace_marker(f"epub-step-{index}")
            monitor.step = index
            name = f"control-{index}.xhtml"
            monitor.step_member = name
            content = ('<html><body><p id="control">Control '
                       '<a href="#control">internal destination</a></p></body></html>')
            document = reader.render(name, content)
            for _ in range(count):
                document.visit(document.anchors.get("control", 0))
            steps.append({"kind": kind, "member": name, "fragment": "control",
                          "status": "completed", "pages": [1]})
        return {"complete": not monitor.missing, "steps": steps, "gaps": [], "events": monitor.events}
    trace_marker("epub-book")
    with tempfile.TemporaryDirectory(dir="/tmp") as scratch:
        try:
            monitor.members = members = inventory(book, Path(scratch), limits)
        except BookError:
            return {"complete": False, "steps": [], "gaps": ["Verified archive inventory unavailable"], "events": []}
        steps, gaps, external = [], [], 0
        rendered = {}

        def add(kind, member, fragment="", status="completed"):
            trace_marker(f"epub-step-{len(steps)}")
            if len(steps) >= options["max_steps"]:
                raise CoverageError("Navigation step limit exceeded")
            steps.append({"kind": kind, "member": member, "fragment": fragment, "status": status})

        def render(member, step):
            if member not in rendered:
                monitor.step = step
                monitor.step_member = member
                source, links, unsupported = html_document(members[member], engine)
                gaps.extend(unsupported)
                result = reader.render(member, source)
                if not result.pages:
                    gaps.append("Renderer produced no pages")
                rendered[member] = links, result
            return rendered[member]

        try:
            spine, nav, planning, documents = package(members)
            gaps.extend(planning)
            for member in spine:
                index = len(steps)
                add("reading_order", member, status="pending")
                try:
                    _, document = render(member, index)
                    trace_marker(f"epub-step-{index}")
                    monitor.step = index
                    monitor.step_member = member
                    steps[index]["pages"] = [document.visit(page) for page in range(document.pages)]
                except (CoverageError, KeyError, ElementTree.ParseError, UnicodeError, ValueError):
                    gaps.append("Reading-order rendering failed")
                    steps[index]["status"] = "skipped"
                else:
                    steps[index]["status"] = "completed"
            sources = [(member, "internal") for member in spine] + nav
            for member, kind in sources:
                if member not in members:
                    gaps.append("Navigation document is unavailable")
                    continue
                if kind == "ncx":
                    tree = xml(members[member].read_bytes())
                    links = [(node.get("src"), None) for node in tree.iter()
                             if local(node.tag) == "content" and node.get("src")]
                    actual = None
                else:
                    index = len(steps)
                    if kind == "toc":
                        add("toc_document", member, status="pending")
                    try:
                        links, document = render(member, index)
                        actual = document.links
                        if kind == "toc":
                            monitor.step = index
                            monitor.step_member = member
                            steps[index]["pages"] = [document.visit(page) for page in range(document.pages)]
                    except (CoverageError, KeyError, ElementTree.ParseError, UnicodeError, ValueError):
                        gaps.append("Navigation source was not rendered")
                        if kind == "toc":
                            steps[index]["status"] = "skipped"
                        continue
                    if kind == "toc":
                        steps[index]["status"] = "completed"
                if kind in {"ncx", "toc"} and not links:
                    gaps.append("Navigation document contains no links")
                for href, purpose in links:
                    url = urljoin(monitor.url(member), href)
                    address = monitor.address(url)
                    if address is None:
                        external += 1
                        continue
                    target, fragment = address
                    index = len(steps)
                    add(purpose or kind, target, fragment, "pending")
                    try:
                        if (urlsplit(url).query or target not in members or target not in documents
                                or (actual is not None and url not in actual)):
                            raise CoverageError("Link was not exposed by the renderer or target was unavailable")
                        _, document = render(target, index)
                        if fragment and fragment not in document.anchors:
                            raise CoverageError("Destination anchor was not exposed by the renderer")
                        monitor.step = index
                        monitor.step_member = target
                        steps[index]["pages"] = [document.visit(document.anchors.get(fragment, 0))]
                    except (CoverageError, KeyError, ElementTree.ParseError, UnicodeError, ValueError):
                        steps[index]["status"] = "skipped"
                        gaps.append("Internal navigation destination could not be verified")
                    else:
                        steps[index]["status"] = "completed"
        except (CoverageError, KeyError, ElementTree.ParseError, UnicodeError, ValueError):
            gaps.append("Verified navigation plan could not be completed")
        if monitor.missing:
            gaps.append("Renderer dependency unavailable or outside the common profile")
        return {"complete": not gaps, "steps": steps, "gaps": sorted(set(gaps)),
                "external_links_unactivated": external, "events": monitor.events,
                "diagnostics": {"resource_callbacks": monitor.requests,
                                "in_book_dependencies_by_media": dict(monitor.dependencies),
                                "elapsed_ms": round((time.monotonic() - started) * 1000)}}


def implementation_identity(identity):
    """Fingerprint the installed renderer code and participating native libraries."""
    digests = {}
    related = ("libqt5", "/pyqt5/", "libpango", "libfontconfig", "libfreetype", "libharfbuzz",
               "/pil/", "libseccomp", "libcairo", "_cffi_backend")
    files = {Path(line.split()[-1]) for line in Path("/proc/self/maps").read_text().splitlines()
             if len(line.split()) == 6 and line.split()[-1].startswith("/")
             and any(label in line.split()[-1].lower() for label in related)}
    for name in identity.get("packages", {}):
        package = metadata.distribution(name)
        for record in package.files or ():
            if (record.parts[0] != ".." and "__pycache__" not in record.parts
                    and record.suffix in {".py", ".so", ".css", ".otf", ".ttf"}):
                path = Path(package.locate_file(record))
                if path.is_file():
                    files.add(path)
    stamp = hashlib.sha256()
    for path in sorted(files):
        if path.is_file():
            with path.open("rb") as source:
                digests[str(path)] = hashlib.file_digest(source, "sha256").hexdigest()
    for path, fingerprint in digests.items():
        stamp.update((path + ":" + fingerprint + "\n").encode())
    return stamp.hexdigest()


def health(engine, host_net, book, host_probe, marker_paths=None):
    monitor = Monitor({})
    reader = session(engine, monitor)
    monitor.step = 0
    monitor.step_member = "health.xhtml"
    control = reader.render("health.xhtml",
        '<html><body><p><a name="landmark" id="landmark">Rendered control</a> '
        '<a href="#landmark">Jump</a><img src="https://health.invalid/probe"> '
        '<img src="file:///missing-control"></p></body></html>')
    read_only = False
    try:
        with open(book, "r+b"):
            pass
    except OSError:
        read_only = True
    for path in (host_probe, *(marker_paths or {}).values()):
        try:
            with open(path, "rb"):
                raise RuntimeError("Private host control is visible in reader")
        except FileNotFoundError:
            pass
    # Test TCP and UDP independently: the kernel seccomp policy denies socket().
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            with socket.socket(socket.AF_INET, kind):
                raise RuntimeError("Socket creation permitted in reader")
        except PermissionError:
            pass
    try:
        subprocess.run(["/usr/bin/python3", "-V"], check=True, capture_output=True)
        raise RuntimeError("Process dispatch permitted in reader")
    except PermissionError:
        pass
    if (not read_only or os.readlink("/proc/self/ns/net") == host_net
            or "landmark" not in control.anchors or monitor.url("health.xhtml") + "#landmark" not in control.links
            or not control.visit(control.anchors["landmark"]) or {item["action"] for item in monitor.events} != {
                "outbound_request", "out_of_book_read"
            }):
        raise RuntimeError("Reader or monitor positive control failed")
    identity = reader.identity
    identity["implementation_sha256"] = implementation_identity(identity)
    return {"ready": True, "identity": identity, "monitor": "renderer-callback+strace+seccomp-v1"}


def restrict():
    """Deny network creation and process dispatch after loading the trusted Python worker."""
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7fff0000)
    if not context:
        raise RuntimeError("Seccomp initialization failed")
    try:
        for name in (b"socket", b"socketpair", b"connect", b"sendto", b"sendmsg", b"sendmmsg",
                     b"execve", b"execveat", b"io_uring_setup", b"open_by_handle_at"):
            syscall = lib.seccomp_syscall_resolve_name(name)
            if syscall < 0 or lib.seccomp_rule_add(context, 0x00050000 | errno.EPERM, syscall, 0):
                raise RuntimeError("Seccomp rule installation failed")
        if lib.seccomp_load(context):
            raise RuntimeError("Seccomp enforcement failed")
    finally:
        lib.seccomp_release(context)


def main():
    engine, mode, host_net, limits, options, host_probe = sys.argv[1:]
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024,) * 2)
    restrict()
    os.mkdir("/tmp/runtime", 0o700)
    trace_marker("epub-monitor-on")
    book = "/input/book.epub"
    result = health(engine, host_net, book, host_probe, json.loads(options).get("marker_paths")) if mode == "health" else inspect(
        book, engine, json.loads(limits), json.loads(options), mode == "comparison")
    trace_marker("epub-monitor-ok")
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
