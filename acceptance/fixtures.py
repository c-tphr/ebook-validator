"""Small generated EPUB 3 inputs. All links are inert, including remote references."""

from pathlib import Path
from zipfile import ZipFile, ZIP_STORED

OPF = """<package xmlns="http://www.idpf.org/2007/opf" unique-identifier="pub" version="3.0" xml:lang="en">
<metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:identifier id="pub">urn:example:small</dc:identifier><dc:title>Example</dc:title><dc:language>en</dc:language><meta property="dcterms:modified">2025-01-01T00:00:00Z</meta></metadata>
<manifest><item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/><item id="text" href="text.xhtml" media-type="application/xhtml+xml"/>{extra}</manifest>
<spine><itemref idref="text"/></spine></package>"""
CONTAINER = """<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="book.opf" media-type="application/oebps-package+xml"/></rootfiles></container>"""
DOC = """<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops" xml:lang="en"><head><title>Page</title></head><body>{}</body></html>"""
BODY = {
    "click": '<a href="https://example.invalid/">Read more</a>',
    "remote": '<img src="https://example.invalid/cover.png" alt="Cover"/>',
    "script": '<script type="text/javascript">void 0</script>',
    "both": '<script type="text/javascript">void 0</script>',
    "heuristic": "<p>"
    + ("Long stretches of legible prose separated by the replacement character �. " * 100)
    + "</p>",
}


def book(path: Path, kind="clean"):
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "corrupt":
        path.write_bytes(b"Incomplete copy of an electronic publication")
        return
    extra = (
        '<item id="absent" href="absent.xhtml" media-type="application/xhtml+xml"/>'
        if kind == "manifest"
        else ""
    )
    fragment = "absent" if kind in {"nav", "both"} else "start"
    nav = (
        '<nav epub:type="toc"><h1>Contents</h1><ol><li><a href="text.xhtml#'
        + fragment
        + '">Chapter one</a></li></ol></nav>'
    )
    with ZipFile(path, "w", compression=ZIP_STORED) as archive:
        archive.writestr("mimetype", "application/epub+zip")
        archive.writestr("META-INF/container.xml", CONTAINER)
        archive.writestr("book.opf", OPF.format(extra=extra))
        archive.writestr("nav.xhtml", DOC.format(nav))
        archive.writestr(
            "text.xhtml",
            DOC.format('<h1 id="start">Chapter one</h1>' + BODY.get(kind, "<p>A quiet page.</p>")),
        )
        if kind == "unsafe":
            archive.writestr("../misplaced.txt", "benign bytes")
        if kind == "unlisted":
            archive.writestr("unused.xhtml", DOC.format(BODY["remote"]))
