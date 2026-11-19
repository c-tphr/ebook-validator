"""Small benign EPUB reading itineraries for behavioral acceptance."""

from pathlib import Path
from zipfile import ZipFile, ZipInfo

from acceptance.fixtures import CONTAINER, DOC, OPF

CITATION = "https://citation.invalid/ordinary?secret=unselected-citation"
IMAGE = "https://image.invalid/synthetic-cover.png?token=sensitive-canary"
FILE = "file:///outside/synthetic-v4-canary.png"


def make_book(path, *, image=None, missing=False, fixed=False, background=False):
    """Write a deterministic two-chapter EPUB with a TOC and a footnote."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    opf = OPF.format(
        extra='<item id="two" href="two.xhtml" media-type="application/xhtml+xml"/>'
    )
    opf = opf.replace("</spine>", '<itemref idref="two"/></spine>')
    if fixed:
        opf = opf.replace(
            "</metadata>",
            '<meta property="rendition:layout">pre-paginated</meta></metadata>',
        )
    contents = '<nav epub:type="toc"><ol><li><a href="text.xhtml#one">First</a></li><li><a href="two.xhtml#two">Second</a></li></ol></nav>'
    target = "missing" if missing else "note"
    first = (
        f'<h1 id="one">First chapter</h1><p>A passage with a <a epub:type="noteref" id="mark" '
        f'href="two.xhtml#{target}">note</a>.</p><a href="{CITATION}">External citation</a>'
    )
    if image:
        first += (
            f'<p><img src="{image}" width="24" height="24" alt="Acceptance image"/></p>'
        )
    second = (
        '<h1 id="two">Second chapter</h1><aside epub:type="footnote" id="note">'
        '<p>Footnote text. <a epub:type="backlink" href="text.xhtml#mark">Back</a></p></aside>'
    )
    entries = {
        "mimetype": "application/epub+zip",
        "META-INF/container.xml": CONTAINER,
        "book.opf": opf,
        "nav.xhtml": DOC.format(contents),
        "text.xhtml": DOC.format(first),
        "two.xhtml": DOC.format(second),
    }
    if background:
        css = '<style>aside { background-image: url("' + IMAGE + '"); }</style>'
        entries["two.xhtml"] = entries["two.xhtml"].replace("</head>", css + "</head>")
    with ZipFile(path, "w") as out:
        for name, data in entries.items():
            out.writestr(ZipInfo(name, (2025, 1, 1, 0, 0, 0)), data)
    return path
