"""Benign, deterministic EPUB fixtures for the independent v2 checks."""

import base64
import hashlib
from pathlib import Path
import subprocess
import tempfile

from lxml import etree
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

from acceptance.fixtures import BODY, CONTAINER, DOC, OPF

OPF2 = """<package xmlns="http://www.idpf.org/2007/opf" unique-identifier="PUB" version="2.0">
<metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:identifier id="pub">urn:example:one</dc:identifier><dc:title>Edition one</dc:title><dc:language>en</dc:language></metadata>
<manifest><item id="toc" href="toc.ncx" media-type="application/x-dtbncx+xml"/><item id="text" href="text.xhtml" media-type="application/xhtml+xml"/></manifest><spine toc="toc"><itemref idref="text"/></spine></package>"""
NCX = """<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1"><head><meta name="dtb:uid" content="{}"/></head><docTitle><text>Edition one</text></docTitle><navMap><navPoint id="one" playOrder="1"><navLabel><text>Chapter one</text></navLabel><content src="text.xhtml"/></navPoint></navMap></ncx>"""


def write_book(
    path,
    *,
    layout=False,
    case=False,
    ambiguous=False,
    metadata=None,
    warning=False,
    signed=False,
    stale_fragment=False,
    competing=False,
):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ref = (
        ("Text" if case else "text")
        + ".xhtml#"
        + ("absent" if stale_fragment else "start")
    )
    nav = DOC.format(
        '<nav epub:type="toc"><h1>Contents</h1><ol><li><a href="'
        + ref
        + '">Chapter one</a></li></ol></nav>'
    )
    entries = {"mimetype": "application/epub+zip", "META-INF/container.xml": CONTAINER}
    body = '<h1 id="start">Chapter one</h1>' + (
        BODY["heuristic"] if warning else "<p>Original text.</p>"
    )
    if metadata is None:
        extra = (
            '<item id="separate-chapter" href="Text.xhtml" media-type="application/xhtml+xml"/>'
            if competing
            else ""
        )
        entries.update(
            {
                "book.opf": OPF.format(extra=extra),
                "nav.xhtml": nav,
                "text.xhtml": DOC.format(body),
            }
        )
    else:
        entries.update(
            {
                "book.opf": OPF2,
                "toc.ncx": NCX.format(metadata),
                "text.xhtml": DOC.format(body),
            }
        )
    if ambiguous:
        entries["TEXT.xhtml"] = DOC.format(body)
    if signed:
        entries["META-INF/signatures.xml"] = signed_nav(nav.encode())
    if layout:
        entries["mimetype"] = entries.pop("mimetype")
    with ZipFile(path, "w") as archive:
        for name, data in entries.items():
            info = ZipInfo(name, (2024, 1, 2, 3, 4, 6))
            info.compress_type = (
                ZIP_DEFLATED if layout and name == "mimetype" else ZIP_STORED
            )
            archive.writestr(info, data.encode())
    return path


def signed_nav(payload):
    """Sign the navigation member with an ephemeral fixture key and verify the signature."""
    ds = "http://www.w3.org/2000/09/xmldsig#"
    digest = base64.b64encode(hashlib.sha256(payload).digest()).decode()
    tree = etree.fromstring(
        f"""<signatures xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
<ds:Signature xmlns:ds="{ds}" Id="example"><ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="nav.xhtml"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>
<ds:SignatureValue/></ds:Signature></signatures>""".encode()
    )
    data = etree.tostring(
        tree.find(".//{%s}SignedInfo" % ds), method="c14n", exclusive=True
    )
    with tempfile.TemporaryDirectory() as tmp:
        key, pub, sig = (Path(tmp) / name for name in ("key", "pub", "sig"))

        def run(*args, **kwargs):
            return subprocess.run(
                ["openssl", *args], capture_output=True, check=True, **kwargs
            )

        run(
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key,
        )
        run("pkey", "-in", key, "-pubout", "-out", pub)
        run("dgst", "-sha256", "-sign", key, "-out", sig, input=data)
        run("dgst", "-sha256", "-verify", pub, "-signature", sig, input=data)
        tree.find(".//{%s}SignatureValue" % ds).text = base64.b64encode(
            sig.read_bytes()
        ).decode()
    return etree.tostring(tree, encoding="unicode")
