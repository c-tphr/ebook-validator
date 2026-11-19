"""Static policy for physical EPUB resources and reader-facing navigation."""

import hashlib
from pathlib import PurePosixPath
import posixpath
import re
from urllib.parse import quote, unquote, urljoin, urlsplit

from lxml import etree
import tinycss2

from .archive import BookError


XML_EXT = {".xml", ".opf", ".ncx", ".xhtml", ".html", ".htm", ".svg", ".smil", ".pls", ".xpgt"}
XML_TYPES = {"application/xhtml+xml", "image/svg+xml", "application/x-dtbncx+xml",
             "application/smil+xml", "text/html", "application/xml", "text/xml"}
DOCUMENT_ROOTS = {
    "html", "svg", "smil", "ncx", "package", "container", "metadata", "encryption",
    "signatures", "rights", "display_options", "plist", "lexicon",
}
ACTIVE_ELEMENTS = {"applet", "handler", "binding", "bindings", "trigger"}
INERT_SCRIPT_TYPES = {"application/json", "application/ld+json", "text/plain"}
FETCH_ATTRS = {"src", "srcset", "imagesrcset", "poster", "background", "data", "codebase",
               "archive", "classid", "lowsrc", "dynsrc", "profile", "manifest", "ping", "icon"}
CSS_ATTRIBUTES = {"fill", "stroke", "filter", "mask", "clip-path", "marker", "marker-start",
                  "marker-mid", "marker-end", "cursor", "color-profile"}
LINK_FETCH = {"stylesheet", "alternate", "preload", "modulepreload", "prefetch", "prerender",
              "preconnect", "dns-prefetch", "icon", "apple-touch-icon", "manifest"}
XML_BASE = "{http://www.w3.org/XML/1998/namespace}base"
SAFE_DOCTYPE = re.compile(
    r"""<!DOCTYPE\s+(?P<root>html|ncx|package)(?:\s+PUBLIC\s+(?P<q>["'])"""
    r"""(?P<public>[^"']+)(?P=q)\s+(?P<sq>["'])(?P<system>[^"']+)(?P=sq))?\s*>""",
    re.IGNORECASE,
)
KNOWN_DTDS = {
    ("html", "-//W3C//DTD XHTML 1.1//EN"): {"www.w3.org/TR/xhtml11/DTD/xhtml11.dtd"},
    ("html", "-//W3C//DTD XHTML 1.0 Strict//EN"): {"www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"},
    ("html", "-//W3C//DTD XHTML 1.0 Transitional//EN"): {"www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"},
    ("ncx", "-//NISO//DTD ncx 2005-1//EN"): {"www.daisy.org/z3986/2005/ncx-2005-1.dtd"},
    ("package", "-//OEBPS//DTD OEB 1.2 Package//EN"): {"openebook.org/dtds/oeb-1.2/oebpkg12.dtd"},
}
PASSIVE_TYPES = {
    "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif", "image/webp": ".webp",
    "font/ttf": ".ttf", "application/x-font-ttf": ".ttf", "font/otf": ".otf",
    "application/vnd.ms-opentype": ".otf", "application/x-font-opentype": ".otf",
    "font/woff": ".woff", "application/font-woff": ".woff", "font/woff2": ".woff2",
    "audio/mpeg": ".mp3", "audio/mp4": ".m4a", "video/mp4": ".mp4",
    "audio/ogg": ".ogg", "video/ogg": ".ogg", "application/ogg": ".ogg",
    "audio/wav": ".wav", "audio/x-wav": ".wav",
}


def local(name):
    return name.rsplit("}", 1)[-1].lower()


def finding(kind, code, detail, member=None):
    result = {"kind": kind, "code": code, "detail": detail}
    if member is not None:
        result["member"] = member
    return result


def markup(data, name):
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True,
                             recover=False, huge_tree=False)
    try:
        root = etree.fromstring(data, parser)
    except etree.XMLSyntaxError as error:
        raise BookError("markup_unreadable", f"XML inspection failed at line {error.lineno}", name) from error
    info = root.getroottree().docinfo
    if info.doctype:
        # Check the original declaration because libxml's reconstructed doctype omits subsets.
        try:
            decoded = data.decode(info.encoding)
        except (LookupError, UnicodeError) as error:
            raise BookError("markup_encoding", "Cannot verify XML document declaration", name) from error
        match = SAFE_DOCTYPE.search(decoded)
        if (not match or len(re.findall(r"<!DOCTYPE\b", decoded, re.I)) != 1
                or match["root"] != info.root_name
                or any(isinstance(node, etree._Entity) for node in root.iter())):
            raise BookError("unsafe_xml_declaration", "Unsupported XML doctype or entity", name)
        if match["public"]:
            scheme, _, address = match["system"].partition("://")
            if scheme not in {"http", "https"} or address not in KNOWN_DTDS.get((match["root"], match["public"]), set()):
                raise BookError("unsafe_xml_declaration", "Unrecognized external XML doctype", name)
    return root


def passive(data, extension):
    if extension in {".jpg", ".jpeg"}:
        return data.startswith(b"\xff\xd8\xff") and data.endswith(b"\xff\xd9")
    if extension == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n") and data.endswith(b"IEND\xaeB\x60\x82")
    if extension == ".gif":
        return data.startswith((b"GIF87a", b"GIF89a")) and data.endswith(b";")
    if extension == ".webp":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP" and int.from_bytes(data[4:8], "little") + 8 == len(data)
    if extension in {".ttf", ".otf", ".woff", ".woff2"}:
        return data.startswith({".ttf": b"\x00\x01\x00\x00", ".otf": b"OTTO",
                               ".woff": b"wOFF", ".woff2": b"wOF2"}[extension])
    if extension == ".mp3":
        return data.startswith(b"ID3") or (len(data) > 2 and data[0] == 255 and data[1] & 0xE0 == 0xE0)
    if extension in {".mp4", ".m4a", ".m4v"}:
        return len(data) >= 12 and data[4:8] == b"ftyp"
    if extension == ".ogg":
        return data.startswith(b"OggS\x00")
    if extension == ".wav":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE" and int.from_bytes(data[4:8], "little") + 8 == len(data)
    return False


class Content:
    def __init__(self, members, occurrences=False):
        self.members = members
        self.occurrences = occurrences
        self.documents = {}
        self.declared = {}
        self.security = []
        self.quality = []

    def add(self, kind, code, detail, name, location=None, diagnostic=None):
        output = self.quality if kind in {"verified", "heuristic"} else self.security
        value = finding(kind, code, detail, name)
        if self.occurrences:
            if location is not None:
                value["location"] = location
            if diagnostic is not None:
                value["diagnostic_sha256"] = hashlib.sha256(diagnostic.encode()).hexdigest()
        if (self.occurrences or value not in output) and len(output) < 100:
            output.append(value)
        elif len(output) == 100:
            output.append(finding("incomplete" if output is self.security else "heuristic",
                                  "findings_capped", "Additional findings exceeded the reporting limit"))

    def reference(self, value, name, base, context, mode="fetch"):
        # Apply URL preprocessing before inspecting the scheme.
        value = value.strip("".join(map(chr, range(33)))).translate({9: None, 10: None, 13: None})
        if not value:
            return None
        if "\\" in value:
            self.add("incomplete", "ambiguous_url", f"Backslash in {context}", name)
            return None
        try:
            value_parts = urlsplit(value)
            scheme = value_parts.scheme.lower()
            if scheme in {"javascript", "vbscript"}:
                self.add("active", "script_url", f"Executable URL in {context}", name)
                return None
            if mode == "base" and (scheme or value_parts.netloc or value.startswith("//")):
                self.add("incomplete", "external_base", f"External base URI in {context}", name)
                return value
            absolute = urljoin(base, value)
            parts = urlsplit(absolute)
            if parts.scheme in {"http", "https"} and (parts.netloc != "epub.invalid" or
                                                     scheme or value.startswith("//")
                                                     or urlsplit(base).netloc != "epub.invalid"):
                if mode == "fetch":
                    self.add("remote", "automatic_remote_resource", f"Remote URL in {context}", name)
                return None
            if mode == "click" and parts.scheme in {"mailto", "tel"}:
                return absolute
            if parts.scheme != "https" or parts.netloc != "epub.invalid":
                self.add("incomplete", "unsupported_url", f"Unsupported URL scheme in {context}", name)
                return None
            # Synthetic-origin paths are never opened on the host.
            return absolute
        except ValueError:
            self.add("incomplete", "ambiguous_url", f"Unparseable URL in {context}", name)
            return None

    def css(self, nodes, name, base):
        work = list(reversed(nodes))
        while work:
            token = work.pop()
            typ = token.type
            if typ == "error":
                self.add("incomplete", "css_parse", "Unparseable CSS token", name)
            elif typ == "url":
                self.reference(token.value, name, base, "CSS url()")
            elif typ == "at-keyword" and token.lower_value == "import":
                self.add("incomplete", "css_import_context", "Invalid nested CSS import context", name)
            elif typ == "function":
                meaningful = [arg for arg in token.arguments if arg.type not in {"whitespace", "comment"}]
                function = token.lower_name
                if function == "url":
                    if len(meaningful) == 1 and meaningful[0].type == "string":
                        self.reference(meaningful[0].value, name, base, "CSS url()")
                    else:
                        self.add("incomplete", "css_url", "Dynamic or invalid CSS URL", name)
                elif function in {"image-set", "-webkit-image-set", "image", "src"}:
                    for arg in meaningful:
                        if arg.type == "string":
                            self.reference(arg.value, name, base, f"CSS {function}()")
                elif function == "expression":
                    self.add("active", "css_expression", "Executable CSS expression()", name)
                elif function in {"var", "attr"}:
                    self.add("incomplete", "dynamic_css", f"Unsupported dynamic CSS {function}()", name)
                work.extend(reversed(token.arguments))
            elif typ == "ident" and token.lower_value in {"behavior", "-moz-binding"}:
                self.add("active", "css_binding", "Executable CSS behavior or binding", name)
            elif hasattr(token, "content") and token.content is not None:
                self.css(token.content, name, base)

    def inspect_document(self, root, name):
        base = "https://epub.invalid/" + quote(name)
        doc = root.getroottree()
        for instruction in doc.xpath("//processing-instruction()"):
            self.add("incomplete", "xml_processing_instruction",
                     f"Unsupported processing instruction {instruction.target}", name)
            if instruction.target.lower() == "xml-stylesheet":
                match = re.search(r"""\bhref\s*=\s*(['"])(.*?)\1""", instruction.text or "")
                if match:
                    self.reference(match[2], name, base, "XML stylesheet")
        if local(root.tag) not in DOCUMENT_ROOTS:
            self.add("incomplete", "unknown_xml", "Unsupported XML resource vocabulary", name)
        for element in root.iter():
            if isinstance(element.tag, str) and local(element.tag) == "base" and element.get("href"):
                base = self.reference(element.get("href"), name, base, "HTML base", "base") or base
                break
        effective_base = {}
        navigation = []
        for element in root.iter():
            if not isinstance(element.tag, str):
                continue
            tag = local(element.tag)
            element_base = effective_base.get(element.getparent(), base)
            if element.get(XML_BASE):
                element_base = self.reference(element.get(XML_BASE), name, element_base,
                                              "xml:base", "base") or element_base
            effective_base[element] = element_base
            if tag == "script":
                script_type = element.get("type", "").lower().partition(";")[0].strip()
                source = any(local(attr) in {"src", "href"} and value.strip()
                             for attr, value in element.attrib.items())
                if source or (script_type not in INERT_SCRIPT_TYPES and "".join(element.itertext()).strip()):
                    self.add("active", "active_element", "Executable <script> element", name)
            if tag in ACTIVE_ELEMENTS:
                self.add("active", "active_element", f"Executable or active <{tag}> element", name)
            if element.tag == "{http://www.w3.org/2001/XInclude}include":
                self.add("incomplete", "xml_include", "Unsupported XML inclusion", name)
            if tag in {"animate", "set", "animatetransform", "animatemotion"}:
                self.add("incomplete", "svg_animation", "Dynamic SVG attributes require further inspection", name)
            if tag in {"foreignobject", "embed", "iframe", "object"}:
                self.add("incomplete", "embedded_content", f"Unsupported embedded <{tag}> context", name)
            if tag == "meta" and element.get("http-equiv", "").strip().lower() == "refresh":
                match = re.search(r"""(?:^|[;,])\s*(?:url\s*=\s*)?(.+)$""", element.get("content", ""))
                if match and re.search(r"[;,]", element.get("content", "")):
                    target = re.split(r"[;,]", element.get("content", ""), maxsplit=1)[1]
                    self.reference(re.sub(r"^\s*url\s*=\s*", "", target, flags=re.I).strip().strip("'\""),
                                   name, element_base, "HTML refresh")
                self.add("active", "automatic_navigation", "HTML meta refresh", name)
            if tag == "style":
                self.css(tinycss2.parse_component_value_list("".join(element.itertext())), name, element_base)
            for qualified, value in element.attrib.items():
                attr = local(qualified)
                if qualified == XML_BASE:
                    continue
                if attr.startswith("on") and value.strip():
                    self.add("active", "event_handler", f"Event handler {attr} on <{tag}>", name)
                elif attr == "srcdoc":
                    self.add("incomplete", "embedded_markup", "Unsupported embedded srcdoc document", name)
                elif attr == "style" or attr in CSS_ATTRIBUTES:
                    self.css(tinycss2.parse_component_value_list(value), name, element_base)
                elif attr in {"srcset", "imagesrcset"}:
                    for candidate in value.split(","):
                        tokens = candidate.split()
                        if tokens:
                            self.reference(tokens[0], name, element_base, f"{tag}[{attr}]")
                elif tag == "content" and attr == "src" and local(root.tag) == "ncx":
                    target = self.reference(value, name, element_base, "NCX target", "click")
                    if target:
                        navigation.append((target, doc.getelementpath(element) + "/@src"))
                elif attr in FETCH_ATTRS and not (attr == "data" and tag != "object"):
                    for candidate in value.split() if attr in {"ping", "archive"} else [value]:
                        self.reference(candidate, name, element_base, f"{tag}[{attr}]")
                elif attr in {"href", "action", "formaction"} and tag != "base":
                    if tag == "link" and attr == "href" and not (
                        LINK_FETCH & set(element.get("rel", "").lower().split())
                    ):
                        continue
                    if tag in {"a", "area", "form", "button", "input"}:
                        mode = "click"
                    elif tag in {"meta", "reference"} and local(root.tag) == "package":
                        mode = "click"
                    else:
                        mode = "fetch"
                    result = self.reference(value, name, element_base, f"{tag}[{attr}]", mode)
                    if result and tag == "a" and any(local(parent.tag) == "nav" for parent in element.iterancestors()):
                        navigation.append((result, doc.getelementpath(element) + "/@href"))
                elif attr == "uri" and tag in {"cipherreference", "retrievalmethod"}:
                    self.reference(value, name, element_base, f"{tag}[{attr}]")
            if tag == "item" and local(root.tag) == "package" and element.get("href"):
                target = self.reference(element.get("href"), name, element_base, "OPF manifest item")
                item_path = self.member_name(target)
                if item_path is not None:
                    media_type = element.get("media-type", "").strip().lower()
                    self.declared.setdefault(item_path, set()).add(media_type)
                    if item_path not in self.members:
                        self.add("verified", "missing_manifest_resource", f"Manifest resource {item_path} is absent", name, doc.getelementpath(element) + "/@href")
            if tag in {"encrypteddata", "encryptionmethod"}:
                self.add("incomplete", "encrypted_content", "EPUB declares encrypted or obfuscated content", name)
        return navigation

    @staticmethod
    def member_name(target):
        if target is None:
            return None
        url = urlsplit(target)
        if url.netloc != "epub.invalid":
            return None
        return posixpath.normpath(unquote(url.path).lstrip("/"))

    def inspect(self):
        try:
            self.inspect_members()
        except RecursionError:
            self.add("incomplete", "static_parser_limit", "Static parser nesting exceeded its limit", None)

    def inspect_members(self):
        navigation = {}
        handled = set()
        # Discover declarations independently from OPF validity or manifest membership.
        for name, path in self.members.items():
            ext = PurePosixPath(name).suffix.lower()
            with path.open("rb") as stream:
                head = stream.read(512)
            looks_xml = (head.lstrip(b"\xef\xbb\xbf \t\n\r").startswith(b"<")
                         or head.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00<", b"<\x00")))
            if ext in XML_EXT or looks_xml:
                self.parse_document(name, path, navigation)
                handled.add(name)
        for name, path in self.members.items():
            ext = PurePosixPath(name).suffix.lower()
            declared = self.declared.get(name, set())
            script = ext in {".js", ".mjs", ".cjs"} or any(
                "javascript" in value or "ecmascript" in value for value in declared
            )
            if script:
                self.add("active", "script_resource", "Executable script resource", name)
            if (declared & XML_TYPES or any(value.endswith("+xml") for value in declared)) and name not in handled:
                self.parse_document(name, path, navigation)
                handled.add(name)
            data = path.read_bytes()
            if ext == ".css" or "text/css" in declared:
                tokens, _ = tinycss2.parse_stylesheet_bytes(data, skip_comments=True, skip_whitespace=True)
                for rule in tokens:
                    if rule.type == "error":
                        self.add("incomplete", "css_parse", "Unparseable stylesheet", name)
                    else:
                        base = "https://epub.invalid/" + quote(name)
                        if not (rule.type == "at-rule" and rule.lower_at_keyword in {"namespace", "supports"}):
                            self.css(rule.prelude, name, base)
                        self.css(rule.content or [], name, base)
                        if rule.type == "at-rule" and rule.lower_at_keyword == "import":
                            for token in rule.prelude:
                                if token.type == "string":
                                    self.reference(token.value, name, base, "CSS @import")
                handled.add(name)
            declared_passive = False
            for value in sorted(declared - {""}):
                if value in PASSIVE_TYPES:
                    if passive(data, PASSIVE_TYPES[value]):
                        declared_passive = True
                    else:
                        self.add("incomplete", "media_type_mismatch", f"Content does not match declared {value}"[:200], name)
                elif (value not in XML_TYPES and not value.endswith("+xml") and value != "text/css"
                      and "javascript" not in value and "ecmascript" not in value):
                    self.add("incomplete", "unsupported_media_type", f"Unsupported declared media type {value}"[:200], name)
            if name not in handled and not (script or name == "mimetype" or declared_passive or passive(data, ext)):
                self.add("incomplete", "unsupported_resource", "Unclassified resource or unsupported media encoding", name)
            if name == "mimetype" and data != b"application/epub+zip":
                if re.fullmatch(rb"[a-zA-Z0-9/+.-]{1,128}\s*", data):
                    self.add("verified", "invalid_mimetype", "Invalid EPUB mimetype content", name)
                else:
                    self.add("incomplete", "unsupported_resource", "Unexpected bytes in EPUB mimetype", name)
        for name, targets in navigation.items():
            for target, location in targets:
                member = self.member_name(target)
                if member is None:
                    continue
                fragment = unquote(urlsplit(target).fragment)
                if member not in self.members:
                    self.add("verified", "broken_navigation_target", f"Missing navigation document {member}", name, location)
                elif fragment and member in self.documents and fragment not in self.documents[member]:
                    if not fragment.startswith(("epubcfi(", "t=", "xywh=")):
                        self.add("verified", "broken_navigation_fragment", f"Missing navigation fragment {fragment[:160]}", name, location, fragment)

    def parse_document(self, name, path, navigation):
        try:
            root = markup(path.read_bytes(), name)
        except BookError as error:
            self.add(error.kind, error.code, str(error), name)
            return
        navigation[name] = self.inspect_document(root, name)
        self.documents[name] = {value for element in root.iter() if isinstance(element.tag, str)
                                for attr, value in element.attrib.items()
                                if local(attr) == "id" or (local(element.tag) == "a" and local(attr) == "name")}
        if local(root.tag) == "html":
            prose = " ".join(root.itertext())
            if prose.count("\ufffd") >= 3:
                self.add("heuristic", "suspected_ocr_corruption", "At least three Unicode replacement characters", name)
