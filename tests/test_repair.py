"""Focused repair checks for ZIP preservation and acceptance identity."""

import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

from acceptance.v2_fixtures import write_book
from epub_triage import worker
from epub_triage.archive import inventory
from epub_triage.cli import DEFAULT_LIMITS
from epub_triage.repair import accept
from epub_triage.content import Content
from epub_triage.repair_rules import Layout, broader, plan


LIMITS = {key: bounds[0] for key, bounds in DEFAULT_LIMITS.items()}


class RepairMountTests(unittest.TestCase):
    def test_sealed_candidate_requires_read_only_mount_even_when_write_open_is_denied(self):
        candidate = Path("/input/book.epub")
        with (patch.object(worker.os, "readlink", return_value="net:[worker]"),
              patch.object(worker.socket, "if_nameindex", return_value=[(1, "lo")]),
              patch.object(worker, "Path", return_value=SimpleNamespace(exists=lambda: False)),
              patch.object(worker.os, "statvfs") as mount,
              patch.object(worker.os, "open", side_effect=PermissionError(errno.EACCES, "sealed")) as write_open):
            mount.return_value = SimpleNamespace(f_flag=0)
            with self.assertRaisesRegex(RuntimeError, "Input mount is writable"):
                worker.mount_probe("net:[host]", candidate)
            write_open.assert_not_called()

            mount.return_value = SimpleNamespace(f_flag=os.ST_RDONLY)
            result = worker.mount_probe("net:[host]", candidate)
            self.assertTrue(result["read_only"])
            self.assertTrue(result["offline"])
            write_open.assert_called_once_with(candidate, os.O_WRONLY)


class RepairRulesTests(unittest.TestCase):
    def test_raw_zip_records_and_archive_comment_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source, candidate = base / "original.epub", base / "fixed.epub"
            member = ZipInfo("data", (2001, 2, 3, 4, 5, 6))
            member.comment = b"member comment"
            member.extra = b"\x55\x54\x05\x00\x01\x00\x00\x00\x00"
            member.external_attr = 0o100640 << 16
            with ZipFile(source, "w") as archive:
                archive.comment = b"archive comment"
                archive.writestr(member, b"unchanged bytes", ZIP_DEFLATED)
                archive.writestr("mimetype", b"application/epub+zip", ZIP_DEFLATED)
            result = plan(source, LIMITS, "mechanical", base, candidate)
            self.assertTrue(result["built"], result)
            with ZipFile(candidate) as after, ZipFile(source) as before:
                self.assertEqual(after.comment, before.comment)
                self.assertEqual(after.namelist(), ["mimetype", "data"])
                self.assertEqual(after.getinfo("mimetype").compress_type, ZIP_STORED)
                original = before.getinfo("data")
                changed = after.getinfo("data")
                for field in ("comment", "extra", "external_attr", "date_time", "compress_type"):
                    self.assertEqual(getattr(original, field), getattr(changed, field))

    def test_edited_xml_content_must_match_the_exact_approved_byte_spans(self):
        real_build = Layout.build

        def faulty_build(layout, candidate, members, edits):
            real_build(layout, candidate, members, edits)
            damaged = candidate.with_name("damaged.epub")
            with ZipFile(candidate) as valid, ZipFile(damaged, "w") as corrupt:
                for item in valid.infolist():
                    data = valid.read(item)
                    if item.filename == "nav.xhtml":
                        data = data.replace(b"Chapter one", b"Chapter two")
                    corrupt.writestr(item, data)
            damaged.replace(candidate)

        with tempfile.TemporaryDirectory() as tmp, patch.object(Layout, "build", faulty_build):
            base = Path(tmp)
            archive = write_book(base / "book.epub", case=True)
            candidate = base / "candidate.epub"
            result = plan(archive, LIMITS, "broader", base, candidate)
            self.assertFalse(result["built"])
            self.assertIn("payload failed byte preservation", result["rejected"])

    def test_separate_manifest_declaration_blocks_case_retargeting(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = write_book(base / "book.epub", case=True)
            target = base / "members"
            target.mkdir()
            members = inventory(archive, target, LIMITS)
            self.assertEqual([edit["rule"] for edit in broader(members)], ["R1"])
            manifest = members["book.opf"]
            original = manifest.read_bytes()
            manifest.write_bytes(original.replace(
                b"</manifest>",
                b'<item id="other-chapter" href="Text.xhtml" media-type="application/xhtml+xml"/></manifest>',
            ))
            self.assertEqual(broader(members), [])


class RepairAcceptanceTests(unittest.TestCase):
    def test_omitted_epubcheck_occurrences_block_repair(self):
        diagnostic = {"ID": "RSC-007", "severity": "ERROR", "message": "Missing resource",
                      "locations": [{"path": "nav.xhtml", "line": 3, "column": 4}],
                      "additionalLocations": 2}
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "conformance.json"
            report.write_text(json.dumps({"messages": [diagnostic]}))
            with patch.object(worker, "Path", return_value=report), patch.object(
                worker, "java_check", return_value=(1, "")
            ):
                repair = Content({}, occurrences=True)
                worker.quality_check(Path("book.epub"), repair)
                ordinary = Content({})
                worker.quality_check(Path("book.epub"), ordinary)
        self.assertEqual([issue["code"] for issue in ordinary.quality], ["RSC-007"])
        self.assertEqual([issue["code"] for issue in repair.quality], ["RSC-007", "findings_capped"])
        self.assertEqual(repair.quality[0]["location"], [3, 4])

    @staticmethod
    def report(findings):
        return {"security": {"complete": True, "findings": []},
                "quality": {"complete": True, "findings": findings}}

    def test_equal_code_and_text_at_different_node_rejected(self):
        mime = {"kind": "verified", "code": "repair_mimetype_layout", "member": "mimetype",
                "detail": "Invalid layout"}
        old = {"kind": "verified", "code": "RSC-007", "member": "nav.xhtml", "detail": "Broken link",
               "location": [12, 2]}
        new = {**old, "location": [14, 2]}
        edit = {"rule": "M1", "finding_codes": [mime["code"]]}
        reason, _ = accept(self.report([mime, old]), self.report([new]), None, [edit])
        self.assertIn("introduces a finding", reason)
        reason, paired = accept(self.report([mime, old, old]), self.report([old, old]), None, [edit])
        self.assertIsNone(reason)
        self.assertEqual(paired[0]["before_findings"], [mime])
