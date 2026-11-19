"""Transport and occurrence boundaries that do not require a real model."""

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from epub_triage.review import BookReview, verification_problem
from epub_triage.review_cli import messages_only, relay, validate_wire
from epub_triage.review_work import OCR, occurrences, ocr_spans


class ReviewBoundaryTests(unittest.TestCase):
    def test_relay_denies_unauthenticated_request_before_upstream(self):
        with patch.dict(os.environ, OPENAI_API_KEY="test", OPENAI_BASE_URL="http://127.0.0.1:1"):
            with relay("codex", 2, "secret-ticket") as (address, errors):
                request = Request(address + "/responses", b"{}", {"Content-Type": "application/json"})
                with self.assertRaises(HTTPError) as error:
                    urlopen(request, timeout=2)
                self.assertEqual(error.exception.code, 403)
                self.assertEqual(errors, [])
                error.exception.close()

    def test_relay_strips_tools_and_rejects_nested_tool_calls(self):
        request = {"input": [{"role": "user", "content": [{"type": "input_text", "text": "Passage"}]}],
                   "tools": [{"type": "function", "name": "exec_command"}],
                   "tool_choice": "required", "previous_response_id": "an_old_context"}
        messages_only(request, "codex")
        self.assertEqual(set(request), {"input"})
        payload = {"output": [{"type": "message", "content": [{"type": "function_call", "name": "exec_command"}]}]}
        with self.assertRaises(ValueError):
            validate_wire(json.dumps(payload).encode(), "application/json", "codex")

    def test_registered_export_is_checked_on_delayed_id_only_approval(self):
        service = BookReview.__new__(BookReview)
        with tempfile.TemporaryDirectory() as root, closing(sqlite3.connect(":memory:")) as connection:
            service.connection = connection
            connection.row_factory = sqlite3.Row
            connection.execute("CREATE TABLE agent_exports(review_id TEXT, path TEXT)")
            path = Path(root) / "proposal.json"
            edit = {"member": "text.xhtml", "start": 8, "before": "Mistak", "after": "Mistake"}
            diff = {"member": "text.xhtml", "start": 8, "removed": "Mistak", "added": "Mistake"}
            record = {"id": "review", "book": "title.epub", "book_sha256": "sha", "finding": {},
                      "assessments": []}
            assessment = {"reviewer": "codex", "edit": edit, "diff": diff}
            assessment["proposal_id"] = service.proposal_id(record, assessment)
            record["assessments"].append(assessment)
            service.export(record, path)
            self.assertEqual(service.approval(record, assessment["proposal_id"], None,
                                              check_implicit_export=True), assessment)
            path.write_bytes(path.read_bytes().replace(b'"added": "Mistake"', b'"added": "Other"'))
            with self.assertRaisesRegex(ValueError, "Exported proposal content differs"):
                service.approval(record, assessment["proposal_id"], None, check_implicit_export=True)

    def test_ocr_occurrences_include_entities_and_retained_twins(self):
        source = '<html><p>Word&#65533;</p><p>Word&#65533;</p><p id="c">Other�</p></html>'
        before = ocr_spans(source)
        after = ocr_spans(source.replace("Word&#65533;", "Word", 1))
        self.assertEqual(len(before), 3)
        self.assertEqual(len(after), 2)
        self.assertEqual([record[2] for record in after], [record[2] for record in before[1:]])
        self.assertNotEqual(before[0][2], after[0][2])

    def test_ocr_passages_in_one_text_slot_have_independent_anchors(self):
        review_finding = {"kind": "heuristic", "code": OCR,
                          "detail": "At least three Unicode replacement characters", "member": "text.xhtml"}
        report = {"security": {"complete": True, "findings": []},
                  "quality": {"complete": True, "findings": [review_finding]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "text.xhtml"
            members = {"text.xhtml": path}
            path.write_text('<html><p id="p">Mist���ak one. Mist���ak two.</p></html>', encoding='utf-8')
            before = occurrences([review_finding], members)
            self.assertEqual(len(before), 2)
            self.assertLessEqual(before[0]["end"], before[1]["start"])
            self.assertNotEqual(before[0]["locator"], before[1]["locator"])
            path.write_text('<html><p id="p">Mistake one. Mist���ak two.</p></html>', encoding='utf-8')
            one_fixed = occurrences([review_finding], members)
            self.assertEqual([item["occurrence"] for item in one_fixed], [before[1]["occurrence"]])
            self.assertIsNone(verification_problem(report, report, report, before, one_fixed, before[0]))
            path.write_text('<html><p id="p">Mist���ak changed. Mist���ak also changed.</p></html>', encoding='utf-8')
            both_changed = occurrences([review_finding], members)
            self.assertIsNotNone(verification_problem(report, report, report, before, both_changed, before[0]))

    def test_ocr_words_in_one_sentence_remain_independent(self):
        source = '<html><p id="p">His Wor���d differs from her Boo���k.</p></html>'
        first, second = ocr_spans(source)
        self.assertEqual(source[first[0]:first[1]], "Wor���d")
        self.assertEqual(source[second[0]:second[1]], "Boo���k")
        self.assertNotEqual(first[2], second[2])
        changed = source.replace("Wor���d", "World")
        self.assertEqual([record[2] for record in ocr_spans(changed)], [second[2]])
        partial = source.replace("Wor���d", "Wor������d")
        self.assertEqual([record[2] for record in ocr_spans(partial)], [first[2], second[2]])

    def test_single_warning_approval_cannot_allow_new_damaged_word_in_same_sentence(self):
        finding = {"kind": "heuristic", "code": OCR, "detail": "OCR warning", "member": "text.xhtml"}
        report = {"security": {"complete": True, "findings": []},
                  "quality": {"complete": True, "findings": [finding]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "text.xhtml"
            members = {"text.xhtml": path}
            path.write_text("<html><p>Wor������d differs from book.</p></html>", encoding="utf-8")
            before = occurrences([finding], members)
            path.write_text("<html><p>Wor���d differs from Boo���k.</p></html>", encoding="utf-8")
            after = occurrences([finding], members)
            self.assertEqual(len(before), 1)
            self.assertEqual(len(after), 2)
            self.assertEqual(verification_problem(report, report, report, before, after, before[0]),
                             "Candidate introduces or reintroduces an occurrence")


if __name__ == "__main__":
    unittest.main()
