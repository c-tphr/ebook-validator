"""Cross-boundary attribution requires aligned independent evidence."""

from unittest import TestCase

from epub_triage.behavior import corroborating_book_request
from epub_triage.reader_worker import file_target_fingerprint


class AttributionTests(TestCase):
    def test_match_requires_two_origins_same_target_member_and_step(self):
        target = file_target_fingerprint("/example/sub/../document")
        native = {"evidence": "observed_reader_syscall", "action": "out_of_book_read",
                  "step": 0, "file_target_fingerprint": target, "event_id": "native"}
        book = {"evidence": "renderer_resource_request", "action": "out_of_book_read",
                "step": 0, "file_target_fingerprint": file_target_fingerprint("/example/document"),
                "member": "chapter.xhtml", "event_id": "resource", "attribution": "book", "blocked": True}
        steps = [{"member": "chapter.xhtml"}]
        self.assertEqual(corroborating_book_request(native, [book], steps), "resource")
        for mismatch in ({"step": 1}, {"member": "other.xhtml"}, {"event_id": "native"},
                         {"file_target_fingerprint": file_target_fingerprint("/example/other")},
                         {"evidence": "observed_reader_syscall"}, {"action": "outbound_request"}):
            self.assertIsNone(corroborating_book_request(native, [{**book, **mismatch}], steps))
