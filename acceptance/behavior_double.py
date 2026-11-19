"""Controlled reader for older static inspection and repair regression tests."""

class FixtureReader:
    def __init__(self, config, private):
        pass

    def health(self, engine):
        return {"ready": True, "identity": {"engine": engine, "renderer": engine, "version": "fixture"},
                "monitor": "fixture"}

    def run(self, engine, book, limits, options, comparison=False):
        return {"complete": True, "steps": [{"kind": "reading_order", "member": "fixture.xhtml",
                                              "fragment": "", "status": "completed", "pages": [1]}],
                "gaps": [], "events": [], "external_links_unactivated": 0}
