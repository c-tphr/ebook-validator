"""Book-scoped v3 review in Colab with the same v3 proposal and export protocol."""

from pathlib import Path

from .colab_drive import Conflict, DriveError
from .review import BookReview
from .review_cli import ReviewerUnavailable, requested_model
from .review_work import stable_hash

PROVIDERS = ("codex", "claude", "agy")
METHODS = {
    "codex": ("Colab Secret: OPENAI_API_KEY", "ChatGPT per-session sign-in or device auth"),
    "claude": ("Colab Secret: ANTHROPIC_API_KEY", "Colab Secret: CLAUDE_CODE_OAUTH_TOKEN",
               "Claude Code per-session sign-in"),
    "agy": ("Colab Secret: GEMINI_API_KEY", "Google per-session sign-in", "Dedicated Google Cloud ADC"),
}


class Assessment(BookReview):
    def __init__(self, query, provider, models):
        self.query = query
        self.provider = provider
        self.config = {**{key + "_model": value for key, value in models.items()},
                       "review_turn_limit": 8}

    def data(self, _, request, candidate=None):
        return self.query(request)

    def call_reviewer(self, reviewer, payload):
        return self.provider(reviewer, self.config, payload)


class Review:
    def __init__(self, controller, provider, pair=("codex", "claude"), models=None):
        self.controller = controller
        self.provider = provider
        self.set_pair(pair)
        self.models = models if models is not None else {}

    def set_pair(self, pair):
        if len(pair) != 2 or len(set(pair)) != 2 or any(name not in PROVIDERS for name in pair):
            raise ValueError("Choose two distinct reviewer CLIs.")
        self.pair = tuple(pair)

    def source(self, book, mutate=False):
        controller = self.controller
        if mutate:
            if controller.settings["report_only"] or controller.generation is None:
                raise DriveError("Review decisions require an acquired durable writer.")
            controller.journal.owned(controller.owner, controller.generation)
        entry = controller.entries[book]
        if (entry["configuration"] != controller.configuration
                or entry.get("report", {}).get("action") != "stage_repair"
                or (entry.get("report", {}).get("behavior") or {}).get("effective") != "release"):
            raise Conflict("This book needs a fresh eligible scan under the current configuration.")
        if (entry.get("operation") or {}).get("action") == "publish" and entry["operation"]["status"] == "complete":
            raise Conflict("Review of an accepted Drive edition requires a verified head binding.")
        controller.scope.current(controller.drive, entry["source"])
        return entry

    def query(self, entry):
        controller = self.controller
        return controller.runtime.review(controller.drive, controller.scope, entry["source"],
                                         controller.settings["stage_bytes"])

    def findings(self, book):
        entry = self.source(book)
        with self.query(entry) as query:
            return query({"action": "findings"})["findings"]

    def review(self, book, occurrence, *, second=False):
        entry = self.source(book, mutate=True)
        records = entry.setdefault("reviews", {})
        prior = records.get(occurrence)
        sha256 = entry["source"]["sha256"]
        if second and (not prior or len(prior.get("assessments", [])) != 1
                       or prior["status"] != "reviewed"):
            raise ValueError("Second opinion requires an open primary review.")
        if prior and prior["book_sha256"] != sha256:
            raise Conflict("The reviewed book version changed.")
        if not second and prior and prior["status"] not in {"paused"}:
            return prior
        selected = self.pair[1 if second else 0]
        if second and selected == prior["assessments"][0]["reviewer"]:
            selected = self.pair[0]
        if second and selected == prior["assessments"][0]["reviewer"]:
            raise ValueError("Second reviewer must differ from the primary reviewer.")
        model = requested_model(selected, {key + "_model": value for key, value in self.models.items()})
        if prior and prior.get("pending_reviewer") and (
                prior["pending_reviewer"] != selected or prior.get("pending_model") != model):
            raise Conflict("Interrupted review must resume with its original provider and model.")
        with self.query(entry) as query:
            matches = [item for item in query({"action": "findings"})["findings"] if item["occurrence"] == occurrence]
            if len(matches) != 1:
                raise Conflict("Selected occurrence changed or is out of scope.")
            inherited = entry.get("intentional", {}).get(occurrence)
            if inherited:
                return {"status": "intentional", "review": inherited, **matches[0]}
            operation = stable_hash(["drive-review", self.controller.scope.intake, book])
            row = prior or {"id": stable_hash(["review-v1", operation, sha256, occurrence]),
                            "book": entry["source"]["name"], "book_sha256": sha256,
                            **matches[0], "assessments": [], "status": "paused"}
            row["pending_reviewer"] = selected
            row["pending_model"] = model
            records[occurrence] = row
            self.controller.save()
            helper = Assessment(query, self.provider, self.models)
            try:
                opinion = helper.assessment(selected, row, None)
            except ReviewerUnavailable:
                row["reason"] = "Reviewer interrupted or its selected authentication is unavailable."
            else:
                row["assessments"].append(opinion)
                row.update(status="reviewed", pending_reviewer=None, pending_model=None)
                row.pop("reason", None)
            self.controller.scope.current(self.controller.drive, entry["source"])
            self.controller.save()
        return row

    def export(self, book, occurrence, destination):
        record = self.source(book)["reviews"][occurrence]
        with destination.open("xb") as stream:
            stream.write(Assessment(None, None, {}).export_bytes(record))

    def decide(self, book, occurrence, action):
        states = {"reject": "rejected", "defer": "deferred", "intentional": "intentional",
                  "investigate": "investigate"}
        if action not in states:
            raise ValueError("Choose a valid user decision.")
        entry = self.source(book, mutate=True)
        row = entry["reviews"][occurrence]
        if row["status"] == states[action]:
            return row
        if row["status"] != "reviewed":
            raise ValueError("This review does not have an open decision.")
        if action == "intentional":
            if row["start"] is None or row["locator"] is None:
                raise ValueError("The finding has no passage to mark intentionally unchanged.")
            with self.query(entry) as query:
                if not any(item["occurrence"] == occurrence and item["locator"] == row["locator"]
                           for item in query({"action": "findings"})["findings"]):
                    raise Conflict("The selected passage changed.")
            entry.setdefault("intentional", {})[occurrence] = row["id"]
        row["status"] = states[action]
        self.controller.save()
        return row

    def approve(self, book, occurrence, proposal_id, exported=None):
        entry = self.source(book, mutate=True)
        row = entry["reviews"][occurrence]
        if row["book_sha256"] != entry["source"]["sha256"]:
            raise Conflict("Approval is bound to the old source SHA-256.")
        if row["status"] not in {"reviewed", "approved"}:
            if row.get("approved_proposal") == proposal_id and row.get("verification"):
                Assessment(None, None, {}).approval(row, proposal_id, Path(exported) if exported else None)
                return row
            raise ValueError("Review does not have a current approvable proposal.")
        if row.get("approved_proposal") and row["approved_proposal"] != proposal_id:
            raise Conflict("Resume the previously approved exact diff.")
        helper = Assessment(None, None, {})
        assessment = helper.approval(row, proposal_id, Path(exported) if exported else None)
        row.update(status="approved", approved_proposal=proposal_id,
                   approval={"book_sha256": row["book_sha256"], "diff": assessment["diff"]})
        self.controller.save()
        with self.query(entry) as query:
            finding = next((item for item in query({"action": "findings"})["findings"]
                            if item["occurrence"] == occurrence), None)
            if finding is None:
                raise Conflict("Finding changed before approval verification.")
            result = query({"action": "verify", "edit": assessment["edit"], "finding": finding})
        row["verification"] = result
        row["status"] = result["status"]
        if result["status"] == "verified_candidate":
            row["publication"] = "pending: Drive source and edition cannot commit atomically"
        self.controller.save()
        return row

    def publication_decision(self, book, occurrence, candidate_sha256, publish):
        entry = self.source(book, mutate=True)
        row = entry["reviews"][occurrence]
        if row["status"] != "awaiting_publication_decision":
            old = row.get("publication")
            if (isinstance(old, dict) and old.get("candidate_sha256") == candidate_sha256
                    and old.get("decision") == ("publish" if publish else "decline")):
                return row
            raise ValueError("No publication decision is pending for this occurrence.")
        exact = row["verification"]["candidate_sha256"]
        if exact != candidate_sha256:
            raise Conflict("Publication decision must name the exact verified candidate.")
        with self.query(entry) as query:
            finding = next((item for item in query({"action": "findings"})["findings"]
                            if item["occurrence"] == occurrence), None)
            assessment = Assessment(None, None, {}).approval(row, row["approved_proposal"], None)
            result = query({"action": "verify", "edit": assessment["edit"], "finding": finding})
        if result.get("status") != "awaiting_publication_decision" or result.get("candidate_sha256") != exact:
            raise Conflict("Reverified candidate changed or no longer has the selected warning.")
        row["publication"] = {"candidate_sha256": exact, "decision": "publish" if publish else "decline",
                              "status": "pending_drive_commit" if publish else "declined"}
        row["status"] = "publication_pending" if publish else "publication_declined"
        self.controller.save()
        return row
