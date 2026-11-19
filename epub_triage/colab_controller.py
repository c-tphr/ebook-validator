"""Colab batch orchestration, durable decisions, and independent book recovery."""

import json
import secrets
import time
from collections import Counter
from dataclasses import asdict

from .colab_drive import CandidateStore, Conflict, DriveError, Journal, reconcile, stamp
from .colab_runtime import WorkerPending
from .colab_worker import MiB


def compact(report, traces, path=()):
    """Separate detailed navigation from recoverable decisions."""
    if not isinstance(report, dict):
        return report
    saved = {}
    for key, value in report.items():
        if key == "engines" and isinstance(value, dict) and "outcome" in report:
            summary = {}
            for engine, evidence in value.items():
                summary[engine] = {"complete": evidence["complete"],
                                   "steps_examined": len(evidence["steps"]),
                                   "events": [event for event in evidence["events"]
                                              if event["attribution"] != "reader"],
                                   "gaps": evidence["gaps"], "monitor": evidence.get("monitor")}
            if report["outcome"] in {"hold", "quarantine"}:
                traces.append({"stage": list(path), "engines": value})
            saved[key] = summary
        else:
            saved[key] = compact(value, traces, (*path, key))
    return saved


class Controller:
    def __init__(self, drive, scope, runtime, *, stage_mib=1024, trace_days=14,
                 profile=None, report_only=True, journal=None, quarantine=None, behavior=True, evidence=None):
        if type(stage_mib) is not int or not 280 <= stage_mib <= 4096:
            raise ValueError("Enter a staging limit from 280 to 4096 MiB.")
        if type(trace_days) is not int or not 1 <= trace_days <= 365:
            raise ValueError("Enter a trace expiry from 1 to 365 days.")
        self.drive, self.scope, self.runtime = drive, scope, runtime
        self.settings = {"scope": asdict(scope), "stage_bytes": stage_mib * MiB,
                         "trace_days": trace_days, "profile": profile, "report_only": report_only,
                         "workflow_revision": 1, "behavior": behavior}
        self.settings["evidence_object"] = evidence.item if evidence else None
        self.configuration = stamp({"settings": self.settings, "runtime": runtime.configuration()})
        self.journal = journal
        self.quarantine = quarantine
        self.evidence = evidence
        self.owner = secrets.token_hex(16)
        self.generation = None
        self.entries = {}
        self.opened = False
        self.selection = []
        self.rejections = {}
        self.local_traces = {}
        self.candidate_drives = set()

    def status(self):
        if self.journal is not None:
            value, _, _ = self.journal.snapshot()
            self.entries = value["books"]
            self.previous_configuration = value.get("configuration")
            self.opened = True
            owned = value["writer"] == self.owner
        else:
            owned = False
        return {"summary": dict(Counter(entry["state"] for entry in self.entries.values())),
                "configuration": self.configuration,
                "persisted_configuration": getattr(self, "previous_configuration", None),
                "writer": "this notebook" if owned else "read-only",
                "books": list(self.entries.values())}

    def select(self, selected=(), recursive=True):
        self.selection, self.rejections = self.scope.select(self.drive, selected, recursive)
        return self.selection, self.rejections

    def acquire(self, takeover=False):
        if self.settings["report_only"]:
            raise DriveError("Report-only uses read-only Drive access.")
        if not isinstance(self.journal, Journal) or not self.journal.qualified:
            raise DriveError("The canonical Drive journal and its CAS qualification are pending.")
        self.status()
        if takeover and self.previous_configuration == self.configuration:
            self.recover_physical(takeover=True)
        self.generation = self.journal.acquire(self.owner, takeover=takeover)
        return self.generation

    def recover_physical(self, takeover=False):
        value, _, _ = self.journal.snapshot()
        intent = value.get("in_flight_physical")
        if not intent:
            return
        kind = intent.get("kind")
        if kind == "candidate":
            lane = CandidateStore(self.drive, self.scope, self.journal, intent["target"], self.candidate_drives)
        else:
            lane = self.evidence if kind == "evidence" else self.quarantine
        if not lane:
            raise Conflict("The original physical lane needs qualification before reconciliation.")
        lane.recover(self.owner, self.generation, takeover=takeover)

    def save(self):
        if self.settings["report_only"]:
            return
        if self.generation is None:
            raise Conflict("This notebook does not have qualified journal writer ownership.")
        self.journal.commit(self.owner, self.generation, self.configuration, self.entries)
        self.previous_configuration = self.configuration

    def initial(self, source):
        return {"source": source, "configuration": self.configuration, "state": "pending"}

    def scan_one(self, entry):
        source = entry["source"]
        self.scope.current(self.drive, source)
        result = self.runtime.inspect(self.drive, self.scope, source,
                                      stage_bytes=self.settings["stage_bytes"],
                                      report_only=self.settings["report_only"], profile=self.settings["profile"],
                                      behavior=self.settings["behavior"])
        traces = []
        report = compact(result, traces)
        action = report["action"]
        if action == "quarantine" and not traces:
            traces.append({"stage": ["static"], "security": report["security"],
                           "quality": report["quality"]})
        repair = report.get("repair", {})
        if repair.get("decision") == "verified_candidate":
            action = "publish"
        operation = None
        if action in {"quarantine", "stage_repair", "publish"}:
            operation = {"id": stamp([self.configuration, source, action, repair.get("output_sha256")]),
                         "action": action,
                         "expected_sha256": repair.get("output_sha256") or source["sha256"],
                         "status": "preview" if self.settings["report_only"] else "pending",
                         "reason": ("Report-only preview." if self.settings["report_only"] else
                                    "Physical Drive mutations require separate safe commit qualification.")}
        if report["status"] == "behavior_pending":
            state = "pending"
        elif action == "hold":
            state = "held"
        else:
            state = "evaluated" if not operation or self.settings["report_only"] else "pending"
        new = {**entry, "state": state, "report": report, "operation": operation}
        if traces and not self.settings["report_only"]:
            fingerprint = stamp(traces)
            new["trace"] = {"expires_at": int(time.time()) + self.settings["trace_days"] * 86400,
                            "sha256": fingerprint, "slot": stamp([source, self.configuration, fingerprint,
                                                                  secrets.token_hex(16)]),
                            "status": "evidence folder upload pending"}
            self.local_traces[source["id"]] = traces
        return new

    def expire(self, now=None):
        if self.settings["report_only"]:
            return 0
        now = int(time.time()) if now is None else now
        count = 0
        for item, entry in list(self.entries.items()):
            for decision in (entry, *entry.get("history", ())):
                trace = decision.get("trace")
                if not trace or trace["status"] == "expired" or now < trace["expires_at"]:
                    continue
                if self.evidence and trace["status"] in {"stored", "expiry pending",
                                                          "evidence needs fresh reconciliation"}:
                    try:
                        self.entries[item] = self.evidence.expire(self.owner, self.generation, entry, trace["slot"])
                        entry = self.entries[item]
                    except DriveError:
                        continue
                else:
                    trace["status"] = "expired"
                if decision is entry:
                    self.local_traces.pop(item, None)
                count += 1
        return count

    def run(self, *, resume=False, fresh=False, notify=lambda _: None):
        self.scope.validate(self.drive)
        blocked_intent = None
        if not self.settings["report_only"]:
            if not self.opened:
                self.status()
            if self.generation is None:
                raise Conflict("Resume or acquire writer ownership before running a durable batch.")
            if self.previous_configuration is not None and self.previous_configuration != self.configuration and not fresh:
                raise Conflict("Configuration changed. Explicitly request a fresh scan.")
            if resume and self.previous_configuration == self.configuration:
                try:
                    self.recover_physical()
                except DriveError:
                    value, _, _ = self.journal.snapshot()
                    blocked_intent = value.get("in_flight_physical")
                    if not blocked_intent:
                        raise
                self.status()
            else:
                value, _, _ = self.journal.snapshot()
                blocked_intent = value.get("in_flight_physical")
            if not blocked_intent:
                self.expire()
        if self.entries and not (resume or fresh):
            raise Conflict("Existing progress is read-only until Resume or Fresh scan.")
        for source in self.selection:
            if blocked_intent and source["id"] == blocked_intent["object"]:
                continue
            if fresh or source["id"] not in self.entries:
                prior = self.entries.get(source["id"])
                self.entries[source["id"]] = self.initial(source)
                if prior and prior.get("report"):
                    historical = {field: prior.get(field) for field in (
                        "source", "configuration", "state", "report", "operation", "reviews", "trace")}
                    self.entries[source["id"]]["history"] = [*prior.get("history", ()), historical]
                    self.entries[source["id"]]["intentional"] = prior.get("intentional", {})
        self.save()
        selected_ids = {entry["id"] for entry in self.selection}
        for book, entry in list(self.entries.items()):
            if fresh and book not in selected_ids:
                continue
            if blocked_intent and book == blocked_intent["object"]:
                self.entries[book] = {**entry, "state": "ambiguous",
                                      "reason": "A physical intent is unresolved; its write lane remains closed."}
                self.save()
                notify(self.entries[book])
                continue
            if entry["configuration"] != self.configuration:
                self.entries[book] = {**entry, "state": "stale", "reason": "Configuration identity changed."}
            elif entry.get("report"):
                if not self.settings["report_only"]:
                    if not entry.get("operation"):
                        try:
                            self.scope.current(self.drive, entry["source"])
                        except DriveError:
                            self.entries[book] = {**entry, "state": "stale",
                                                  "reason": "Source version or access changed."}
                    self.entries[book] = reconcile(self.drive, self.scope, self.entries[book])
                    op = self.entries[book].get("operation")
                    if op and op["status"] == "complete":
                        self.entries[book]["state"] = "complete"
                    elif op and op["status"] == "ambiguous":
                        self.entries[book]["state"] = "ambiguous"
                    elif op and op["status"] == "stale_or_inaccessible":
                        self.entries[book]["state"] = "stale"
            else:
                try:
                    self.entries[book] = self.scan_one(entry)
                except Conflict as error:
                    self.entries[book] = {**entry, "state": "stale", "reason": str(error)}
                except (DriveError, WorkerPending, ValueError, OSError) as error:
                    self.entries[book] = {**entry, "state": "pending", "reason": (
                        str(error) if isinstance(error, (DriveError, WorkerPending, ValueError))
                        else "Local stage unavailable.")}
            self.save()
            record = self.entries[book]
            if (self.evidence and book in self.local_traces and not self.settings["report_only"]
                    and not blocked_intent):
                try:
                    self.entries[book] = self.evidence.write(self.owner, self.generation,
                                                              record, self.local_traces[book])
                    record = self.entries[book]
                    self.local_traces.pop(book)
                except DriveError:
                    pass
            if (not self.settings["report_only"] and self.quarantine and self.quarantine.qualified_drive
                    and not blocked_intent
                    and (record.get("operation") or {}).get("action") == "quarantine"
                    and record["operation"]["status"] == "pending" and record["state"] == "pending"):
                try:
                    self.entries[book] = self.quarantine.dispatch(self.owner, self.generation, record)
                except DriveError as error:
                    current, _, _ = self.journal.snapshot()
                    blocked_intent = current.get("in_flight_physical")
                    if (blocked_intent or {}).get("object") == book:
                        record["state"] = "ambiguous"
                        record["operation"]["dispatched"] = True
                    elif current.get("in_flight_physical"):
                        record["state"] = "pending"
                    else:
                        record["state"] = "stale" if isinstance(error, Conflict) else "pending"
                    record["operation"]["reason"] = str(error)
                    self.save()
            record = self.entries[book]
            pending_candidate = record.get("candidate") or {}
            if (resume and not self.settings["report_only"] and not blocked_intent
                    and record["state"] not in {"stale", "ambiguous"}
                    and pending_candidate.get("status") == "staging_needs_retry"):
                try:
                    self.stage_candidate(book, pending_candidate["id"])
                except (DriveError, WorkerPending, ValueError, OSError):
                    pass
            notify(self.entries[book])
        return self.status() if not self.settings["report_only"] else {
            "summary": dict(Counter(entry["state"] for entry in self.entries.values())),
            "writer": "report-only", "configuration": self.configuration,
            "books": list(self.entries.values())}

    def qualify_candidate(self, item):
        if self.settings["report_only"] or self.journal is None or not self.journal.qualified:
            raise DriveError("Qualify the durable journal first.")
        probe = CandidateStore(self.drive, self.scope, self.journal, item)
        self.candidate_drives.add(probe.qualify())

    def stage_candidate(self, book, item):
        if self.settings["report_only"] or self.generation is None:
            raise DriveError("Acquire the journal writer before staging a verified candidate.")
        self.journal.owned(self.owner, self.generation)
        entry = self.entries[book]
        repair = entry.get("report", {}).get("repair", {})
        target = (entry.get("operation") or {}).get("expected_sha256")
        if (entry["configuration"] != self.configuration or not target
                or repair.get("decision") != "verified_candidate"
                or entry["state"] in {"stale", "ambiguous"}):
            raise Conflict("A current verified automatic repair candidate is required.")
        store = CandidateStore(self.drive, self.scope, self.journal, item, self.candidate_drives)
        source = entry["source"]

        def stage(candidate, digest):
            if digest != target:
                raise Conflict("Rebuilt candidate differs from the originally verified digest.")
            self.entries[book] = store.store(self.owner, self.generation, entry, candidate, target)

        self.runtime.inspect(self.drive, self.scope, source, stage_bytes=self.settings["stage_bytes"],
                             report_only=False, profile=self.settings["profile"], behavior=True,
                             candidate_sink=stage)
        if not self.entries[book].get("candidate"):
            raise Conflict("Candidate could not be reverified and staged.")
        self.save()
        return self.entries[book]["candidate"]

    def export(self):
        data = {"configuration": self.configuration, "settings": self.settings, "books": self.entries}
        return json.dumps(data, ensure_ascii=True, indent=2)
