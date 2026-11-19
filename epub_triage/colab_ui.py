"""Google Colab widgets for a single notebook controller."""

import json
from pathlib import Path
import tempfile

from .colab_cli import Dispatcher
from .colab_controller import Controller
from .colab_drive import (Drive, DriveError, EvidenceStore, Journal, Quarantine, Scope,
                          candidate_template, evidence_template, journal_template)
from .colab_review import METHODS, PROVIDERS, Review
from .colab_runtime import Runtime, WorkerPending
from .colab_setup import install_epubcheck, install_packages, install_weasyprint, refresh, setup_versions
from .review_cli import ReviewerUnavailable


def show():
    import ipywidgets as w
    from IPython.display import display

    output = w.Output()
    root = None
    runtime = None
    drive = None
    controller = None
    review = None

    def load_secret(name):
        from google.colab import userdata
        return userdata.get(name)

    dispatcher = Dispatcher(load_secret)
    reviewer_models = {}
    folders = {key: w.Text(description=label, style={"description_width": "initial"}) for key, label in (
        ("intake", "Intake ID"), ("quarantine", "Quarantine ID"), ("repair", "Repair intake ID"),
        ("editions", "Repaired editions ID"), ("reports", "Reports ID"), ("evidence", "Evidence ID"))}
    journal_id = w.Text(description="Journal ID")
    probe_id = w.Text(description="CAS probe ID")
    evidence_id = w.Text(description="Evidence file")
    move_file = w.Text(description="Move probe file")
    move_from = w.Text(description="Probe folder A")
    move_to = w.Text(description="Probe folder B")
    chosen = w.Text(description="Selected IDs", placeholder="Blank = intake. Separate IDs with spaces.")
    recursive = w.Checkbox(value=True, description="Include subfolders")
    report_only = w.Checkbox(value=True, description="Report-only")
    behavior = w.Checkbox(value=True, description="Run v4 behavioral gate")
    profile = w.Dropdown(options=(("Scan only", None), ("Mechanical repair", "mechanical"),
                                  ("Broader repair", "broader")), description="Workflow")
    stage = w.BoundedIntText(value=1024, min=280, max=4096, description="Staging MiB")
    timeout = w.BoundedIntText(value=60, min=60, max=600, description="Reader seconds")
    expiry = w.BoundedIntText(value=14, min=1, max=365, description="Trace days")
    first = w.Dropdown(options=PROVIDERS, value="codex", description="Primary")
    second = w.Dropdown(options=PROVIDERS, value="claude", description="Second")
    reviewer = w.Dropdown(options=PROVIDERS, description="Configure CLI")
    methods = w.Dropdown(options=(("Colab API key", "secret-key"), ("Per-session sign-in", "session"),
                                 ("Claude OAuth token", "oauth-token"), ("Google ADC", "adc")),
                         description="Sign-in")
    reviewer_path = w.Text(description="ELF executable")
    reviewer_digest = w.Text(description="SHA-256 pin")
    reviewer_model = w.Text(description="Model")
    reviewed_book = w.Text(description="Book ID")
    occurrence = w.Text(description="Occurrence")
    proposal = w.Text(description="Proposal ID")
    candidate = w.Text(description="Candidate SHA")
    staging_id = w.Text(description="Staging file ID")
    binary_probe = w.Text(description="Binary CAS probe ID")
    exported = w.FileUpload(description="Choose proposal file", accept=".json", multiple=False)
    decision = w.Dropdown(options=("intentional", "defer", "reject", "investigate"), description="Decision")
    actions = []

    def say(value):
        print(json.dumps(value, ensure_ascii=True, indent=2) if not isinstance(value, str) else value)

    def button(label, callback):
        control = w.Button(description=label, layout=w.Layout(width="auto"))
        actions.append(control)

        def clicked(_):
            for action in actions:
                action.disabled = True
            with output:
                output.clear_output(wait=True)
                try:
                    callback()
                except (DriveError, WorkerPending, ValueError, OSError, RuntimeError) as error:
                    # Known protocol errors may be shown. Native launch and
                    # authentication errors are reduced to fixed descriptions.
                    say(str(error)[:400] if isinstance(error, (DriveError, WorkerPending, ValueError))
                        else "The requested stage failed. Check its readiness and retry.")
                except (KeyError, IndexError):
                    say("The selected book, finding, or proposal was not found.")
                finally:
                    for action in actions:
                        action.disabled = False

        control.on_click(clicked)
        return control

    def setup():
        nonlocal root, runtime, controller, review
        controller = None
        review = None
        if runtime:
            runtime.close()
            runtime = None
        if root:
            root.cleanup()
        root = tempfile.TemporaryDirectory(prefix="epub-v5-software-")
        install = Path(root.name)
        install.chmod(0o755)
        evidence = {}
        stages = (
            ("system packages", install_packages),
            ("EPUBCheck 5.4.0", lambda: str(install_epubcheck(install / "epubcheck"))),
            ("WeasyPrint", lambda: str(install_weasyprint(install / "python"))),
            ("signatures", lambda: refresh(install / "signatures")),
        )
        for name, action in stages:
            try:
                value = action()
                evidence[name] = {"ready": True}
                if name == "system packages":
                    evidence[name]["pins"] = value
            except Exception as error:
                evidence[name] = {"ready": False, "reason": (
                    str(error)[:250] if type(error) is RuntimeError else "Pinned installation or update failed.")}
        say(evidence)
        versions = setup_versions()
        say(versions)
        if evidence["EPUBCheck 5.4.0"]["ready"] and evidence["system packages"]["ready"]:
            runtime = Runtime(database=install / "signatures",
                              epubcheck_jar=install / "epubcheck" / "epubcheck.jar",
                              behavior_python_packages=install / "python" if evidence["WeasyPrint"]["ready"] else None,
                              behavior_timeout=timeout.value)
            runtime.tool_identity = versions["tools"]
            say(f"Removed {runtime.abandoned_removed} abandoned staging directories.")
            evidence = runtime.qualify()
            if not runtime.config.get("behavior_python_packages"):
                evidence["behavior_ready"] = False
                evidence["engines"]["weasyprint"] = {"ready": False, "reason": "Pinned WeasyPrint lock failed."}
            if not evidence.get("scan", {}).get("ready"):
                say("Inspection, repair, and reviewer source access remain pending.")
            say(evidence)
        else:
            say("Scan, behavioral gate, repair and review remain pending.")

    def connect():
        nonlocal drive
        try:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            from google.colab import auth
            auth.authenticate_user()
            credentials, _ = google.auth.default()
            session = AuthorizedSession(credentials)
            drive = Drive(session)
            account = drive.account()
        except Exception:
            raise DriveError("Drive sign-in or API authorization did not complete.") from None
        say("Drive is connected. Select an intake or open status.")

    def scope_now():
        if drive is None:
            raise DriveError("Connect Drive first.")
        return Scope(**{key: value.value.strip() for key, value in folders.items()})

    def settings_now():
        scope = scope_now()
        if not runtime:
            # A disconnected runtime still supports historical read-only status.
            class PendingRuntime:
                @staticmethod
                def configuration():
                    return {"ready": False}

                @staticmethod
                def inspect(*args, **kwargs):
                    raise WorkerPending("Run setup before scanning.")
            selected_runtime = PendingRuntime()
        else:
            selected_runtime = runtime
        journal = Journal(drive, scope, journal_id.value.strip(), drive.account()) if journal_id.value.strip() else None
        return Controller(drive, scope, selected_runtime, stage_mib=stage.value,
                          trace_days=expiry.value, profile=profile.value, report_only=report_only.value,
                          behavior=behavior.value, journal=journal,
                          quarantine=Quarantine(drive, scope, journal) if journal else None,
                          evidence=EvidenceStore(drive, scope, journal, evidence_id.value.strip())
                          if journal and evidence_id.value.strip() else None)

    def current():
        nonlocal controller, review
        available = settings_now()
        if (controller is None or controller.configuration != available.configuration or
                (controller.journal.item if controller.journal else None) !=
                (available.journal.item if available.journal else None)):
            controller = available
            review = Review(controller, dispatcher, models=reviewer_models)
        return controller

    def select():
        c = current()
        items, denied = c.select(chosen.value.split(), recursive.value)
        say({"selected": [{"id": item["id"], "name": item["name"], "bytes": item["size"]}
                          for item in items], "rejected": denied})

    def provision():
        scope = scope_now()
        say(journal_template(scope.intake, drive.account()))
        say({"purpose": "epub-v5-disposable-cas-probe"})
        say(evidence_template(scope.intake))

    def status():
        c = current()
        say(c.status())

    def qualify():
        c = current()
        if c.settings["report_only"]:
            raise DriveError("Turn off report-only before qualifying writes on disposable objects.")
        if c.journal is None:
            raise DriveError("Enter the canonical pre-provisioned journal ID first.")
        c.journal.snapshot()
        c.journal.qualify(probe_id.value.strip())
        say("The journal accepted a current conditional write and rejected the stale one.")
        probes = [value.value.strip() for value in (move_file, move_from, move_to)]
        if all(probes):
            c.quarantine.qualify(*probes)
            say("The conditional quarantine lane passed its disposable move probe.")
        if binary_probe.value.strip():
            c.qualify_candidate(binary_probe.value.strip())
            say("The unpublished candidate lane passed its disposable binary CAS probe.")

    def run(resume=False, takeover=False, fresh=False):
        c = current()
        if not c.settings["report_only"] and (c.generation is None or takeover):
            try:
                c.acquire(takeover)
            except DriveError as error:
                if not resume:
                    raise
                say(str(error))
                status = c.status()
                say(status["summary"])
                say("Durable and physical writes are paused. Running a separate read-only preview.")
                preview = Controller(c.drive, c.scope, c.runtime, stage_mib=stage.value,
                                     trace_days=expiry.value, profile=profile.value,
                                     report_only=True, behavior=behavior.value)
                pending = tuple(row["source"]["id"] for row in status["books"]
                                if row["state"] in {"pending", "held"})
                selected = chosen.value.split() or pending
                if selected:
                    preview.select(selected, recursive.value)
                    say(preview.run()["summary"])
                return
        if fresh or not resume:
            items, denied = c.select(chosen.value.split(), recursive.value)
            say({"selected": len(items), "rejected": denied})
        result = c.run(resume=resume, fresh=fresh, notify=lambda row: say({
            "book": row["source"]["name"], "state": row["state"], "operation": row.get("operation"),
            "reason": row.get("reason")}))
        say(result["summary"])

    def download_report():
        from google.colab import files
        with tempfile.TemporaryDirectory() as destination:
            path = Path(destination) / "epub-run-report.json"
            path.write_text(current().export())
            files.download(path)

    def stage_candidate():
        say(current().stage_candidate(reviewed_book.value.strip(), staging_id.value.strip()))

    def candidate_placeholder():
        say(candidate_template("disposable"))
        say(candidate_template(reviewed_book.value.strip()))

    def reviewers():
        say({"selected": [first.value, second.value], "reviewers": {
            cli: {"authentication": list(options), "readiness": dispatcher.readiness(cli)}
            for cli, options in METHODS.items()}})

    def configure_reviewer():
        try:
            dispatcher.configure(reviewer.value, reviewer_path.value.strip(),
                                 reviewer_digest.value.strip(), methods.value, reviewer_model.value.strip())
        except ReviewerUnavailable as error:
            raise WorkerPending(str(error)) from None
        if reviewer_model.value.strip():
            reviewer_models[reviewer.value] = reviewer_model.value.strip()
        reviewers()

    def smoke_reviewer():
        import secrets
        name = reviewer.value
        marker = secrets.token_hex(12)
        config = {name + "_model": reviewer_models.get(name)}
        try:
            response = dispatcher(name, config, {"book_sha256": "0" * 64, "members": [],
                "finding": {"code": "public_disposable_smoke_test", "detail": (
                    "Return an uncertainty assessment with the exact rationale " + marker)},
                "passage": None, "history": []})
        except ReviewerUnavailable:
            raise WorkerPending("Restricted reviewer smoke test did not complete.") from None
        if response.get("rationale") != marker or response.get("action") != "assess":
            raise WorkerPending("Provider response did not match the public test marker.")
        say("The selected pinned CLI and secret completed the public test.")


    def review_action(action):
        current()
        review.set_pair((first.value, second.value))
        book = reviewed_book.value.strip()
        target = occurrence.value.strip()
        if action == "findings":
            say(review.findings(book))
        elif action in {"primary", "second"}:
            say(review.review(book, target, second=action == "second"))
        elif action == "decide":
            say(review.decide(book, target, decision.value))
        elif action == "approve":
            uploaded = exported.value
            if uploaded:
                value = next(iter(uploaded.values())) if isinstance(uploaded, dict) else uploaded[0]
                if len(value["content"]) > 2 * 1024 * 1024:
                    raise ValueError("Proposal file exceeds the approval size limit.")
                with tempfile.TemporaryDirectory() as destination:
                    path = Path(destination) / "approval.json"
                    path.write_bytes(value["content"])
                    say(review.approve(book, target, proposal.value.strip(), exported=path))
            else:
                say(review.approve(book, target, proposal.value.strip()))
        elif action == "export":
            from google.colab import files
            with tempfile.TemporaryDirectory() as destination:
                path = Path(destination) / "epub-proposal.json"
                review.export(book, target, path)
                files.download(path)
        else:
            say(review.publication_decision(book, target, candidate.value.strip(), action == "publish"))

    display(w.VBox([
        w.HTML("<h2>EPUB validator</h2>"),
        w.HBox([button("Set up", setup), button("Connect Drive", connect)]),
        w.VBox(list(folders.values())),
        w.HBox([journal_id, probe_id, evidence_id]),
        w.HBox([move_file, move_from, move_to, binary_probe]),
        w.HBox([button("Journal template", provision), button("Qualify disposable writes", qualify)]),
        w.HBox([chosen, recursive]),
        w.HBox([report_only, behavior, profile]),
        w.HBox([stage, expiry, timeout]),
        w.HBox([button("Select", select), button("Open status", status), button("Run", run),
                button("Resume", lambda: run(resume=True)), button("Fresh scan", lambda: run(fresh=True)),
                button("Take over and resume", lambda: run(resume=True, takeover=True)),
                button("Download report", download_report)]),
        w.HTML("<h3>Agent review</h3><p>Review sends only the selected finding and requested passages "
               "to the chosen reviewer. Review is optional and starts only on request.</p>"),
        w.HBox([first, second, button("Reviewers and sign-in methods", reviewers)]),
        w.HBox([reviewer, methods, reviewer_model]),
        w.HBox([reviewer_path, reviewer_digest, button("Configure reviewer", configure_reviewer),
                button("Test selected reviewer", smoke_reviewer)]),
        w.HBox([reviewed_book, occurrence, proposal, candidate]),
        w.HBox([staging_id, button("Staging template", candidate_placeholder),
                button("Stage verified candidate", stage_candidate)]),
        w.HBox([exported, decision, button("Record decision", lambda: review_action("decide"))]),
        w.HBox([button(label, lambda action=action: review_action(action)) for label, action in (
            ("Findings", "findings"), ("Request primary", "primary"), ("Second opinion", "second"),
            ("Export proposal", "export"), ("Approve exact diff", "approve"),
            ("Confirm publication", "publish"), ("Decline publication", "decline"))]),
        output,
    ]))
