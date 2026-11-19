# EPUB validator v2 — repair brief and acceptance checks

**Handoff to Astra 6.2.** Begin once v1 is complete. Review the delivered CLI, its queue and findings formats, the [v1 brief](BUILD-BRIEF.md), and the v2 research findings. Spawn Sol 6.2 to implement the repair workflow. Independently review and test the result on Linux and WSL. Record evidence and any unverified behavior.

## Select the work

- Repair is opt-in. A standalone repair command processes pending queue entries, including eligible entries written by v1. An explicit scan-and-repair flag processes only eligible books from that scan. Ordinary scans retain their v1 behavior.
- Verify the bytes to be repaired against the queued intake hash. On mismatch, skip the book, report the reason, and continue. A fresh scan can establish eligibility again.
- Use v1 isolation, scanner readiness, signature freshness, and resource limits. Keep library originals and repair-intake copies read-only. Build candidates in temporary storage inside the offline sandbox. Keep repaired outputs out of recursive intake scans.

## Plan and apply edits

| Decision | Required behavior |
|---|---|
| Default mechanical profile | Apply rules with one demonstrably correct result. An initial candidate rule is to fix placement or compression of an otherwise valid EPUB `mimetype` entry. |
| Explicit broader profile | Also allow internal reference corrections and metadata reconciliation when the book itself supplies unambiguous evidence. A unique case match can support a reference fix. Conflicting targets or metadata values leave the issue unresolved. |
| Heuristic findings | Books with only heuristic findings remain review-only. Preserve warnings on mixed-finding books and limit automatic edits to supported defects. Codex CLI integration is deferred. |
| Digital signatures | If a proposed edit would invalidate an existing signature, refer the whole book for review, identify the edit and signed content, and leave the book untouched. Where signature impact cannot be established, record the uncertainty for review. |
| Report-only | List proposed edits, locations, and supporting evidence. Label the plan unverified. Do not generate or validate a repaired EPUB, change the queue, or write a repaired output. Combined scan-and-repair honors the v1 report-only contract throughout. |

Sol should document the initial rule catalog, evidence each rule requires, and cases it skips. A successful validation result alone cannot establish that an edit preserved the intended chapter, text, or metadata value.

## Verify and publish

1. Run the full v1 security and quality checks on the exact candidate bytes. Accept only if every security check completes, no quarantine trigger occurs, at least one targeted defect is resolved, and no new findings appear. Remaining findings are allowed. Compare individual findings so that fixing one issue cannot conceal a new issue with the same count or code.
2. On retry, rebuild from the hash-verified intake copy and compare with the latest accepted version as well. Previously fixed defects must stay fixed. Keep outstanding findings visible. Retry an accepted partial repair when a relevant rule changes or a broader profile is selected. Skip repeat work under unchanged conditions.
3. If edits together fail verification, discard the entire candidate, report the failed checks, preserve earlier outputs, and continue to the next book. Apply v1 operational-failure handling when the verification infrastructure itself is unavailable.
4. Publish each distinct accepted version in a configured repaired-output folder. Preserve the original and intake copy. Identify the latest accepted version in the report and avoid duplicating identical outputs. Make publication recoverable across interruptions and concurrent runs.
5. Retain a per-edit record with the rule, affected location, change, supporting evidence, and before-and-after validation findings. Associate the record with the input and output hashes and profile so an operator can trace a version to the edits that produced it. Preserve v1's scriptable reporting conventions.

## Independent acceptance checks for Astra

| Check | Evidence to collect |
|---|---|
| Entry points and compatibility | Start with a pending v1 queue entry. Verify standalone repair handles it, a scan-and-repair run handles only the current scan, and an ordinary scan performs no repair. Change one intake copy and verify it is skipped while the next eligible book proceeds. |
| Profile and evidence boundaries | Use benign examples of a packaging defect, a unique internal reference correction, an ambiguous target, corroborated and conflicting metadata, and a heuristic-only warning. Check profile defaults, skipped edits, preserved content, and supporting evidence. |
| Report-only | Exercise both entry points. Inspect the reported edits and evidence, confirm no candidate writer or candidate verifier ran, and compare originals, intake, queue, and output directory before and after. |
| Signed content | Plan a change affecting signed content alongside another eligible edit. Verify the entire book goes to review, the affected content is identified, and no output is published. |
| Acceptance boundary | Accept a partial repair. Reject a no-op, a newly introduced finding even if total counts decline, an incomplete security check, and a quarantine trigger. Verify a failed multi-edit candidate is discarded as a unit and the batch continues after book-specific failures. Use controlled test doubles for failure paths as needed. |
| Retry and version history | Verify an unchanged rerun skips work. Change a relevant rule or broaden the profile and confirm the next attempt starts from intake. Reject regressions against the latest version. Verify distinct accepted versions survive and identical output bytes are stored once. |
| Isolation and file integrity | Verify offline processing, refusal when isolation or scanner preflight fails, and read-only source handling on Linux and WSL. Exercise a collision, interruption, and concurrent publication. Check that records resolve to complete outputs and that failures leave prior versions recoverable. |
| Audit and regression | Parse CLI output, trace a published EPUB through its edit records and findings, and rerun v1 acceptance checks affected by queue handling, reporting, and folder traversal. Identify platforms and checks actually exercised. |
