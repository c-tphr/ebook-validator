# EPUB validator v4 — behavioral analysis and acceptance checks

**Handoff to Astra 6.2.** Begin once v3 is complete. Review the delivered CLI, the [v1 disposition rules](BUILD-BRIEF.md), the [v2 repair contract](V2-BUILD-BRIEF.md), the [v3 approval and publication rules](V3-BUILD-BRIEF.md), and the v4 research findings when available. Spawn Sol 6.2 to implement v4. Independently verify the resulting behavior on Linux and WSL.

## When to run

Automatically test every EPUB that clears v1 security checks before the utility releases it for opening or repair. This includes structurally deficient repair candidates. Support explicit investigation of quarantined books and preserve their quarantine disposition after a quiet investigation. Preserve the existing report-only contract for predicted file and queue actions.

Before v2 or v3 publishes a repaired version, test the exact candidate bytes through the same behavioral gate. Keep earlier accepted versions and the original recoverable. A finding or hold on the candidate applies to that candidate. Continue to enforce v3's user approvals, including the separate decision for a persistent targeted warning.

## What the engines must observe

- Use two distinct EPUB rendering engines. Record their identities, versions, effective settings, and material differences. Two applications using the same underlying renderer do not fulfill the two-engine requirement.
- Run both offline in isolated, disposable environments with comparable settings and the same bounded navigation sequence. Visit the book's reading-order items and exercise internal navigation, including the TOC and footnotes when present. Record the actions, targets, completed coverage, and anything skipped. Keep ordinary external links unactivated.
- Block external connections, access to host data, and external application launches. Observe attempted actions at the relevant boundary. Keep book bytes read-only and use isolated reader state. Distinguish reader startup activity, ordinary rendering dependencies, and user-directed navigation from automatic activity attributable to the book.
- Verify both engines and their event monitors are healthy before starting the batch. Pause on startup failure, leave untested items pending, and resume when both engines and monitors are healthy. A monitor failure cannot produce a passing result.

## Decision rules

| Evidence | Decision |
|---|---|
| Either engine observes an automatic outbound request, an attempted read outside the EPUB, or an external application launch attempt attributable to the book | Quarantine even when blocked. Name the action, engine, preceding navigation step, and attribution evidence. |
| An event could be attributable to the book or the reader | Run one controlled comparison. Apply the observed-behavior rule if attribution is established. Hold if uncertainty remains. If established as reader background activity, record that conclusion and evaluate the remaining evidence. |
| Either engine crashes, times out, or skips required content during the book's run | Hold for review and identify the coverage gap. An established quarantine trigger in either engine still takes precedence. |
| Both engines complete required coverage without a blocking finding | Release the behavioral gate for this version and configuration, subject to the other applicable checks and approvals. |

Allow an explicit, reasoned user override of a **review hold**. Bind it to the exact book hash and test configuration, and preserve the observed result alongside the override. Keep quarantine decisions and existing approval requirements in force.

## Evidence, retention, and reuse

Record the book or candidate hash, engine versions and settings, test configuration, navigation coverage, relevant blocked events, attribution evidence, and disposition. Redact sensitive URL values in the decision record. Retain detailed traces locally for held or quarantined books for a configurable period and implement expiry. Identify temporary traces separately from the durable decision record.

Reuse a completed result only for identical bytes under the same test configuration. Include both engines, effective profiles, navigation plan and limits, monitor configuration, and decision policy in the configuration identity. Publish the verified bytes. Sol should document the engine pair, isolation and monitoring prerequisites, coverage limits, retention setting, and any platform differences.

## Independent acceptance checks for Astra

| Check | Expected evidence |
|---|---|
| Intake and quarantine routing | A v1-cleared clean book and a repair-eligible book reach both engines before release. A quarantined book is investigated only on request and remains quarantined after a quiet run. Report-only leaves the protected files and queues untouched. |
| Two engines and comparable coverage | Using a benign book with multiple chapters, TOC links, footnotes, and an ordinary external citation, verify distinct renderer identities, comparable settings, matching planned actions, per-engine coverage, and an unactivated external citation. |
| Isolation and observation | On Linux and WSL, verify enforcement and observation independently using benign local probes, synthetic monitor events, and empty disposable reader profiles. Check automatic outbound, out-of-book read, and external launch decisions. Record which boundaries were exercised end to end and which classifier paths used simulated events. |
| Attribution and precedence | Reader background activity alone must not quarantine a book. Exercise an attributable event seen in only one engine and ambiguous events resolved both ways. Verify exactly one controlled comparison for ambiguity, a hold for unresolved attribution, and quarantine when one engine supplies a decisive trigger while the other is quiet or incomplete. |
| Book failure and infrastructure failure | Separately simulate a crash, timeout, and skipped chapter during a book run. Verify a hold and an accurate reason. Start a batch with one engine or monitor unavailable. Verify a pause, pending work, and successful resume after recovery. |
| Overrides and retention | Require a reason for hold release. Change the bytes or configuration and confirm the override no longer applies. Inspect decision records for sensitive URL values. Verify local trace expiry for held and quarantined books while the decision and override remain auditable. |
| Candidate publication and reuse | Exercise v2 and v3 paths, including a v3 persistent-warning approval. Require both the applicable approval and the behavioral decision. Change a candidate after testing and confirm publication is gated again. Check reuse for identical bytes and configuration, and invalidation after changing either engine, settings, or navigation coverage. Confirm rejected outputs leave earlier versions intact. |

Return a readiness assessment with the engine and OS versions, evidence for each check, v1–v3 regressions tested, and any gaps in live platform coverage.
