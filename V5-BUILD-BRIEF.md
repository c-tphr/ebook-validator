# EPUB validator v5 — Google Colab and Drive

**Handoff to Astra 6.2.** Begin after v4 is complete. Review the delivered implementation and the v5 documentation research. Spawn Sol 6.2 to build a single-user, interactive notebook for hosted Google Colab. Reuse the existing validator and its decision rules. Independently verify the notebook from a fresh hosted runtime using benign EPUBs and test Drive folders.

## Notebook workflow

1. **Set up.** One action installs pinned dependencies, verifies them, and reports readiness per stage. Show what passed, which prerequisite failed, and which work is pending. Run all workers in Colab. Allow setup downloads, signature updates, Drive transfers, and explicitly requested model-provider calls through their respective components. Keep untrusted inspection, rendering, and repair offline and isolated from Drive, credentials, and unrelated books.
2. **Select.** Configure a dedicated intake and destinations for quarantine, repair intake, repaired editions, reports, and evidence. Support My Drive and folders shared with the signed-in account when it has the permissions needed for the operation. Select an intake folder, subfolder, or individual EPUBs within intake. Enforce that boundary for selected IDs and shortcuts as well as displayed paths. Exclude generated outputs from discovery.
3. **Run and inspect.** Offer the [v1 scan](BUILD-BRIEF.md), [v2 optional repair](V2-BUILD-BRIEF.md), [v3 optional agent review](V3-BUILD-BRIEF.md), and [v4 behavioral gate](V4-BUILD-BRIEF.md). Show per-book decisions and a run summary. Honor report-only semantics and existing gates. Automatically move qualifying intake files to quarantine and write accepted outputs and reports to the configured Drive folders. Stage bounded batches on temporary runtime storage, enforce a configurable storage limit, and clean up completed or abandoned staging.
4. **Handle missing capabilities.** If an operation cannot run with verified isolation and healthy tools, show why and keep affected work pending. In particular, v4 requires two distinct engines and working monitors before its batch can proceed. Reviewer authentication is required only for the requested reviewer. No external worker fallback.

## Durable state and Drive operations

- Keep enough state in Drive to show completed, pending, held, and ambiguous work after losing the runtime. Preserve decisions, proposal IDs, approvals, hashes, configuration identity, and pending file operations. Keep detailed traces of held and quarantined books in a dedicated Drive evidence folder. Apply the configured expiry when the notebook runs and retain the durable decision evidence.
- Before a quarantine move or publication, check that the intake file still matches the scanned identity and bytes. If it changed, preserve the current file, pause that book, and offer a fresh scan. Continue independent books. Protect occupied destinations and publish only verified candidate bytes.
- On reopening, show progress and wait for **Resume**. Recheck identities, settings, prerequisites, and writer ownership. Reconcile interrupted moves and uploads using recorded identities, content, and destination state. Complete clearly pending work, recognize an already completed operation, and pause only ambiguous books. A repeated Resume must not duplicate a move, output, or approval.
- Allow one writer per intake. A second notebook can inspect status. Require explicit takeover of an interrupted run and prevent the old session from committing subsequent changes, including queued or retried operations. Sol should document how the chosen Drive integration handles concurrent writes, permission changes, and partial operations.

## Agent review

Offer Codex CLI, Claude Code CLI, and Google Antigravity CLI (`agy`). Offer per-session sign-in and Colab secrets wherever each CLI supports them. Show available methods and reviewer readiness. Keep credentials out of notebooks, saved cell output, Drive artifacts, and untrusted workers.

Use a configured pair of distinct reviewers by default. Show the pair and allow changes before the user requests an independent second opinion. Retain v3's book-access scope, diagnostic restrictions, independent review context, interruption behavior, and exact-diff approvals. Inline notebook and file-based review use the same proposal IDs. Recheck the book version, approved diff, and required publication decisions after resume.

## Independent acceptance checks for Astra

| Scenario | Evidence to collect |
|---|---|
| Fresh hosted runtime | Start from the distributed notebook. Run the single setup action and record versions, platform, and readiness per stage. Exercise the full supported path from Drive input to an accepted Drive output. Identify every stage demonstrated live or still blocked. |
| Isolation and prerequisites | For each real engine and monitor, verify comparable navigation, observation of a harmless blocked action, offline enforcement, and isolation from Drive, credentials, and unrelated staged files. Use disposable markers. Disable a prerequisite and confirm affected books remain pending. A simulated event alone cannot establish live isolation. |
| Scope and permissions | Exercise an owned intake, a permitted shared folder, insufficient permissions, and an outside-intake selection or shortcut. Check recursive selection, individual selection, output exclusions, and prevention of unauthorized writes. |
| Staging and dispositions | Run enough benign fixtures to exceed one staging batch. Check the configured cap and cleanup. Verify clean, repair-eligible, held, and quarantined outcomes, report-only previews, trace retention and expiry, and preservation of earlier editions. |
| Disconnect and conflict | Interrupt a move and an upload before and after the Drive mutation. Reopen, inspect progress, and click Resume twice. Check both recognition and completion of operations. Change an intake file and a relevant setting in separate trials. Confirm stale results cannot authorize a move or publication and that ambiguous books are identified. |
| Two sessions | Attempt simultaneous writer acquisition. Verify one writer, read-only status in the other session, explicit takeover after interruption, and rejection of a stale writer's delayed commit. |
| Reviewer integration | Exercise all three CLIs and each claimed authentication method in hosted Colab. Show and change the reviewer pair. Verify independent context, matching proposal IDs in both interfaces, and invalidation of stale approvals. Check saved outputs and Drive records for credential exposure using test values. |
| Regression and readiness | Recheck v1–v4 decisions touched by the notebook, especially repaired-byte verification and persistent-warning approval. Report actual hosted-runtime results separately from local tests, mocks, and unavailable account-dependent checks. |
