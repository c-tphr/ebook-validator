# EPUB validator v3 — agent-assisted review and acceptance checks

**Handoff to Astra 6.2.** Begin once v2 is complete. Inspect the delivered review queue, version history, repair pipeline, and [v2 acceptance contract](V2-BUILD-BRIEF.md). Spawn Sol 6.2 to implement both Codex CLI and Claude Code CLI integrations. Oversee the work, independently verify it on Linux and WSL, and have Sol correct failures. V3 can start with fresh agent-review records.

## Start and scope a review

- Start model calls only on an explicit request to review a selected book, a selected finding, or a batch of pending findings. Allow either CLI as primary reviewer. Run unattended batches directly within configured limits and leave excess findings pending.
- For each book, select the latest accepted repair when available. Otherwise use the verified intake copy. Verify the selected bytes against their recorded hash and review findings that still apply to that version. Quarantined books and books with incomplete security coverage are ineligible.
- The selected CLI may send the whole extracted content of the selected book to its model provider as needed. Give it read and search access within that book and a defined set of local diagnostics, such as comparing chapter headings or counting spelling variants. Treat book text and agent responses as untrusted data. Enforce access limits outside the model. Review cannot grant shell access, alter files, approve an edit, or publish an EPUB. Keep model communication separate from v2's offline inspection and repair workers.
- If the selected CLI becomes unavailable or reaches a usage limit, save completed reviews, pause the batch, and leave unfinished findings pending. Resume with the same reviewer without repeating completed work.

## Assess the finding and capture a decision

1. A reviewer may explain that a passage appears intentional, identify uncertainty, or propose an exact edit. Show the original passage, precise diff, and supporting evidence before requesting approval. A suggestion to investigate further is a valid outcome.
2. On request, have the other CLI independently assess the same finding on the same book version. Give it access to the book and approved diagnostics in a fresh review context. Withhold the first assessment and diff until the second review is complete. Present both assessments side by side. The user may choose either exact diff, reject both, or defer.
3. Support interactive terminal decisions and exported proposals approved by ID in a later command. Use the same stable proposal IDs and approval rules in both interfaces. Bind approval to the exact book hash and diff displayed. Recheck both before applying. A changed book requires a fresh proposal, even if the affected passage still matches. Changing an exported diff invalidates its approval.
4. When the user marks a particular occurrence intentional, remember that decision across runs. Reopen it if the relevant passage or finding changes. An unrelated edit elsewhere in the book should preserve the decision. Keep this occurrence-level decision distinct from edit approval, which is bound to the whole book hash.
5. Retain the exact diff for each proposed edit, cited passages or locations, reviewer rationale, diagnostic results used, reviewer identity, and the user's decision. Connect these records to the finding, reviewed book version, verification results, and any published version.

## Apply, verify, and publish

Apply only explicitly approved edits to a temporary candidate from the reviewed version. Reuse v2's isolation, signed-content policy, regression checks, output versioning, and file-preservation rules. Run full security and quality verification on the exact candidate bytes.

| Verification outcome | Disposition |
|---|---|
| The targeted heuristic warning clears and all other acceptance checks pass | Publish the verified candidate through v2 and record the result. |
| The approved edit was applied, the same targeted warning persists, and all other checks pass | Show the verified candidate, actual change, and remaining warning. Require a separate explicit decision to publish those exact candidate bytes. Leave the candidate unpublished while awaiting the decision. |
| A new finding appears, a previously fixed defect returns, security coverage is incomplete, or another v2 check fails | Block publication and record why. The persistent-warning decision applies only to the original targeted warning. |

## Independent acceptance checks for Astra

| Check | Evidence to collect |
|---|---|
| Both CLIs and invocation scope | Exercise each CLI as primary with a benign book. Select one finding, one book, and a bounded batch. Verify ordinary scan and repair commands make zero model calls, and findings beyond the batch limit remain pending. |
| Input selection and access | Provide different text in the intake copy and latest accepted repair. Verify the reviewer sees the accepted version and uses intake when it is the only eligible version. Check that a full-book search and an approved diagnostic work while access to another book, file mutation, and unapproved tools are denied. |
| Independent second opinion | Exercise both reviewer orders. Inspect the second request for independence. Present conflicting diffs for one finding and verify that choosing either, rejecting both, and deferring each produce the corresponding decision. |
| Approval integrity | Approve through the terminal and by exported ID. Verify only the displayed edit is applied. Try a changed book with an identical target passage, a modified exported diff, and a deferred proposal. None may reuse a previous approval. |
| Publication boundary | Verify the warning-cleared path. For a persistent warning, exercise both accepting and declining publication after verification. Confirm the second decision binds to the verified bytes. Introduce a new finding, an incomplete scan, a quarantine trigger, and a signed-content conflict in separate cases. Confirm each blocks publication and preserves prior editions. |
| Intentional occurrences | Mark one occurrence intentional in a book with two similar passages. Verify only that occurrence is suppressed. Make an unrelated edit, then change the relevant passage or finding, and check that suppression persists in the first case and review reopens in the second. |
| Interruption and audit | Interrupt a batch after one completed review and simulate a provider usage limit. Resume with the same reviewer and check for lost or duplicated work. Trace an accepted edit from reviewer evidence through user decisions to output hash. |

Use controlled reviewer responses for repeatable decision tests and actual CLI invocations for integration evidence. Record the OS, CLI versions, checks run, and gaps in live coverage. Rerun the v2 acceptance checks affected by candidate selection, verification, and publication.
