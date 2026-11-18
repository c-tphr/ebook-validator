# EPUB validator v1 — implementation and acceptance brief

**Handoff to Astra 6.2.** Spawn Sol 6.2 to implement this CLI. Give Sol this brief and the research findings when available. Oversee implementation, independently review the changes, and run the acceptance checks. Ask Sol to address failures and recheck the fixes. Record the environment and evidence for each check, including any platform behavior that still needs verification.

## Purpose

Help a reader decide which downloaded EPUBs to open, quarantine, or keep for repair. Report security coverage and structural quality independently. A completed scan describes what the configured checks found. Automatic repair is future work.

## Invocation and preflight

- Support Linux and Windows through WSL. Require a configured intake folder unless `--folder PATH` supplies the root for this invocation.
- Scan recursively by default and honor `--no-recursive`. If relative filenames are supplied, inspect exactly those books. Keep selection within the root, skip symlinks and exclude the quarantine directory. Also exclude the repair intake directory from traversal to prevent reprocessing.
- Sol chooses the sandbox. Perform all untrusted EPUB inspection offline, with read-only access to the input. Refuse to inspect if isolation cannot be established.
- Require a functioning malware scanner and signatures published within the last 72 hours. At startup, attempt an online update if signatures are stale. If readiness or freshness cannot be established, stop before moving any books. The updater operates separately from the offline inspection environment.

## Per-book disposition

| What the CLI observes | Action |
|---|---|
| Malware signature match, unsafe archive condition, active content such as JavaScript, or a remote resource a reader may load automatically | Quarantine. Record the specific trigger. Ordinary clickable web links are allowed. |
| A book-specific condition such as encryption, corruption, or a resource limit prevents a security check from finishing | Quarantine. Identify the incomplete check and reason. Reserve malware-detection wording for an actual detection. |
| Security checks complete without a quarantine trigger and a quality check verifies a defect | Leave the original in place, copy it to repair intake, and add a repair queue entry. |
| Security checks complete without a quarantine trigger and quality findings are heuristic only | Take the same repair-staging actions and mark the book `needs_review`. |
| All checks complete without findings | Report the result and leave the book in place. |

Quarantine takes precedence over repair staging. Check EPUB conformance and verifiable reader-facing defects such as broken navigation targets. Label heuristic findings such as suspected OCR corruption or suspicious chapter order separately. A broken manifest can qualify for repair when every security check still completes. An infrastructure failure is an operational error and must never trigger mass quarantine.

## Files and reporting

- Move qualifying books automatically to a configured quarantine directory. Preserve paths relative to the active scan root and protect existing files from overwrite.
- Use a configured repair intake directory and a separate machine-readable queue. Include the source path, content hash, findings, and a reference to the complete repair copy.
- Emit one JSONL record per book on stdout and a readable batch summary on stderr. Use distinct exit codes for a clean run, a completed run with findings, and an operational failure.
- Support `--report-only` with either root selection method. Report predicted actions while leaving originals, quarantine, repair intake, and queue untouched.

## Acceptance checks for Astra

1. **Isolation.** Verify offline inspection and read-only source access on Linux and WSL. Make isolation unavailable and confirm inspection refuses to start. Record whether each platform was actually tested.
2. **Preflight and failures.** Exercise fresh signatures, stale signatures followed by a successful update, and an unavailable scanner or failed freshness check. Confirm a failed preflight leaves books in place. Distinguish a book-specific inspection limit from a failed worker environment.
3. **Decision boundaries.** Use benign fixtures or controlled test doubles for a signature match, active content, a clickable link, an automatically loaded remote resource, incomplete security coverage, a verified navigation defect, a broken manifest with full security coverage, a heuristic-only finding, and a clean book. Verify reasons, precedence, queue contents, and disposition.
4. **File integrity.** Exercise nested paths, duplicate names, occupied destinations, concurrent or repeated runs, interrupted moves or copies, and a queue-write failure. Verify original bytes remain recoverable, existing files survive, and every queue entry resolves to a complete copy.
5. **CLI contract.** Parse stdout as JSONL and inspect stderr and exit codes. Test configured and overridden roots, default recursion, top-level scans, symlinks, excluded output directories, and explicit selection of two files in a larger folder. Compare a report-only preview with a normal run on equivalent inputs.

Sol owns the choice of backend, validator, scanner, limits, quality heuristics, configuration format, collision naming, JSONL schema, and numeric exit codes. Document the choices and their limits so Astra can verify them.
