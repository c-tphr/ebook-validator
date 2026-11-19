# V4 behavioral acceptance

## Implementation and qualification scope

The acceptance contract is the supplied v4 brief. The v1–v3 CLI, its SQLite queue, and its immutable publication path are present. The research memo's description of an empty checkout predates that delivery.

The selected EPUB frontends use Qt 5 QTextDocument and WeasyPrint. They share package and itinerary code and use distinct layout engines. Both can render headlessly without a desktop session, an external browser or an application handler. This choice makes automatic resource requests observable at the point where layout asks for content. The tested profiles cover reflowable text. Each result must identify unsupported material, navigation shortfalls, and whether evidence came from a renderer, an isolation control, or a simulated event.

The host is Debian 13 x86-64, Linux 6.18.57. It restricts creation of unprivileged user namespaces. Two Debian guests under QEMU each run Linux 6.12.107, UID 1000, on two ext4 volumes with no external NIC. An initial unprivileged Bubblewrap check painted text in Qt 5.15.15 and emitted a PDF through WeasyPrint 70.0. The operator confirmed that a WSL 2 runner is unavailable and will test that platform separately.

Before v4 changes, 27 implementation tests and 47 independent v1–v3 checks passed on the Linux host.

## Independent workflow and regression checks

The host suite exercises the public CLI, SQLite state, EPUB snapshots and real repair writer. It injects deterministic reader receipts and scanner verdicts for failures and recovery. The native and guest renderer runs are recorded separately.

| Check on the Debian host | Passing evidence with controlled readers |
| --- | --- |
| Intake and investigation | Clean and layout-deficient books reach both test readers. A static quarantine does not render the book until explicitly investigated. A quiet investigation preserves its bytes and quarantine disposition. Preview preserves an existing protected tree including timestamps and creates no queue in an empty tree. |
| Attribution and precedence | A blocked request, file read, and launch in one test reader each quarantine despite the other reader timing out. Simulated reader background releases. A single grouped comparison per affected engine resolves trusted reader or book provenance, and holds on an unmatched or wrong-step event. The durable record omits a synthetic sensitive URL value. |
| Failure and readiness | Separate crash, timeout, skipped, empty, and divergent navigation receipts prevent release. Failure of preflight leaves the book pending. A mid-run monitor failure cannot be overridden. The book runs again after recovery. |
| Override and retention | Empty reasons and quarantine overrides fail. A reasoned override preserves the underlying hold. Changing the bytes or engine invalidates it. Expiring held/quarantined traces preserves the decision and override rows. |
| Publication and reuse | V2 publishes the hash passed to both test readers. Substitution before copy prevents publication. Crash-before-link recovery rechecks the gate under a changed configuration. Candidate quarantine preserves an earlier accepted edition. A v3 persistent warning requires its own exact-candidate decision even after a behavioral hold override. Identical bytes/configuration reuse the decision after fresh preflight. A changed book, engine version or step limit causes a new run. |

[Test implementation](acceptance/test_v4_independent.py) · [Live gate harness](acceptance/v4_live.py) · [Benign EPUB fixtures](acceptance/v4_books.py)

## Independent host results

All 90 automated checks passed on Debian 13. The 47 prior acceptance checks comprise 7 v1, 18 v2 and 22 v3 checks. They cover v1 security and routing, v2 repair and recovery, and v3 review, proposal approval and publication. The 15 new independent cases exercise the v4 workflow with controlled reader transport. The remaining 28 checks are the project's implementation tests. Separate direct calls to the installed renderers produced 12 real engine receipts on the host. Host namespace restrictions limit those receipts to renderer evidence.

[Earlier regression results](acceptance/evidence/v4/regressions.txt) · [Independent v4 results](acceptance/evidence/v4/independent.txt) · [Implementation test results](acceptance/evidence/v4/unit-tests.txt) · [Host renderer receipts](acceptance/evidence/v4/host-renderers.jsonl) · [Tested source hashes](acceptance/evidence/v4/source-sha256.txt)

## Independent Linux guest results

The guest harness uses the production supervisor, SQLite and two fresh, individually isolated readers. The common viewport is 768 × 1024, the font family is DejaVu Sans, and each engine has a 600-second allowance under CPU emulation. On the clean fixture both engines completed the same seven actions, including both spine items, a footnote, its backlink, the TOC document and both TOC destinations. Each produced a page receipt per action and recorded one external citation left idle.

| Benign fixture | Gate decision in the Linux guest | Observed evidence |
| --- | --- | --- |
| Clean multi-chapter book | Release | Both engines completed all seven actions and an identical repeat reused the decision. |
| Missing footnote destination | Hold | The required destination was skipped and both engines recorded a coverage gap. |
| HTTP image | Quarantine | Both renderers requested the book-supplied image while rendering the first spine member. The host loopback listener received zero connections. |
| File image outside the archive | Quarantine | Both resource callbacks denied the request and recorded the originating step and member. |
| Fixed-layout declaration | Hold | Both readers identified material outside the common reflowable profile. |
| CSS background image on a semantic element | Quarantine | WeasyPrint requested the image. Qt recorded incomplete coverage because its semantic-container mapping can affect author CSS selectors. The WeasyPrint finding determined the book's disposition. |

The final clean run recorded 36 WeasyPrint events attributed to reader activity and released. Qt's image runs also had ambiguous native activity. Each run performed one controlled comparison, retained the uncertain events, and quarantined on the independently attributed image callback. In the CSS case the decisive callback was WeasyPrint's request from `two.xhtml` at step 1.

The isolation preflight uses positive controls. It observes denied IPv4 stream and datagram sockets, an external executable invocation, a host-only file read, and a write to the mounted input. It also requires successful observation of blocked renderer resource callbacks. The preflight dispatch attempt is a real kernel control. Book-attributed external launch classification uses a synthetic monitor event. These passive reader profiles provide no automatic external application handler. Ambiguous-event comparison, infrastructure recovery, operator overrides, expiry and publication-time byte substitution use deterministic host tests.

Independent testing initially found failing Bubblewrap startup, a missed footnote anchor, incomplete page receipts being accepted, and an automatic CSS fetch hidden by markup normalization. Sol corrected those failures. The final checks also exercise same-step event provenance, monitor failures, and recovery of a completed resource receipt after a reader interruption.

The forced-exit check used Qt with a benign remote image and injected a process exit after its actual resource callback. The supervisor retained the blocked action, member and navigation step. Timeout and independent monitor-loss decisions were exercised with controlled failures on the host.

[Final-source guest matrix](acceptance/evidence/v4/shipping-probes.jsonl) · [Guest configuration and source identity](acceptance/evidence/v4/guest-environment.txt) · [Earlier qualification matrix](acceptance/evidence/v4/guest-matrix.jsonl)

## Publication evidence

The v2 guest check runs the public `scan --repair` command with ClamAV 1.4.6, signed daily definitions, EPUBCheck 5.4.0, both behavioral readers and two ext4 volumes. A packaging defect makes the original eligible for repair. The check verifies the original and intake hashes, compares every decompressed ZIP member before and after the repair, and hashes the published file independently. The candidate must have complete security and quality results with no findings, a behavioral release and a new SHA-256.

The v3 guest check runs the real proposal, decision, staging and publication workflow with both native readers. Scanner and reviewer responses are controlled for this persistent-warning case. The first approval leaves the candidate staged. An incorrect hash cannot publish it. The second approval of the exact candidate publishes bytes identical to the staging file, while the original stays unchanged.

Both final-source guest publication checks passed. Reading the two v2 ext4 volumes independently confirmed that the intake copy and original were identical, all five EPUB members retained their contents, and the published file matched the candidate gate hash. The v3 check independently hashed the staged and published files.

| Final-source guest check | Tested and published SHA-256 |
| --- | --- |
| v2 mechanical repair | `96cba40954d967d269bb35524d53f6e4837e40b8dcb793150af1c7a13751fae9` |
| v3 persistent-warning approval | `265472762fb2658088ca4cbe133ad2c64ab5103d20d50d2db03094b2f45149a1` |

[Publication and volume evidence](acceptance/evidence/v4/publication.json) · [Guest assertions and exit status](acceptance/evidence/v4/guest-publication.txt)

**Readiness.** All seven contract areas passed at their stated evidence levels for the tested Debian configuration. No open Linux blocker was found. WSL 2 needs separate operator qualification. Book-origin external launch attribution remains simulation-only. The common reader profile sends unsupported content to review.

## WSL operator qualification

The Windows and WSL builds, WSLg/interop isolation, denial of Windows-side file/egress/launch canaries, and behavior across a WSL restart are unverified. Run the native gate harness and one guarded repair in the target WSL 2 distribution. Check that the worker cannot see the host drives, interop sockets or display session. Use Linux ext4 for the queue, intake, quarantine and repaired outputs. The inherited storage policy rejects Windows-mounted disposition paths. Verify that rejection on the actual installation.

From the repository root in the target WSL distribution, use the system Python that has both engine bindings installed. The harness creates its own benign books, host-only file and listening loopback canary.

```sh
uname -a
/usr/bin/python3 -m acceptance.v4_live --timeout 600
./epub-triage scan --repair --config /path/to/operator-test.toml
```

For the repair run use a disposable ext4 library with a known repairable layout defect. Compare the SHA-256 of the published file with the repair output hash and the candidate behavioral decision hash. Keep the distribution/kernel, Bubblewrap and engine versions with the result.
