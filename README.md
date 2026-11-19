# EPUB triage

`epub-triage` reports malware, static security findings, and observed reader behavior separately from EPUB and navigation defects. It moves quarantined books out of intake, stages repair copies, and records pending and completed file operations. A clean result describes the coverage of the configured checks.

For the Google Colab workflow, see the [v5 notebook release guide](V5-COLAB.md).

## Install

Run as an unprivileged user on a Linux system with working unprivileged Bubblewrap namespaces. On Windows, run inside **WSL 2** and keep intake, quarantine, repair intake, repaired outputs, the queue and the signature database on the Linux filesystem. Windows mounts such as `/mnt/c`, network filesystems and tmpfs-backed disposition paths are rejected. The launcher accepts ext-family filesystems, XFS, Btrfs and Linux overlay filesystems. The selected installation and filesystem need operational verification before production use. Directory synchronization and hard-link publication must be supported.

Install Python 3.11 or later at `/usr/bin/python3`, system Python packages `lxml` and `tinycss2`, Bubblewrap with user, network, mount, IPC, PID and UTS namespaces plus `--disable-userns` and sized tmpfs support, and compatible ClamAV tools `clamscan`, `sigtool` and `freshclam` under `/usr/bin`. Install a headless JRE at `/usr/bin/java` and an upstream W3C EPUBCheck release. The research reference versions were ClamAV 1.4.6 and EPUBCheck 5.4.0. Keep EPUBCheck's release directory, including its adjacent `lib` directory, together. Use trusted system packages and a verified upstream release. See the [acceptance report](ACCEPTANCE.md) for the versions and platforms actually exercised.

For behavioral reading, install PyQt5 with Qt 5 and the Qt offscreen platform plugin, WeasyPrint 70 with its Python dependencies and native Pango and Fontconfig libraries, DejaVu fonts, `libseccomp.so.2`, and `/usr/bin/strace` with child tracing. Install the Python modules for `/usr/bin/python3`. If they live in a separate trusted package directory, set `behavior_python_packages` to its absolute path. Keep that directory and the system runtime mounts free of protected data. The font package must supply `/usr/share/fonts/truetype/dejavu`. Linux user namespaces must be usable while tracing the unprivileged Bubblewrap process. See [V4 acceptance](V4-ACCEPTANCE.md) for live platform qualifications.

Create a dedicated ClamAV database directory controlled by the trusted FreshClam updater, and populate it with official main, daily and bytecode definitions. For in-command refresh, the scanning account must be able to run FreshClam against that directory. An existing empty directory is valid for initial refresh. External updaters sharing the path must acquire the same exclusive advisory lock on that directory for the duration of their update. Configure FreshClam to use the official service or a trusted mirror, with site-appropriate update configuration and no command hooks. This is the only runtime operation that needs Internet access. An offline site can stage a current trusted generation separately.

Set `~/.config/epub-triage/config.toml` or pass `--config`. Relative configuration paths are relative to the configuration file. Use real directories with no symlink aliases and keep them outside the trusted runtime mounts.

```toml
folder = "/home/reader/incoming"
quarantine = "/home/reader/quarantine"
repair = "/home/reader/repair-intake"
# repaired_output = "/home/reader/repaired-epubs"
queue = "/home/reader/epub-state/repair.sqlite"
database = "/home/reader/clamav"
epubcheck_jar = "/opt/epubcheck/epubcheck.jar"
# freshclam_config = "/home/reader/clamav/freshclam.conf"
```

Use one queue for cooperating invocations sharing an output tree. Cooperating producers must publish finished downloads by renaming them into the intake and must leave published paths and bytes alone while the scanner handles them. Keep the queue and output trees under the scanning account's exclusive administration. The scanner verifies the source and destination bytes and holds advisory locks. A writer ignoring those locks can race pathname operations. On WSL, keep disposition data in the distribution filesystem for the supported storage model.

## Run

```sh
./epub-triage
./epub-triage --folder /home/reader/other-intake --no-recursive
./epub-triage --report-only
./epub-triage --folder /home/reader/other-intake --report-only 'Series/Book 1.epub' 'Book 2.epub'
```

Discovery includes case-insensitive `.epub` extensions and recurses by default. Explicit paths select just those files, deduplicated in argument order, including nested paths even with `--no-recursive`. Directory and file symlinks are skipped, including in explicit selection. Absolute explicit names, parent references and explicit selection inside any output tree are errors. A nonexistent explicit regular file produces an operational error. Books in quarantine, repair intake and repaired outputs are excluded during discovery.

Report-only still checks isolation, scanner readiness and freshness and can refresh the external signature cache. It predicts destination names and reports recoverable pending operations without changing originals, outputs or queue. It uses Linux no-atime reads of protected data, so the scan account needs ownership of files and directories read during preview. Preview refuses a queue with an interrupted SQLite transaction or a nonempty SQLite WAL. Recover the queue with a normal run.

## Results

Stdout contains UTF-8 JSONL with one record per selected book after preflight. Preflight failures print to stderr before any disposition. The batch summary and operational diagnostics go to stderr.

| Field | Meaning |
| --- | --- |
| `path`, `source` | Original path relative to intake and absolute original path |
| `sha256` | Examined bytes or recorded source bytes on recovery. Can be null after an error. |
| `security`, `quality` | Each contains `complete` and `findings`. Quality can include `incomplete_reason`. A finding has `kind`, `code`, `detail` and, where applicable, the logical EPUB `member`. |
| `action` | `leave`, `quarantine`, `stage_repair`, `hold` or `error` |
| `status` | `clean`, `quarantine`, `behavior_quarantine`, `behavior_hold`, `behavior_pending`, `verified_defect`, `needs_review` or `operational_error` |
| `behavior` | Exact-byte behavioral decision, effective disposition, reader receipts, and any hold override |
| `destination` | Predicted or published absolute path, or null |
| `report_only` | Whether actions are predictions |
| `pending`, `recovered`, `intended_action`, `error` | Optional preview, recovery and operational context |

Security findings distinguish signature matches, unsafe archive structure, active content, remote automatic requests and incomplete coverage. Any of those takes priority over repair. When security requires quarantine, the worker preserves static quality findings and skips EPUBCheck. The quality report identifies why it is incomplete. Quality distinguishes verified defects from items for review. Standalone EPUBCheck warnings are routed to review. The standalone heuristic flags at least three Unicode replacement characters in XHTML text. A plain web anchor and a plain external NCX navigation link are allowed.

Exit codes are `0` for a completed run without findings, including an empty selection, `1` for a completed run with findings, and `2` for an operational or command-line error. An operational failure stops further inspection and disposition. Remaining selected books are reported as skipped with an operational error.

Quarantine and repair retain relative directories. An occupied basename is preserved and an operation-derived suffix is added before `.epub`. File publication uses an exclusive private temporary file, checksum verification, file synchronization, atomic hard linking without replacement and directory synchronization. Quarantine deletes the source only after verified publication. Repair retains the source and commits its queue entry only after the copy is durable. Pending operations in the selected scope resume on a normal run after preflight. If source bytes have changed or a pending destination conflicts, the run stops and leaves available bytes in place. An abrupt exit before temporary-file ownership can be journaled may leave an unreferenced private partial file. The utility leaves such files for inspection.

The SQLite queue's `repair_queue` table contains `operation_id`, `source`, `sha256`, `findings` (JSON text with security and quality reports), `status` and absolute `repair_copy`. The `operations` table is the disposition journal. Keep the journal alongside the queue when backing up or moving state.

## Behavioral reading

After a book clears static security inspection, both readers examine its exact snapshot before intake reports it as clean or stages it for repair. The same gate applies before v2 or v3 publishes a candidate, including interrupted publication recovery. A candidate decision applies to that candidate SHA-256. Earlier accepted editions and the original remain recoverable. The v3 targeted-warning publication decision remains separate.

```sh
./epub-triage behavior-investigate 'Series/Book 1.epub'
./epub-triage behavior-investigate --report-only 'Series/Book 1.epub'
./epub-triage behavior-override SHA256 CONFIGURATION_ID --reason 'Reviewed the omitted content offline'
./epub-triage behavior-expire
```

Select quarantined books by path relative to the quarantine root. Investigation is explicit and keeps the book in quarantine. Report-only runs can perform behavioral reading and predict file actions while leaving protected files, queue, decision data, and traces untouched. New runs use disposable scratch storage.

A book-attributed automatic outbound request, attempted out-of-book file read, or external application dispatch attempt requires quarantine even when blocked. Evidence identifies the engine, action, navigation step, and attribution. Ordinary external links stay inert. Observable reader startup and in-archive dependencies are recorded separately from book-attributed events. An ambiguous observation triggers one fresh control run for that engine with synthetic content and the corresponding navigation steps. Unresolved attribution and uncovered content require a hold. A renderer crash or timeout also requires a hold. An authenticated quarantine trigger takes precedence. A failed reader or monitor readiness control pauses the batch, and the next invocation can resume after recovery. Missing independent monitor evidence during reading prevents release or a hold override.

A hold leaves the intake item in place or keeps a candidate unpublished. An override requires the recorded book SHA-256, configuration ID, and reason. A later scan or publication attempt can use that decision for the same bytes and configuration. The original observation remains in the audit history. Quarantine and required v3 approvals remain in force. When software or coverage settings change, obtain a new decision before release.

### Effective reader profiles

- **Qt 5 QTextDocument** lays out rich text and paints 768 × 1024 offscreen viewports. The EPUB frontend maps supported semantic block containers to Qt's block model, reads anchor and hyperlink data from rendered fragments, and paints the viewport containing each selected destination. Author CSS combined with this mapping requires review.
- **WeasyPrint 70** applies its paged HTML/CSS layout with a 768 × 1024 pixel page. It reads links and anchors from page objects and produces an in-memory PDF for each visited page. Rendering retains the original HTML tag semantics.

Both use a private DejaVu Sans font environment, follow the same verified spine and package navigation, and exercise exposed internal links including EPUB TOC, EPUB 2 NCX destinations, and footnote links. Per-engine receipts record observed pages, skipped actions, and external links left idle. Rendering engines inherit different layout, CSS and pagination behavior. The common profile covers static reflowable XHTML with supported passive dependencies. Fixed layout, active and interactive content, linked CSS beyond the shared profile, multiple renditions, ambiguous references, missing destinations, and unsupported render features require review. This is a bounded reading test for these two engines. Other reading applications can have different rendering and activation behavior.

Each engine gets a fresh Bubblewrap environment with isolated network and reader state and a read-only EPUB mount. The platform runtime and dedicated fonts are read-only. Resource callbacks accept only supported passive members of the verified archive and record attempted automatic access across its boundary. Seccomp denies socket creation, connection, network sends, executable dispatch, and selected bypass syscalls. The independent `strace` monitor covers file-open, socket, connection, send and execution syscall families and ties observations to trusted startup or navigation markers. Font and operating-system runtime loads are accounted for separately. Startup tests require both renderers to paint and resolve a real control anchor, record synthetic image requests at their callback boundaries, and independently observe blocked TCP, UDP, a private host file lookup, a write-open against the read-only input, and executable dispatch. The startup dispatch probe exercises the kernel boundary. The reading profile does not run executable book content or activate external hyperlinks.

| Optional TOML setting | Default | Maximum |
| --- | ---: | ---: |
| `behavior_timeout` per engine run in seconds | 60 | 600 |
| `behavior_max_steps` per engine | 200 | 500 |
| `behavior_trace_days` | 14 | 365 |

Each engine also has a 100-page document limit, bounded resource callbacks, and a 1.5 GiB virtual address-space cap. Decision records in `behavior_results` and `behavior_decisions` preserve engine identities, effective settings, navigation receipts, event attribution, and disposition. `behavior_overrides` preserves operator decisions. URLs in these records use redacted fields and fingerprints. Detailed local run traces live in `behavior_traces` until their recorded expiry. Normal healthy runs expire them automatically, or run `behavior-expire` directly. Expiry leaves decision and override records available. Completed releases and decisive quarantines are reused only for identical bytes under the same configuration. Incomplete holds can be rerun unless an exact override already releases them.

## Opt-in repair

Configure `repaired_output` to enable repair. Keep it distinct from quarantine, repair intake, queue, and the signature database. It may be a subdirectory of the scanned library. The command excludes that subtree from discovery. The `repair` setting continues to name the directory holding intake copies.

```sh
./epub-triage repair
./epub-triage repair --profile broader --report-only
./epub-triage scan --repair --report-only 'Series/Book 1.epub'
./epub-triage scan --repair --profile broader
```

Standalone repair reads eligible entries in the configured queue, including older v1 entries and entries staged through a scan folder override. It uses the recorded intake copy and works after an original folder has been moved. Combined scan and repair considers only entries staged or selected for repair by the current scan. Ordinary scans continue to stage and report findings. Each repair checks the intake copy against its queued SHA-256. A changed or missing copy is skipped. A fresh matching scan can stage a new copy, preserving the damaged or occupied path and the version history for that input hash.

Report-only lists each proposed edit and its evidence with `verification: "unverified"`. It runs input checks and stops before writing or validating a candidate. It leaves the library, repair intake, queue and repaired outputs untouched. The same scan preflight and external signature cache policy apply.

### Rule catalog

| Rule | Evidence | Cases left for review |
| --- | --- | --- |
| **M1** · Both profiles | A regular root `mimetype` with the exact EPUB payload has a nonzero local ZIP offset or uses DEFLATE. Place it first and store it uncompressed. | Missing or incorrect payload, extra fields on this entry, a data descriptor on this entry, and unsupported or ambiguous ZIP layout. |
| **R1** · Broader | A link in the selected EPUB 3 navigation document or EPUB 2 NCX names an absent local document. The sole ASCII case match changes the filename only, belongs to the unambiguous active XHTML manifest, and contains the unique named fragment when present. Change just the corresponding ASCII letters in the original attribute. | Competing manifest declarations, directory or fragment case mismatches, a missing or duplicated fragment, redirects, alternate renditions, custom base URIs, percent-encoded or otherwise unsupported URLs, and XML attributes whose literal byte span cannot be established. |
| **D1** · Broader | A dangling EPUB 2 `unique-identifier` pointer has exactly one ASCII case match among XML IDs, on a Dublin Core identifier. The spine's associated NCX has exactly one `dtb:uid` whose text agrees exactly with that identifier value. Change only the pointer. | Conflicting identifiers, mismatched NCX metadata, alternate renditions, encryption or font obfuscation, and attributes whose literal byte span cannot be established. |

Heuristic-only findings remain review items. Mixed books can receive a partial repair with their existing warnings visible. Recognized signatures route the whole edit plan to review. The report identifies signature members, references, and any whole-member references whose input would change. The initial rules leave cases with unqualified signature coverage for review, including a signature whose visible references appear disjoint from a proposed edit.

### Verification and version history

The offline worker builds a candidate in private scratch storage from the original staged intake. It checks the ZIP directory, archive metadata, unchanged local records, payload hashes and edit postconditions. The supervisor hashes the transferred bytes and mounts them read-only for a separate full inspection using the pinned scanner definitions and EPUBCheck. Acceptance requires complete security and quality checks, zero quarantine triggers, a resolved targeted defect and zero new individual findings. An incomplete finding list prevents acceptance. A failed set of edits is discarded as a unit. Book-specific failures are reported and the batch continues. An unavailable verifier stops the batch.

An unchanged profile, rule revision and limits skip another editing attempt. A new profile or relevant rule revision can revisit a partial repair. A new accepted version must preserve the earlier fixes and make additional progress against the latest validated output. Each distinct result lives at `repaired_output/<sha256>.epub`. Publication checks for an existing identical object, uses a durable journal and publishes without replacing a path. A later invocation resumes interrupted publication for the selected entries. Earlier versions and intake copies remain available.

Standalone repair emits one JSONL record per selected queue entry with `phase: "repair"`. Combined runs include the same record in the owning scan record under `repair`. Read `decision`, `reason`, `edits`, `verification`, `sha256`, `output_sha256`, `destination` and `latest` for the result and version history. Evidence includes member and location, old and new values, rule and rule revision, member hash, and paired findings for each accepted edit. The record includes complete input and candidate reports as applicable. SQLite retains this evidence in `repair_attempts.report`, and `repair_versions` records the associated objects. Query completed versions with `ready = 1`.

Standalone exit status `1` indicates outstanding findings or an entry requiring operator attention. Combined runs keep the scan exit convention, so they return `1` if the scan found a defect even when repair succeeds. Exit status `2` indicates an operational or invocation error.

## Coverage and limits

Each book is inspected from a private snapshot mounted read-only in an offline Bubblewrap environment. Startup requires a distinct network namespace containing only loopback, a failed write-open against the read-only input mount and an isolated clean/positive scanner control. The worker can see trusted system runtime files, the EPUBCheck release and a pinned read-only signature generation. It has private scratch space and no host home, incoming directory or resolver configuration. Configure runtime mounts and the validator directory as trusted software locations, free from sensitive content and network-capable host sockets. The supervisor is the only component responsible for disposition.

The UTC freshness rule accepts a daily publisher build age from zero through 259,200 seconds. It uses the publisher build epoch, checks authenticated inner metadata for a CVD, and relies on the trusted FreshClam update chain and write controls for a CLD. Verify and load main and bytecode definitions as companion files, whose build dates can be older. A stale or missing generation triggers one FreshClam call, then the same freshness check. Startup requires scanner load and harmless control results plus a working EPUBCheck invocation. Keep the system clock reliable and the updater cache trusted.

The scanner receives the raw EPUB plus every physical regular member. The static ZIP pass reconciles local and central headers, flags, sizes, ZIP bounds, descriptors and actual CRCs and expansion before exposing private numeric members to scanners. It accepts single-volume stored or deflated ZIP with a limited set of extra fields. ZIP64, unknown compression, ambiguous records, encryption, and unsupported paths produce explicit findings. Static inspection includes XML markup, metadata, stylesheets and supported passive formats. EPUBCheck checks conformance independently of the custom inventory. A broken but security-inspectable manifest can qualify for repair. Unsupported data URLs, embedded contexts, dynamic CSS URLs, unrecognized resource formats, unreadable markup, and uninspectable encryption or obfuscation are handled conservatively as incomplete. The policy uses format markers for passive images, fonts and media and does not render or exercise their decoders. Reader-specific behavior and future or undocumented formats can exceed static coverage.

| Optional TOML limit | Default | Maximum |
| --- | ---: | ---: |
| `max_book_bytes` | 128 MiB | 192 MiB |
| `max_member_bytes` | 48 MiB | 128 MiB |
| `max_expanded_bytes` | 256 MiB | 512 MiB |
| `max_entries` | 4096 | 8192 |

The worker has 1 GiB of private scratch. The default readiness deadline is 180 seconds and the default per-book inspection deadline is 300 seconds. Optional TOML integers `readiness_timeout` and `inspection_timeout` set seconds, with ranges of 1–1800 and 1–3600 respectively. Choose deadlines that account for signature engine startup on the host. Configure the host with sufficient RAM for ClamAV, scratch and Java together. A known book size, member count or expansion limit causes book-specific incomplete coverage. An unexplained process death, timeout, scanner diagnostic, invalid response or shared resource failure causes an operational error and preserves the affected source.

## Tests

```sh
/usr/bin/python3 -m unittest discover -s tests -v
```

The focused suite uses harmless EPUB fixtures and in-process scanner and worker doubles. It covers freshness boundaries, physical ZIP and content policy, CLI selection and output, preview, no-overwrite publication, queue failure and interrupted recovery. Run the separate acceptance harness on a provisioned machine to establish platform isolation and collect real ClamAV and EPUBCheck evidence.

## Agent-assisted review (v3)

Use agent review to assess findings from a staged book. Scanning, automatic repair, listing findings, and making decisions run without a model. An explicit review sends the selected book's text and finding to the named model provider as requested during the review. The selected version is the latest accepted edition, or the verified intake copy when no repair has been accepted.

### Configure the native reviewers

Add the reviewer executable paths to the existing config file. Set `repaired_output` as for automatic repair. Use standalone Linux binaries that support noninteractive, isolated execution and the required tool-disable flags.

```toml
codex_executable = "/path/to/codex"
claude_executable = "/path/to/claude"
# Optional model names.
codex_model = "gpt-5.4"
claude_model = "claude-sonnet-4-6"
review_batch_limit = 10
review_turn_limit = 8
review_timeout = 120
```

Set `OPENAI_API_KEY` for Codex CLI and `ANTHROPIC_API_KEY` for Claude Code. Reviewers start in new temporary homes with no account sessions, project instructions, plugins, hooks, MCP servers, or persistent CLI conversation. A local, authenticated relay handles provider credentials and forwards text-only requests. Use `OPENAI_BASE_URL` or `ANTHROPIC_BASE_URL` only to select a trusted HTTPS provider endpoint or a local loopback fixture. OpenAI endpoints include their API prefix, such as `https://api.openai.com/v1`. Anthropic endpoints use the origin, such as `https://api.anthropic.com`.

The reviewer can page through the selected EPUB's text inventory, read source slices, search exact text, and run the offline `count_variants` diagnostic. Counts are case-sensitive literal matches against extracted text resources. The worker supplies these results over a data-only protocol. The native CLI sees an empty working directory and receives no book file, queue, or library mount. The relay removes native tool declarations and rejects provider tool calls.

### Select and assess findings

```sh
./epub-triage review-list title.epub --config config.toml
./epub-triage review title.epub --finding FINDING_ID --reviewer codex --interactive --config config.toml
./epub-triage review title.epub --reviewer claude --config config.toml
./epub-triage review --batch --limit 4 --reviewer claude --config config.toml
./epub-triage review-second REVIEW_ID --interactive --config config.toml
```

A review ID identifies the selected occurrence and book version. For a later `review --finding FINDING_ID` without a book argument, discover the ID through `review-list` first. A book review assesses its outstanding findings. A batch counts newly assessed findings toward its limit and records each completion before starting another. If a reviewer is unavailable or reaches a usage limit, the batch reports a pause and exits with status 2. Rerun it with the same reviewer to resume. A bounded batch leaves excess work pending.

The other CLI can give a second opinion while the review is open. It receives a fresh context with the same verified book version and finding. The command displays both assessments and retains their separate evidence and proposal IDs. Interactive input accepts `approve PROPOSAL_ID`, `reject`, `defer`, `intentional`, or `investigate`. To leave a review open for a later decision, press Enter. An intentional decision applies to the same finding and passage occurrence, including when an unrelated change creates a new edition. OCR warnings identify individual damaged words. Changing the number of words in a sentence or the sentence structure of a text slot can reopen nearby decisions when the old positions become ambiguous.

### Export, approve, and publish

```sh
./epub-triage review-export REVIEW_ID proposal.json --config config.toml
./epub-triage review-decide REVIEW_ID approve --proposal PROPOSAL_ID --export proposal.json --config config.toml
./epub-triage review-audit REVIEW_ID --config config.toml
```

The exact displayed proposal ID binds the reviewer, book SHA-256, finding, and single text replacement. When reviewing an export, retain its original bytes. If only one copy was exported, approval by ID checks that registered file automatically. With several exports, pass `--export` to select the copy. The decision validates the export and current book again before building a candidate. To decline both suggestions or leave a finding for investigation, use `review-decide REVIEW_ID reject`, `defer`, or `investigate`.

A candidate publishes through the same version journal and file-preservation checks as v2. If the targeted heuristic warning persists and everything else passes, the verification record shows the staged candidate path, the actual change, the remaining warning, and the verified candidate SHA-256. Choose separately whether to publish those bytes.

```sh
./epub-triage review-publish PROPOSAL_ID publish --candidate-sha256 CANDIDATE_SHA256 --config config.toml
./epub-triage review-publish PROPOSAL_ID decline --candidate-sha256 CANDIDATE_SHA256 --config config.toml
```

The review audit links the original and current versions, assessment evidence, user choices, verification reports, and any published output hash. Staged candidates remain in the queue's sibling review-candidates directory for inspection and are excluded from intake. A finding regression, incomplete security or quality coverage, a signed-content conflict, or a changed edition blocks publication. Any exact repair proposal applies to a UTF-8 source member.
