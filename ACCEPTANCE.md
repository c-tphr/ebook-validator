# EPUB triage acceptance record

Reviewed on 18 November 2026 against `BUILD-BRIEF.md`. Sol 6.2 implemented the CLI. The supervising reviewer inspected the selection, sandbox, worker protocol, scanner adapter, content policy, queue and file transactions, wrote an independent harness, and ran the checks below.

**Readiness.** Ready for a controlled Linux rollout on qualified local storage with cooperative intake ownership. All 14 implementation tests and seven independent acceptance tests passed on the host. Both live guest dispositions passed on separate ext4 volumes. WSL 2 qualification is open. Live incremental CLD refresh and physical power-loss durability were not tested.

## Decisions that affect operators

- Freshness means the daily release’s publisher build epoch, with 72 hours inclusive. The main and bytecode companion releases can be older. CVD verification checks the signed payload and the daily inner metadata. Incremental CLD support assumes a trusted FreshClam-managed directory.
- Use one fail-closed Bubblewrap backend. The supervisor snapshots and controls files, and FreshClam runs outside the offline worker. EPUBCheck checks conformance. The static inspector covers physical ZIP members even if the package manifest is broken. The scanner receives both archive bytes and recovered members.
- The brief gives security disposition precedence. A confirmed trigger therefore skips external conformance checking, records why quality coverage is incomplete, and retains any static quality evidence already found. EPUBCheck warnings go to review. Unsupported encryption, including font obfuscation, produces an incomplete-security finding.
- Windows support targets WSL 2 with distribution-local storage. The memo proposed separately qualifying Windows-mounted storage and an OCI fallback. Neither is required by the brief. This implementation rejects Windows-mounted storage and requires Bubblewrap. An operator who requires direct processing under `/mnt/c` needs additional implementation and qualification.
- Durable publication requires cooperative control of intake, supported directory synchronization and hard links at the destination. A process ignoring advisory locks can replace or modify files during disposition. The CLI documents the contract and verifies source and destination bytes.

## Environments

| ID | Environment |
| --- | --- |
| H | Managed Debian 13.6 x86-64, Linux 6.18.57, unprivileged UID 1000, Python 3.13.5. Workspace and test intake on overlayfs. The independent cross-filesystem fault tests used tmpfs as a second device with the worker replaced. Production preflight rejects tmpfs disposition paths. The outer sandbox exposes a read-only UID map. |
| G | Disposable Debian userspace and Debian Linux 6.12.107+deb13-amd64, QEMU 10.0.13 software emulation, UID 1000. Unprivileged user/network namespaces enabled. Bubblewrap 0.12.0. Real CLI tests use separate ext4 virtual disks for intake/queue and destination. The guest has no external network device. Its supervisor can reach its own live loopback listener. |
| W | WSL 2 unavailable. The operator asked to report this gap. No result from H or G counts as a Windows run. |

Real tool versions were ClamAV/FreshClam 1.4.6, EPUBCheck 5.4.0 and OpenJDK 21.0.13. The official daily CVD was version 28187, publisher epoch 1794983319 (18 November 2026 at 06:28:39 UTC). Main was 63 and bytecode was 339. See [tool and signature evidence](acceptance/evidence/tools.txt).

## Results by brief check

| Check | Environment and result | Supporting observation |
| --- | --- | --- |
| 1. Successful isolation | G, passed live | The launcher started an independent network namespace with only loopback. The worker read a sentinel, write-open failed with EROFS, the supervisor-only file was hidden, and a TCP listener reachable from the supervisor could not be reached from the worker. The production probe also checks that resolver configuration is absent. [Canary](acceptance/isolation.py) |
| 1. Isolation unavailable | H, passed live | Direct Bubblewrap and the unmodified CLI reported a read-only UID map. CLI exit 2, zero stdout lines, same source SHA-256 before/after and no output directories or queue. [Evidence](acceptance/evidence/refusal.txt) |
| 2. Freshness and update | H, passed component and controlled checks | Real FreshClam downloaded and tested all three official CVDs from an empty cache using its HTTP fallback after the DNS TXT lookup failed. The actual daily CVD passed the inner-epoch check. With the real preflight decision logic and controlled epochs/updater, fresh caused zero updates, stale→fresh caused exactly one, and stale→stale and update failure exited 2 with protected state unchanged. Boundary tests covered exactly 72 hours, one second over and a future epoch. Live incremental CLD refresh was not exercised. |
| 2. Failure scope | H, passed live and injected checks | Real ClamAV returned OK, Eicar-Test-Signature FOUND, and Empty file for the three controls. Simulated scanner unavailability stopped preflight. A 32-byte physical-member cap quarantined only the selected book with a member_limit finding. A lost worker returned exit 2, preserved both selected sources, and produced zero quarantines. |
| 3. Decisions and precedence | H, passed | The independent 12-book batch covered a scanner match, script, plain web link, automatically loaded remote image, unlisted remote resource, unsafe path, corruption, broken navigation, missing manifest member, heuristic-only prose, combined script/navigation and clean. It asserted each disposition and trigger class. Only navigation, manifest and heuristic books entered the queue. Source and copy hashes matched for all three, and only the heuristic row had needs_review. Real EPUBCheck separately reported RSC-012 for the missing fragment and RSC-001 for the missing manifest resource. [Decision harness](acceptance/test_review.py) |
| 4. Integrity, collisions and concurrency | H, passed with real filesystem operations | Two concurrent processes handled equal nested basenames, one occupied destination and one repair source. The existing bytes survived, both quarantined copies were recoverable, and there was exactly one repair row. Reintroducing identical quarantined bytes at the original path removed that path again after verifying the copy. |
| 4. Interrupted operations and queue failure | H, passed with fault injection | An injected failure after a 21-byte partial copy left the source and no final target. Queue commit failure retained the complete published copy and source, with no dangling row. A child process exited abruptly after quarantine unlink and before journal commit. Preview preserved pending state, one normal retry recovered it, and a second retry found no remaining operation. The repair retry produced one resolvable row per book. These are process-interruption tests. Power-loss and storage-controller recovery remain unqualified. |
| 5. CLI selection, output and exit codes | H, passed with controlled backend and real supervisor | Parsed each stdout line as JSON. The summary was on stderr. Clean, findings and operational exits were 0, 1 and 2. Checked configured, missing and overridden roots, recursive and top-level selection, two explicit names in a larger folder, symlink files and directories, and quarantine/repair exclusions. An explicit symlink mixed with a regular book skipped the link and inspected the book. |
| 5. Preview | H, passed | Both root-selection methods predicted the same action and destination as the following normal run on the same inputs. Protected paths and contents were identical across previews. A focused test checked atime, mtime and ctime. Previewing a pending operation produced a prediction without replay. |
| 2–5. Production CLI, real databases and cross-volume disposition | G, passed two live runs | Used the final executable and modules, genuine ClamAV and EPUBCheck, and independent ext4 source and destination volumes. Both runs passed isolated clean/positive controls with publisher epoch 1794983319. Used 600 seconds for readiness and 900 for inspection on this software emulator. |
| 3–5. Live quarantine | G, passed | The real signature match identified control.txt. The CLI returned one JSON record, findings exit 1 and zero operational errors. The original disappeared, the destination matched the input SHA-256, and the repair queue was empty. [Transcript](acceptance/evidence/live-quarantine.txt) |
| 3–5. Live repair | G, passed | Security completed with no findings. Static navigation checking and EPUBCheck RSC-012 verified the broken fragment. The CLI retained the source, published an identical repair copy on the other ext4 disk, committed exactly one matching queue row and exited 1. [Transcript](acceptance/evidence/live-repair.txt) |
| 1–5. WSL 2 | W, untested | Repeat the canary, suites, live CLI, storage checks and operator procedure below on the intended WSL installation before approving it. WSL 1 and direct Windows-mounted storage are outside the supported configuration. |

A second decision run on H exercised the final worker with genuine ClamAV and EPUBCheck on 12 reviewer-generated benign fixtures. Only executable, database and scratch paths were redirected into a temporary installation. This component run did not exercise isolation or file disposition. All 12 actions matched the expected decision, and only the standalone EICAR member produced a malware signature. [Hashes and worker findings](acceptance/evidence/worker-matrix.jsonl)

The same seven independent checks also passed on the guest across two ext4 disks, including concurrent publication, interruption and recovery. The intermediate guest build also passed its 12 focused tests. [Guest transcript](acceptance/evidence/guest-cross-volume.txt)

The final host command transcripts are in [focused tests](acceptance/evidence/implementation-tests.txt) and [independent tests](acceptance/evidence/review-tests.txt). The tests use real filesystem and SQLite operations. Tests replacing scanner output or worker startup establish disposition behavior and failure attribution only.

## Review findings resolved

Sol corrected repeated quarantine of newly downloaded identical bytes, temporary-file ownership on recovery, and handling of explicit symlinks mixed with valid files. Linux reruns covered these paths. Additional regressions cover a changed CVD header, malformed worker evidence, malformed CSS, clickable NCX targets, and a verified security trigger surviving an unavailable downstream validator. A full-database startup exceeded the default 180-second readiness deadline under software emulation and exited 2. The final CLI keeps that default, supports separately bounded readiness and inspection deadlines, and loads the engine once for a valid archive and all of its members. The production launcher includes the Debian Java alternatives path. A minimal-runtime run exposed a ClamAV locale warning. The worker now requests the POSIX C locale with explicit UTF-8 for Python and Java.

## Operator checks

From the repository root, install the runtime described in [README.md](README.md). Use an unprivileged account and an existing, writable Linux directory for disposable books. The live harness reads only the database, EPUBCheck and optional FreshClam configuration paths and timeout settings from the supplied TOML. It creates its own intake, output and queue and prints the real CLI results before cleaning up.

```sh
/usr/bin/python3 -m acceptance.isolation
/usr/bin/python3 -m unittest discover -s tests -v
TMPDIR="$HOME" /usr/bin/python3 -m unittest -v acceptance.test_review
/usr/bin/python3 -m acceptance.live --config ~/.config/epub-triage/config.toml --work-parent "$HOME"
```

On WSL, record the Windows build, `wsl.exe --version`, distribution kernel and `findmnt -T` for each configured path. Verify the source mount and worker cannot access Windows interop or Windows services, and that a configuration pointing into `/mnt/c` fails before moving any files. To exercise a second supported Linux filesystem, supply its existing writable directory to `--output-parent` and set `EPUB_ACCEPTANCE_SECOND_FS` for the independent suite. Test interruption and restart on the storage the operator will actually use. The live harness includes the harmless EICAR control and requires working current vendor signatures.
