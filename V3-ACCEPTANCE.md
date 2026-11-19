# Agent-assisted EPUB review

The acceptance contract is the supplied v3 brief. The operator requested Linux verification with Luna emulating the two reviewers and deferred WSL.

## Review design

The CLI selects a hash-verified version and mediates read, search and diagnostic requests for that book. The offline EPUB worker reads the archive and builds candidates. A separate process invokes each provider CLI in a fresh context. Its relay accepts text responses and withholds native model tools. The human chooses an exact proposal before any candidate is built. A persistent warning requires a second decision tied to the verified candidate.

## Environments

- Native Debian 13, x86-64, Linux 6.18.57. The host restricts unprivileged namespace setup. Native workflow tests use controlled infrastructure and exercise the real EPUB rules, SQLite, version publication and CLI command handling.
- A Debian Linux guest with two ext4 volumes, Linux 6.12.107, unprivileged UID 1000 and functioning Bubblewrap. The guest has loopback and no external network interface.
- Codex CLI 0.167.0-alpha.4 and the native Claude Code CLI 2.1.327. The provider endpoints use a local HTTP responder authored by Luna. No live account credentials or external book transfers were used. In direct native invocations each binary completed a streamed provider call. The clients returned different exact replacements at character offset 42 in the same synthetic passage. [Binary invocation transcripts](acceptance/evidence/v3/native-clients.txt)

## Acceptance evidence

| Contract check | Environment and result | Supporting observation |
| --- | --- | --- |
| Invocation scope | Pass · Debian host and guest native clients | Explicit book, finding ID, and bounded batch paths ran. Scan, repair and list produced zero model calls. A two-item batch left excess findings available. |
| Input selection and access | Pass · Debian host workflow | The reviewer read the accepted edition’s changed navigation text. With intake alone it read the pinned intake. Full-book search and variant counts returned results. A different book, a filesystem path, writing, shell execution and approval requests produced no capability or side effect. Quarantine, incomplete coverage and a changed intake prevented review. |
| Independent second opinion | Pass · guest native clients and Debian host workflow | Codex and Claude each acted as primary and secondary. The second request had the identical book hash, an empty history, and no first rationale or proposal ID. The reviewers returned different diffs. Tests chose each proposal, rejected both and deferred both. |
| Approval integrity | Pass · Debian host workflow | A real pseudo-terminal displayed the passage and proposal before receiving its exact ID. Later approval by exported ID changed only the selected text. An altered export, stale book with identical target passage, and deferred proposal all failed approval. |
| Publication | Pass · Debian host workflow and isolated Linux guest | Warning-cleared approvals publish. For a persistent warning the output remained absent until a separate candidate-hash decision. Accept, decline, wrong hash and tampered staging were exercised. A new finding, return of a resolved v2 defect, incomplete inspection, quarantine trigger, and signature conflict each blocked publication. |
| Intentional occurrences | Pass · Debian host workflow | Marking one occurrence preserved the other for review. A new edition containing an unrelated text change retained the decision. Changing the relevant passage or diagnostic reopened it. |
| Interruption and audit | Pass · guest native CLI and Debian host workflow | A subprocess interruption after the first review and a provider HTTP 429 each preserved completed work. Resuming with the other reviewer failed. Same-reviewer resume respected the limit. Interrupted publication also recovered without a duplicate output, while replacement of a pending parent prevented publication. |
| Affected earlier behavior | Pass · Debian host | All 18 independent v2 checks and seven v1 regressions passed, including queue/hash selection, signed and ambiguous books, candidate drift, regression rejection, preview, collisions, retries, process death and immutable output versions. [Regression log](acceptance/evidence/v3/regressions.txt) |

Review failures found and corrected during qualification included CLI session initialization, stale source selection, edited exports approved by ID, recovery of a stale pending publication, duplicate-looking batch output after HTTP 429, and grouping two damaged words into one finding. The independent [workflow tests](acceptance/test_v3_review.py) use real EPUBs, production byte-level editing, queue storage, approvals and publication. Their controlled worker makes individual scanner failure paths repeatable. The [native client matrix](acceptance/v3_clients.py) uses actual reviewer binaries, the production relay and Luna’s streamed API responses. It records provider order, data requests, exact diffs and output hashes, and exercises an HTTP rate limit. [Fixture setup](acceptance/V3-MODEL-FIXTURES.md)

A marked OCR word keeps its own occurrence ID when a different damaged word in the same sentence is fixed. The persistent-warning fixture removes three of six replacement glyphs from one word, then checks that publishing requires a separate decision. Creating a second damaged word blocks publication. When structural changes make an occurrence ambiguous, the implementation reopens it for review. Changes to the word count of its sentence or the sentence count of its XML text node can trigger that conservative reopening.

Final host runs passed 22 independent v3 checks, 25 v1/v2 regressions and 27 implementation tests. [V3 results](acceptance/evidence/v3/review-tests.txt) · [Implementation suite](acceptance/evidence/v3/unit-tests.txt) · [Tested source hashes](acceptance/evidence/v3/source-sha256.txt)

The restricted host also ran both real native clients in both orders, followed by a real HTTP 429, refusal of a reviewer switch, and bounded resume. Only the Bubblewrap process launcher was substituted in that host run. The guest exercises the production launcher. [Host workflow transcript](acceptance/evidence/v3/native-workflow.jsonl)

## Isolated Linux runs

The guest first staged a warning-bearing EPUB using v2. During implementation, the production Codex CLI then assessed it through the relay. Approval ran the genuine offline verifier and published the exact `World` edit. SHA-256 changed from `1479cb287099cada10f66f9324d9f61f3dc461a9f6c82ecd237f9cb6b9f75410` to `09a226181676147d9fbaa091bcae186fa15c8188be388c0a754fc6cf57d92155`. Original and intake matched byte for byte, and every other member matched the source. This Codex run used an earlier v3 snapshot.

The final build then ran both native clients in both reviewer orders under Bubblewrap. Each pair made four provider calls, advertised zero native tools, and used both a full-book search and a spelling-count diagnostic. The Codex HTTP 429 run resumed on the same reviewer, reported one newly completed ID and left one finding pending. The guest transcript retains the initial missing `librt.so.1` loader failure. Provisioning the guest runtime fixed it before either integrated matrix. [Guest transcript](acceptance/evidence/v3/guest-linux.txt)

A second end-to-end run used the final build and a disposable copy of the genuine v2 queue reset to its pre-review state. Claude proposed `Wor���d` → `Word` at character 171 of `text.xhtml`. Approval rebuilt and verified the exact candidate using Bubblewrap, ClamAV 1.4.6 with signed daily definitions (epoch 1794983319), and EPUBCheck 5.4.0. Security and quality were complete with zero remaining findings. Source and intake still matched. The output SHA-256 was `2908eb4473f3c1b0bc318851aca5f59709c002a3e8dc61e6b36d7fac3645ad53`. The recorded primary assessment, user decision and publication all identified the same proposal. A separate probe inside the production reviewer mount configuration confirmed a read-only root, an empty work directory, and no library, SQLite queue, upstream key or system shell at the tested paths. [Guest verification and audit](acceptance/evidence/v3/guest-linux.txt)

**Readiness.** All seven v3 acceptance areas passed in the tested Debian configuration. WSL filesystem behavior and live provider accounts remain for operator qualification.

## Operator checks

On WSL 2, run the native-client matrix with the intended Linux CLI binaries, then review and approve a benign title using the real configured ClamAV database and EPUBCheck installation. Verify Bubblewrap namespace creation, terminal approval, queue locking, and no-replace publication on the filesystem used for the library and outputs. For a Windows-mounted destination, check its file-preservation and hard-link behavior separately. See the [operator commands](README.md#agent-assisted-review-v3).

Live provider authentication, account entitlements, service-side model behavior, and real quota windows were outside this credential-free run. The integration uses operator-supplied API keys. Current exact edits require a round-trippable UTF-8 text member.

### Reproduce the Linux checks

Use the repository's v1/v2 Python dependencies for these commands. The native-client matrix starts its own loopback service and supplies dummy credentials. It requires working unprivileged Bubblewrap namespaces and executable paths to the native binaries.

```sh
python3 -m unittest discover -s tests -v
python3 -m unittest -v acceptance.test_v3_review acceptance.test_v2_review acceptance.test_review
python3 -m acceptance.v3_clients --codex /path/to/codex --claude /path/to/claude
```
