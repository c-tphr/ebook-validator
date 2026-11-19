# Colab notebook acceptance

**Hosted release is blocked.** The cloud browser could not navigate to Colab. Its tab remained blank. Two HTTP checks, including a retry with network permission, received a proxy refusal at CONNECT. Google did not allocate a runtime. No Google account, Drive folder or model-provider account was used in the tests below. A local kernel run verifies the distributed notebook can open and report missing prerequisites. Isolated Debian guests supply separate process-level evidence.

## Contract checks

| Scenario | Environment and evidence | Hosted status |
| --- | --- | --- |
| Fresh runtime and setup | A new local Jupyter kernel opened the embedded notebook and exercised the Set up button. The Debian host is outside the pinned Ubuntu 24.04 / system Python 3.12 target. The EPUBCheck bundle downloaded successfully. All 13 binary distributions in the WeasyPrint CPython 3.12 lock were independently downloaded with hash verification. | Pending fresh Colab setup and Drive-to-Drive output. |
| Reader and monitor isolation | Debian host kernel 6.18.57 denies user namespace creation. A disposable Debian 13 guest runs Linux 6.12.107 with a separate root controller and worker UID 62037. Qualification uses real Qt and WeasyPrint, separate network namespaces, process tracing, a positive loopback control and disposable markers. See guest results below. | Pending proof in a hosted allocation with authorized Drive and Colab Secrets. |
| Selection and permissions | The independent HTTP service model exercises folder recursion, per-ID selection, shared-drive listing parameters, denied download, inside/outside shortcuts, generated output exclusion, bounded media reads and changed revisions. | Pending My Drive, real shared-folder permissions and inaccessible ancestor cases. |
| Batches, decisions and retention | Deterministic worker replies exercise sequential real temporary staging, cleanup after a monitor outage, report-only behavior and independent books. V1–v4 regressions exercise clean, quarantine, held, repair, publication and earlier editions. | Pending hosted disk limits, Drive artifacts and retention. |
| Disconnect and conflicts | In the Drive model, a lost response after a quarantine move is recognized, and a failure before the move can be resumed. Two resumes produce one move. Conflicting source or destination preserves existing bytes. Binary uploads to an unpublished, book-bound candidate slot were interrupted before and after the API mutation. Rebuild and repeated Resume preserved the candidate hash and occupied slots. A delayed binary upload lost its ETag after takeover. A separate readback test supplied absent, matching and conflicting final-output states directly. | Pending actual interrupted Drive mutations and upload finalization. |
| Two sessions | Two contenders race to acquire one canonical journal. The model enforces ETags and permits one winner. An explicitly superseded writer's delayed journal update and physical move are rejected. A service accepting a stale conditional write fails qualification. The evidence store also survived an interrupted upload, and expiry of one book preserved another book’s identical trace and the durable decisions. | Pending server-side stale-write rejection on Google Drive. |
| Reviewer workflow | Controlled reviewer replies exercise all three reviewer identities, pair changes, independent second opinions, matching exported and inline proposal IDs, exact-candidate confirmation and source-change invalidation. CLI-specific evidence follows below. | Pending live provider authentication, model responses and account-specific controls. |
| Regression | Independent earlier acceptance comprises 7 v1, 18 v2, 22 v3 and 15 v4 cases on Debian. They cover exact repaired bytes and separate persistent-warning approval. | Earlier Linux results cannot qualify hosted operation. |

## Independent evidence

[Drive and workflow tests](acceptance/test_v5_independent.py) · [Fresh local notebook check](acceptance/v5_notebook_smoke.py) · [Prior-version regression output](acceptance/evidence/v5/regressions.txt)

## Design decisions and open gates

The v4 CLI and its two distinct renderers were present in the checkout. The notebook embeds the validator, uses the Drive REST API by object ID and performs inspection in disposable runtime storage. Its isolation probes and conditional mutation probes are runtime prerequisites. The default is report-only. A provider authentication failure applies to that reviewer.

Drive supports distinct object IDs with the same displayed name. Conditional updates to a canonical journal can establish writer ownership if the actual service rejects stale requests. A writer check on that journal alone cannot fence a queued update to another object. The quarantine path records a physical intent and uses a separately qualified conditional update on the file to protect against that race. Finalizing an edition upload requires guarantees covering the source and a different destination. The shipped lane's restriction and pending disposition are significant release limitations.

## Linux isolation and local reviewer evidence

The unprivileged Linux host refused creation of a user namespace. In the guest, the notebook launcher dropped from root to UID 62037 and placed the monitor in a separate network and filesystem namespace. The scanner and both readers recorded denials for the synthetic Drive mount, credential cache, unrelated book and notebook channel. Both engines completed seven matching navigation actions. Qt QTextDocument 5.15.15 recorded six blocked callbacks across the two resource controls. WeasyPrint 70.0 recorded two. Each callback identified a book member, step and denied action. The controller listener passed its positive control and received zero worker connections. The kernel socket and dispatch controls also passed.

Independent testing found that a read-only proc mount prevented nested UID mapping and that additional proc mounts prevented the inner PID namespace from mounting proc. The correction uses a private outer PID namespace and keeps the reader's inner proc read-only. Qualification now requires completed navigation on a clean book and attributable denials on separate resource controls. Under CPU emulation WeasyPrint exceeded the default 60-second allowance, which left the gate pending. The passing run used the configurable 600-second allowance.

Real Linux Codex and Claude Code executables completed structured assessments through the notebook's isolated CLI and relay. Provider replies and secrets were local fixtures. An initial Codex run failed because its private home was missing. I verified the correction with the same executable and transport. No authenticated model-provider call was made.

[Linux reader and monitor receipts](acceptance/evidence/v5/linux-qualification.json) · [Native CLI receipts and versions](acceptance/evidence/v5/linux-reviewers.json) · [Colab access attempt](acceptance/evidence/v5/hosted-access.txt) · [Wheel lock check](acceptance/evidence/v5/wheel-lock.txt)

A second Debian guest repeated the reader and monitor qualification from the embedded distribution. Both readers passed again. A locally compiled Antigravity protocol fixture returned the secret-free routing marker through the restricted relay. The dispatcher then kept a real review request pending before requesting a secret. The genuine Google executable, its native-tool restrictions and Google authentication remain unverified. Interactive account sign-in is pending for all three reviewers.

The Linux suites passed all 125 checks across 42 implementation tests, 21 independent v5 checks and 62 affected v1–v4 regressions. These counts include simulated Drive operations and reviewer responses. The local kernel and guest runs are additional checks. The notebook contains no saved cell output, and all 25 embedded modules matched their source bytes.

[Implementation test output](acceptance/evidence/v5/unit.txt) · [Independent v5 test output](acceptance/evidence/v5/independent.txt) · [Local kernel setup output](acceptance/evidence/v5/local-notebook.json) · [Embedded module hashes](acceptance/evidence/v5/bundle-digests.json) · [Repeated guest qualification](acceptance/evidence/v5/linux-distribution-probes.json) · [Simulated Antigravity receipt](acceptance/evidence/v5/linux-agy-probe.txt)

## Remaining release blockers

1. A fresh hosted Colab allocation must qualify the pinned installation, scanners, both readers and monitors, and workspace cleanup with real Drive access and disposable markers. A denied prerequisite keeps the affected batch pending.
2. Google Drive must demonstrate the required conditional updates across actual owned and shared folders, interrupted operations, concurrent acquisition and explicit takeover. The implementation limits conditional quarantine to a qualified direct-child move. Other quarantine routes remain pending.
3. Repaired-edition publication and repair-intake copies require an implementation that can bind a guarded destination commit to the current source and writer. Uploading verified bytes to an unpublished slot (maximum 5 MiB) proves staging only. The notebook cannot complete the brief’s accepted Drive output today.
4. Hosted credentials and effective controls must be verified for each claimed reviewer route. Codex and Claude have local native-client evidence with simulated providers. Antigravity needs a genuine pinned CLI and verified native-tool denial before a model call can be enabled.

A further guest trial staged a benign repairable EPUB through a simulated Drive media client and invoked the actual scanner, reader gate and repair workflow. The static inspection of the source exceeded its 300-second deadline under software emulation. A repeat reproduced the timeout. No candidate reached the trusted byte-verification callback. Prior Linux repaired-byte regressions passed, but the v5 guest trial leaves the full candidate handoff pending. [Guest repair trial](acceptance/evidence/v5/linux-candidate.json)

Sol corrected the timeout diagnostic after the guest trial. An independent Linux check forced an actual subprocess to exceed its deadline and verified the static worker and controller reported the inspection phase and kept the operation pending. The complete guest repair run was not repeated after this diagnostic-only correction.
