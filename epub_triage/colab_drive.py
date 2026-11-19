"""Drive v3 intake and conditional updates to a single, pre-provisioned journal."""

from dataclasses import dataclass
import hashlib
import json
import re

API = "https://www.googleapis.com/drive/v3"
UPLOAD = "https://www.googleapis.com/upload/drive/v3"
FOLDER = "application/vnd.google-apps.folder"
SHORTCUT = "application/vnd.google-apps.shortcut"
FIELDS = ("id,name,mimeType,parents,driveId,trashed,version,headRevisionId,size,"
          "sha256Checksum,properties,shortcutDetails(targetId,targetMimeType),"
          "capabilities(canDownload,canEdit,canAddChildren,canMoveItemWithinDrive,"
          "canMoveItemOutOfDrive,canRemoveChildren)")
ID = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
JOURNAL_LIMIT = 8 * 1024 * 1024


class DriveError(RuntimeError):
    pass


class Conflict(DriveError):
    pass


def key(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise DriveError("Enter a Drive item ID.")
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def stamp(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def identity(meta):
    if meta.get("trashed") or not meta.get("version") or not meta.get("headRevisionId"):
        raise DriveError("Drive binary identity or revision is unavailable.")
    try:
        size = int(meta["size"])
    except (KeyError, TypeError, ValueError):
        raise DriveError("Drive binary size is unavailable.") from None
    checksum = meta.get("sha256Checksum")
    if size < 0 or not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
        raise DriveError("Drive SHA-256 or size is unavailable.")
    return {**{field: meta.get(field) for field in ("id", "name", "mimeType", "driveId",
                                                    "version", "headRevisionId")},
            "parents": sorted(meta.get("parents", [])), "size": size, "sha256": checksum}


class Drive:
    def __init__(self, session):
        self.session = session

    def request(self, method, url, **kwargs):
        try:
            response = self.session.request(method, url, timeout=30, allow_redirects=False, **kwargs)
        except Exception:
            # Never include OAuth exceptions, response bodies or request URLs in notebook outputs.
            raise DriveError("Drive request interrupted. Recheck status before retrying.") from None
        if response.status_code == 412:
            response.close()
            raise Conflict("Drive rejected a stale conditional request.")
        if response.status_code not in (200, 201, 206):
            code = response.status_code
            response.close()
            raise DriveError(f"Drive returned HTTP {code}. Check access or service readiness.")
        return response

    def json_get(self, path, params):
        with self.request("GET", API + path, params=params) as response:
            return response.json()

    def meta(self, item):
        value = self.json_get("/files/" + key(item), {"fields": FIELDS, "supportsAllDrives": "true"})
        if value.get("id") != item:
            raise DriveError("Drive returned an unexpected object.")
        return value

    def tagged_meta(self, item):
        with self.request("GET", API + "/files/" + key(item), params={
            "fields": FIELDS, "supportsAllDrives": "true",
        }) as response:
            value = response.json()
            etag = response.headers.get("ETag")
        if value.get("id") != item or not strong_etag(etag):
            raise DriveError("Drive metadata route does not provide a strong object ETag.")
        return value, etag

    def patch_metadata(self, item, etag, data, *, add=None, remove=None):
        if not strong_etag(etag):
            raise DriveError("Conditional Drive request requires a strong metadata ETag.")
        params = {"fields": FIELDS, "supportsAllDrives": "true"}
        if add:
            params["addParents"] = key(add)
        if remove:
            params["removeParents"] = key(remove)
        with self.request("PATCH", API + "/files/" + key(item),
                          params=params, headers={"If-Match": etag}, json=data) as response:
            result = response.json()
        if result.get("id") != item:
            raise DriveError("Unexpected Drive metadata mutation result.")
        return result

    def account(self):
        about = self.json_get("/about", {"fields": "user(permissionId)"})
        return key(about["user"]["permissionId"])

    def children(self, folder):
        page = None
        tokens = set()
        while True:
            params = {"q": f"'{key(folder['id'])}' in parents and trashed = false",
                      "fields": "nextPageToken,incompleteSearch,files(" + FIELDS + ")",
                      "supportsAllDrives": "true", "includeItemsFromAllDrives": "true",
                      "pageSize": 100}
            if folder.get("driveId"):
                params.update(corpora="drive", driveId=key(folder["driveId"]))
            if page:
                params["pageToken"] = page
            result = self.json_get("/files", params)
            if result.get("incompleteSearch"):
                raise DriveError("Drive reported incomplete discovery.")
            yield from result.get("files", ())
            page = result.get("nextPageToken")
            if not page:
                break
            if page in tokens or len(tokens) >= 1000:
                raise DriveError("Drive listing exceeded the page limit.")
            tokens.add(page)

    def read(self, item, allowance, sink, expected=None):
        """Transfer at most allowance bytes. A verified download checks both metadata reads."""
        if expected is not None and (expected["id"] != item or expected["size"] > allowance):
            raise DriveError("Object exceeds the staging allowance or is outside the request.")
        count = 0
        digest = hashlib.sha256()
        with self.request("GET", API + "/files/" + key(item), stream=True, headers={
            "Accept-Encoding": "identity"}, params={"alt": "media", "supportsAllDrives": "true"}) as response:
            etag = response.headers.get("ETag")
            for chunk in response.iter_content(64 * 1024):
                count += len(chunk)
                if count > allowance or expected is not None and count > expected["size"]:
                    raise DriveError("Drive transfer exceeded the byte allowance.")
                digest.update(chunk)
                sink.write(chunk)
        fingerprint = digest.hexdigest()
        if expected is not None and (count != expected["size"] or fingerprint != expected["sha256"]
                                     or identity(self.meta(item)) != expected):
            raise Conflict("The Drive source changed during transfer. A fresh scan is required.")
        return etag

    def patch_journal(self, item, data, etag):
        return self.patch_media(item, data, etag, "application/json")

    def patch_media(self, item, data, etag, content_type):
        if not strong_etag(etag):
            raise DriveError("Drive journal has no strong media ETag.")
        with self.request("PATCH", UPLOAD + "/files/" + key(item), data=data,
                          headers={"If-Match": etag, "Content-Type": content_type},
                          params={"uploadType": "media", "supportsAllDrives": "true", "fields": "id"}) as response:
            if response.json().get("id") != item:
                raise DriveError("Drive did not confirm the expected journal identity.")


def strong_etag(value):
    return isinstance(value, str) and re.fullmatch(r'"[!-~]+"', value) is not None


@dataclass(frozen=True)
class Scope:
    intake: str
    quarantine: str
    repair: str
    editions: str
    reports: str
    evidence: str

    def outputs(self):
        return {self.quarantine, self.repair, self.editions, self.reports, self.evidence}

    def validate(self, drive):
        if len(self.outputs() | {self.intake}) != 6:
            raise DriveError("Intake and all five destinations require distinct Drive IDs.")
        folders = {item: drive.meta(item) for item in sorted(self.outputs() | {self.intake})}
        for item, meta in folders.items():
            if meta.get("trashed") or meta.get("mimeType") != FOLDER:
                raise DriveError("Configure real, active Drive folders for intake and destinations.")
            # Output trees may be within intake, but may not contain intake or other outputs.
            parent_exclusions = self.outputs() - {item}
            chain = self.ancestor_ids(drive, meta)
            if parent_exclusions & chain:
                raise DriveError("Destinations cannot contain intake or other destinations.")
        return folders

    @staticmethod
    def ancestor_ids(drive, meta, stop=None):
        seen = set()
        while parents := meta.get("parents", []):
            if len(parents) != 1 or parents[0] in seen or len(seen) >= 100:
                raise DriveError("Ambiguous or excessive Drive ancestry.")
            parent = key(parents[0])
            seen.add(parent)
            if parent == stop:
                break
            meta = drive.meta(parent)
            if meta.get("trashed") or meta.get("mimeType") != FOLDER:
                raise DriveError("Inactive or inaccessible ancestor.")
        return seen

    def within(self, drive, meta):
        item = key(meta.get("id"))
        if item in self.outputs() or meta.get("trashed"):
            raise DriveError("Selection is excluded from intake.")
        if item != self.intake:
            ancestors = self.ancestor_ids(drive, meta, self.intake)
            if self.intake not in ancestors or self.outputs() & ancestors:
                raise DriveError("Selection resolves outside the allowed intake.")
        return meta

    def select(self, drive, selected=(), recursive=True):
        self.validate(drive)
        initial = tuple(selected) or (self.intake,)
        result, visited, rejected = {}, set(), {}
        stack = []
        for item in initial:
            try:
                stack.append(self.within(drive, drive.meta(item)))
            except DriveError as error:
                rejected[item] = str(error)
        while stack:
            meta = stack.pop()
            item = key(meta.get("id"))
            if item in visited:
                continue
            if len(visited) >= 10000:
                raise DriveError("Drive scope exceeds the discovery limit.")
            visited.add(item)
            try:
                self.within(drive, meta)
                kind = meta["mimeType"]
                if kind == SHORTCUT:
                    target = self.within(drive, drive.meta(meta["shortcutDetails"]["targetId"]))
                    if target["mimeType"] == SHORTCUT:
                        raise DriveError("Nested shortcuts are outside this selection workflow.")
                    if target["mimeType"] != FOLDER or recursive or item in initial:
                        stack.append(target)
                elif kind == FOLDER:
                    for child in drive.children(meta):
                        if child["id"] not in self.outputs() and (recursive or child["mimeType"] != FOLDER):
                            if len(stack) >= 10000:
                                raise DriveError("Drive folder exceeds the discovery limit.")
                            stack.append(child)
                elif meta["name"].lower().endswith(".epub"):
                    if not meta.get("capabilities", {}).get("canDownload"):
                        raise DriveError("This account cannot download the selected EPUB.")
                    result[item] = identity(meta)
                elif item in initial:
                    raise DriveError("Select a folder, shortcut, or EPUB.")
            except DriveError as error:
                rejected[item] = str(error)
        return sorted(result.values(), key=lambda item: (item["name"].casefold(), item["id"])), rejected

    def current(self, drive, expected):
        current = identity(self.within(drive, drive.meta(expected["id"])))
        if current != expected:
            raise Conflict("The intake identity or revision changed. A fresh scan is required.")
        return current


class Journal:
    """A pre-provisioned binary object is the only atomic writer resource."""

    def __init__(self, drive, scope, item, account):
        self.drive, self.scope, self.item, self.account = drive, scope, key(item), key(account)
        self.qualified = False
        self.qualified_storage = None

    def read_object(self, item):
        from io import BytesIO
        before = self.drive.meta(item)
        if before.get("parents") != [self.scope.reports]:
            raise DriveError("Journal and probe must be directly in the reports folder.")
        if before.get("mimeType") != "application/json":
            raise DriveError("Upload the journal as a binary application/json file.")
        source = identity(before)
        data = BytesIO()
        etag = self.drive.read(item, JOURNAL_LIMIT, data, source)
        try:
            payload = json.loads(data.getvalue())
        except (ValueError, UnicodeError):
            raise DriveError("Journal is not a valid JSON record.") from None
        if not isinstance(payload, dict):
            raise DriveError("Journal must be a JSON object.")
        return payload, etag, before.get("capabilities", {})

    def snapshot(self):
        folder = self.drive.meta(self.scope.intake)
        if (folder.get("trashed") or folder.get("mimeType") != FOLDER
                or folder.get("properties", {}).get("epubValidatorV5Journal") != self.item):
            raise DriveError("The intake folder does not bind this canonical journal ID.")
        value, etag, capabilities = self.read_object(self.item)
        if value.get("format") != 1 or value.get("intake") != self.scope.intake or value.get("account") != self.account:
            raise DriveError("Journal is bound to a different intake or account.")
        if (not isinstance(value.get("books"), dict) or not isinstance(value.get("writer"), (str, type(None)))
                or type(value.get("generation")) is not int or value["generation"] < 0):
            raise DriveError("Unexpected journal schema.")
        return value, etag, capabilities

    def qualify(self, probe):
        """Only the designated disposable artifact is touched by this test."""
        import secrets
        probe = key(probe)
        if probe == self.item:
            raise DriveError("Use a separate disposable CAS probe object.")
        old, first, capabilities = self.read_object(probe)
        if old.get("purpose") != "epub-v5-disposable-cas-probe" or not capabilities.get("canEdit"):
            raise DriveError("Disposable CAS probe is unrecognized or not writable.")
        if not strong_etag(first) or old.get("state") == "refused":
            raise DriveError("Disposable probe lacks a fresh strong ETag qualification.")
        change = {"purpose": old["purpose"], "nonce": secrets.token_hex(16)}
        self.drive.patch_journal(probe, canonical(change), first)
        current, second, _ = self.read_object(probe)
        if current != change or not strong_etag(second) or second == first:
            raise DriveError("Drive did not preserve a distinct conditional journal version.")
        try:
            self.drive.patch_journal(probe, canonical({**change, "state": "refused"}), first)
        except Conflict:
            pass
        else:
            raise DriveError("This Drive route accepted a stale write. Journal writes are disabled.")
        if self.read_object(probe)[:2] != (current, second):
            raise DriveError("A concurrent writer changed the qualifying probe.")
        _, etag, capabilities = self.snapshot()
        if not strong_etag(etag) or not capabilities.get("canEdit"):
            raise DriveError("Journal media ETag or edit capability unavailable.")
        self.qualified_storage = self.drive.meta(self.item).get("driveId")
        self.qualified = True

    def update(self, value, etag):
        data = canonical(value)
        if not self.qualified or len(data) > JOURNAL_LIMIT:
            raise DriveError("Conditional journal writes are unavailable or the journal is full.")
        self.drive.patch_journal(self.item, data, etag)
        current, _, _ = self.snapshot()
        if current != value:
            raise Conflict("Journal confirmation changed. Inspect current status before proceeding.")
        return current

    def acquire(self, owner, *, takeover=False):
        value, etag, _ = self.snapshot()
        if value["writer"] == owner:
            return value["generation"]
        if value["writer"] is not None and not takeover:
            raise Conflict("Another notebook owns this journal. Status is read-only until explicit takeover.")
        if value.get("in_flight_physical"):
            raise Conflict("A physical operation still needs reconciliation before takeover.")
        replacement = {**value, "writer": owner, "generation": value["generation"] + 1}
        return self.update(replacement, etag)["generation"]

    def owned(self, owner, generation):
        value, etag, _ = self.snapshot()
        if (value["writer"], value["generation"]) != (owner, generation):
            raise Conflict("This notebook has lost writer ownership.")
        return value, etag

    def commit(self, owner, generation, configuration, books):
        value, etag = self.owned(owner, generation)
        return self.update({**value, "configuration": configuration, "books": books}, etag)

    def begin_operation(self, owner, generation, intent):
        value, etag = self.owned(owner, generation)
        if value.get("in_flight_physical"):
            raise Conflict("Another physical operation needs reconciliation first.")
        self.update({**value, "in_flight_physical": intent}, etag)

    def finish_operation(self, owner, generation, intent, book):
        value, etag = self.owned(owner, generation)
        if value.get("in_flight_physical") != intent:
            raise Conflict("This operation is no longer the active physical intent.")
        entry = {**book, "operation": {**book["operation"], "status": intent["result"]}} if "result" in intent else book
        self.update({**value, "in_flight_physical": None,
                     "books": {**value["books"], book["source"]["id"]: entry}}, etag)

    def finish_recovery(self, value, etag, intent, book):
        # Caller already fenced a possibly queued write to the physical object.
        if value.get("in_flight_physical") != intent:
            raise Conflict("The physical operation changed during recovery.")
        self.update({**value, "in_flight_physical": None,
                     "books": {**value["books"], book["source"]["id"]: book}}, etag)


def journal_template(intake, account):
    return {"format": 1, "intake": key(intake), "account": key(account), "writer": None,
            "generation": 0, "configuration": None, "books": {}}


def reconcile(drive, scope, record):
    """Read back a previously recorded intent. Never infer that an invisible item is absent."""
    operation = record.get("operation")
    if not operation:
        return record
    source = record["source"]
    action = operation.get("action")
    observed = {}
    try:
        if action == "quarantine":
            current = identity(drive.meta(source["id"]))
            if (current["parents"] == [scope.quarantine] and current["sha256"] == source["sha256"]
                    and current["size"] == source["size"] and current["headRevisionId"] == source["headRevisionId"]):
                return {**record, "operation": {**operation, "status": "complete"}}
        elif action in {"publish", "stage_repair"} and operation.get("destination_id"):
            observed = identity(drive.meta(operation["destination_id"]))
            destination = scope.editions if action == "publish" else scope.repair
            if (observed["parents"] != [destination]
                    or observed["sha256"] != operation.get("expected_sha256")):
                raise Conflict("Reserved destination does not match the recorded parent and hash.")
            scope.current(drive, source)
            return {**record, "operation": {**operation, "status": "complete"}}
        scope.current(drive, source)
    except DriveError:
        return {**record, "operation": {**operation, "status": "ambiguous" if
                operation.get("dispatched") or observed else "stale_or_inaccessible"}}
    return {**record, "operation": {**operation, "status": "pending"}}


class Quarantine:
    """Single-file Drive mutation behind a persistent intent and a tested conditional route."""

    def __init__(self, drive, scope, journal):
        self.drive, self.scope, self.journal = drive, scope, journal
        self.qualified_drive = None

    def qualify(self, disposable_file, disposable_from, disposable_to):
        import secrets
        source_dir, target_dir = (self.drive.meta(folder) for folder in (disposable_from, disposable_to))
        configured = self.scope.outputs() | {self.scope.intake}
        for directory in (source_dir, target_dir):
            if (directory.get("mimeType") != FOLDER or directory.get("trashed")
                    or directory.get("parents") != [self.scope.reports] or directory["id"] in configured
                    or directory.get("properties", {}).get("epubValidatorV5Probe") != "disposable"):
                raise DriveError("Conditional-move probes require two disposable sibling folders in reports.")
        initial, first = self.drive.tagged_meta(disposable_file)
        if (disposable_from == disposable_to or initial.get("parents") not in ([disposable_from], [disposable_to])
                or initial.get("properties", {}).get("epubValidatorV5Probe") != "disposable"):
            raise DriveError("Conditional-move probe file is not a disposable probe in a designated folder.")
        before = identity(initial)
        if initial["parents"] == [disposable_to]:
            disposable_from, disposable_to = disposable_to, disposable_from
        from io import BytesIO
        media_etag = self.drive.read(disposable_file, 1024 * 1024, BytesIO(), before)
        altered = secrets.token_bytes(32)
        self.drive.patch_media(disposable_file, altered, media_etag, before["mimeType"])
        check, revised_meta_tag = self.drive.tagged_meta(disposable_file)
        if (revised_meta_tag == first or check.get("parents") != [disposable_from]
                or identity(check)["sha256"] != hashlib.sha256(altered).hexdigest()):
            raise DriveError("Metadata ETag did not track the disposable Drive content change.")
        try:
            self.drive.patch_metadata(disposable_file, first, {}, add=disposable_to, remove=disposable_from)
        except Conflict:
            pass
        else:
            raise DriveError("Drive accepted a move based on an old binary revision.")
        initial, first = check, revised_meta_tag
        next_fence = secrets.token_hex(16)
        self.drive.patch_metadata(disposable_file, first, {"properties": {"epubV5Fence": next_fence}})
        changed, second = self.drive.tagged_meta(disposable_file)
        if (first == second or changed.get("properties", {}).get("epubV5Fence") != next_fence
                or changed.get("parents") != [disposable_from]
                or identity(initial)["sha256"] != identity(changed)["sha256"]):
            raise DriveError("Conditional-move probe cannot fence a delayed request.")
        try:
            self.drive.patch_metadata(disposable_file, first, {}, add=disposable_to, remove=disposable_from)
        except Conflict:
            pass
        else:
            raise DriveError("Drive accepted a stale conditional move. Quarantine writes are disabled.")
        if self.drive.tagged_meta(disposable_file) != (changed, second):
            raise DriveError("Disposable move probe was changed concurrently.")
        self.drive.patch_metadata(disposable_file, second, {}, add=disposable_to, remove=disposable_from)
        moved, third = self.drive.tagged_meta(disposable_file)
        if (third in {first, second} or moved.get("parents") != [disposable_to]
                or identity(moved)["sha256"] != identity(changed)["sha256"]):
            raise DriveError("Conditional-move probe failed exact readback.")
        ids = {directory.get("driveId") for directory in (source_dir, target_dir)}
        ids.add(moved.get("driveId"))
        if len(ids) != 1:
            raise DriveError("Probe did not cover one Drive storage class.")
        self.qualified_drive = (True, ids.pop())

    def dispatch(self, owner, generation, book):
        source = book["source"]
        if self.qualified_drive != (True, source.get("driveId")):
            raise DriveError("Conditional quarantine move is unqualified on this Drive.")
        destination = self.drive.meta(self.scope.quarantine)
        if (destination.get("driveId") != source.get("driveId") or destination.get("trashed")
                or destination.get("mimeType") != FOLDER or
                not destination.get("capabilities", {}).get("canAddChildren")):
            raise DriveError("Quarantine requires a writable destination on the same Drive.")
        live, etag = self.drive.tagged_meta(source["id"])
        self.scope.within(self.drive, live)
        if identity(live) != source:
            raise Conflict("The source changed before quarantine dispatch.")
        if source["parents"] != [self.scope.intake]:
            raise DriveError("Nested quarantine requires an atomic ancestor guard and remains pending.")
        if not live.get("capabilities", {}).get("canMoveItemWithinDrive"):
            raise DriveError("The account cannot move this file within its Drive.")
        class DigestOnly:
            def write(self, data):
                return len(data)

        self.drive.read(source["id"], source["size"], DigestOnly(), source)
        if any(item.get("name") == source["name"] for item in self.drive.children(destination)):
            raise DriveError("Quarantine destination name is occupied.")
        intent = {"id": book["operation"]["id"], "object": source["id"], "etag": etag,
                  "parent": source["parents"][0], "target": self.scope.quarantine,
                  "source": source}
        self.journal.begin_operation(owner, generation, intent)
        self.drive.patch_metadata(source["id"], etag, {},
                                  add=self.scope.quarantine, remove=source["parents"][0])
        verified = reconcile(self.drive, self.scope, book)
        if verified["operation"]["status"] != "complete":
            raise Conflict("Move was dispatched but exact readback is uncertain.")
        verified["state"] = "complete"
        self.journal.finish_operation(owner, generation, intent, verified)
        return verified

    def recover(self, owner, generation, *, takeover=False):
        """Fence a delayed PATCH before releasing the durable writer barrier."""
        import secrets
        if takeover:
            value, etag, _ = self.journal.snapshot()
        else:
            value, etag = self.journal.owned(owner, generation)
        intent = value.get("in_flight_physical")
        if not intent:
            return
        book = value["books"][intent["object"]]
        source = intent["source"]
        if (intent.get("target") != self.scope.quarantine
                or self.qualified_drive != (True, source.get("driveId"))):
            raise Conflict("Original configuration and move qualification are required to reconcile takeover.")
        for _ in range(3):
            observed, observed_etag = self.drive.tagged_meta(source["id"])
            current = identity(observed)
            if (current["parents"] == [intent["target"]] and current["sha256"] == source["sha256"]
                    and current["headRevisionId"] == source["headRevisionId"] and observed_etag != intent["etag"]):
                verified = {**book, "state": "complete",
                            "operation": {**book["operation"], "status": "complete"}}
                break
            if observed_etag != intent["etag"]:
                # This includes an external edit or a previous successful drain.
                verified = {**book, "state": "stale",
                            "operation": {**book["operation"], "status": "stale_or_inaccessible"}}
                break
            if current != source:
                raise Conflict("Source ETag failed to track a source identity change.")
            target = self.drive.meta(intent["target"])
            if (target.get("trashed") or target.get("mimeType") != FOLDER
                    or not target.get("capabilities", {}).get("canAddChildren")
                    or target.get("driveId") != current.get("driveId")
                    or not observed.get("capabilities", {}).get("canMoveItemWithinDrive")
                    or any(item.get("name") == source["name"] for item in self.drive.children(target))):
                raise Conflict("The existing move intent needs a writable unoccupied destination.")
            if not takeover:
                try:
                    self.drive.patch_metadata(source["id"], intent["etag"], {},
                                              add=intent["target"], remove=intent["parent"])
                except Conflict:
                    pass
                continue
            fence = secrets.token_hex(16)
            try:
                self.drive.patch_metadata(source["id"], intent["etag"], {"properties": {"epubV5Fence": fence}})
            except Conflict:
                continue
            after, new_tag = self.drive.tagged_meta(source["id"])
            if new_tag == intent["etag"] or after.get("properties", {}).get("epubV5Fence") != fence:
                raise Conflict("Physical write fence could not be established.")
            rebound = identity(after)
            if any(rebound[field] != source[field] for field in source if field != "version"):
                raise Conflict("Source changed while fencing the interrupted operation.")
            operation = {**book["operation"], "status": "pending", "dispatched": False,
                         "reason": "Interrupted move fenced. Source content and revision rechecked."}
            verified = {**book, "source": rebound, "state": "pending", "operation": operation}
            break
        else:
            raise Conflict("Physical operation is still ambiguous.")
        self.journal.finish_recovery(value, etag, intent, verified)


class EvidenceStore:
    """One pre-provisioned CAS object stores detailed evidence separately from decisions."""

    def __init__(self, drive, scope, journal, item):
        self.drive, self.scope, self.journal, self.item = drive, scope, journal, key(item)

    def snapshot(self):
        from io import BytesIO
        folder = self.drive.meta(self.scope.evidence)
        if folder.get("properties", {}).get("epubValidatorV5Evidence") != self.item:
            raise DriveError("Evidence folder does not bind this canonical evidence ID.")
        meta = self.drive.meta(self.item)
        if (meta.get("parents") != [self.scope.evidence] or meta.get("mimeType") != "application/json"
                or not meta.get("capabilities", {}).get("canEdit")):
            raise DriveError("The evidence file is outside its dedicated folder or is not writable.")
        source = identity(meta)
        if not self.journal.qualified or source.get("driveId") != self.journal.qualified_storage:
            raise DriveError("Evidence file requires a qualified JSON media route in the same Drive.")
        target = BytesIO()
        etag = self.drive.read(self.item, JOURNAL_LIMIT, target, source)
        try:
            value = json.loads(target.getvalue())
        except (UnicodeError, ValueError):
            raise DriveError("Evidence file is not valid JSON.") from None
        if (not isinstance(value, dict) or value.get("intake") != self.scope.intake
                or value.get("format") != 1 or not isinstance(value.get("traces"), dict)
                or not strong_etag(etag)):
            raise DriveError("Evidence file has invalid binding or conditional media identity.")
        return value, etag, source["sha256"]

    def write(self, owner, generation, book, details):
        import secrets
        if not self.journal.qualified:
            raise DriveError("Qualify conditional updates before writing evidence.")
        evidence, tag, _ = self.snapshot()
        trace = book["trace"]
        if stamp(details) != trace["sha256"]:
            raise DriveError("Temporary evidence differs from the durable digest.")
        value = {**evidence, "traces": {**evidence["traces"], key(trace["slot"]): {
            "book": book["source"]["id"], "expiry": trace["expires_at"], "details": details,
            "sha256": trace["sha256"], "configuration": book["configuration"]}},
            "nonce": secrets.token_hex(16)}
        return self.change(owner, generation, book, value, tag, "stored", trace["slot"])

    @staticmethod
    def mark_trace(book, slot, status):
        from copy import deepcopy
        book = deepcopy(book)
        for decision in (book, *book.get("history", ())):
            trace = decision.get("trace")
            if trace and trace["slot"] == slot:
                trace["status"] = status
        return book

    def expire(self, owner, generation, book, slot):
        import secrets
        evidence, tag, _ = self.snapshot()
        if slot not in evidence["traces"]:
            return self.mark_trace(book, slot, "expired")
        traces = {key: value for key, value in evidence["traces"].items() if key != slot}
        return self.change(owner, generation, book,
                           {**evidence, "traces": traces, "nonce": secrets.token_hex(16)}, tag, "expired", slot)

    def change(self, owner, generation, book, value, tag, result, slot):
        data = canonical(value)
        if len(data) > JOURNAL_LIMIT:
            raise DriveError("Evidence file reached the bounded storage limit.")
        if result == "stored":
            self.scope.current(self.drive, book["source"])
        intent = {"kind": "evidence", "id": stamp([self.item, book["source"]["id"], tag, result]),
                  "object": book["source"]["id"], "target": self.item, "etag": tag,
                  "sha256": hashlib.sha256(data).hexdigest(), "result": result, "slot": slot}
        self.journal.begin_operation(owner, generation, intent)
        self.drive.patch_journal(self.item, data, tag)
        if self.snapshot()[2] != intent["sha256"]:
            raise Conflict("Evidence response could not be reconciled.")
        verified = self.mark_trace(book, slot, result)
        value, journal_tag = self.journal.owned(owner, generation)
        self.journal.finish_recovery(value, journal_tag, intent, verified)
        return verified

    def recover(self, owner, generation, *, takeover=False):
        import secrets
        if takeover:
            journal, journal_tag, _ = self.journal.snapshot()
        else:
            journal, journal_tag = self.journal.owned(owner, generation)
        intent = journal.get("in_flight_physical")
        if not intent or intent.get("kind") != "evidence" or intent.get("target") != self.item:
            raise Conflict("Canonical evidence configuration is required to resolve the pending write.")
        book = journal["books"][intent["object"]]
        for _ in range(3):
            current, tag, digest = self.snapshot()
            if digest == intent["sha256"]:
                status = intent["result"]
                break
            if tag != intent["etag"]:
                status = "evidence needs fresh reconciliation"
                break
            # Current and delayed updates contend on the same old ETag.
            # The randomized fence preserves all currently stored traces.
            fence = {**current, "nonce": secrets.token_hex(16)}
            try:
                self.drive.patch_journal(self.item, canonical(fence), tag)
            except Conflict:
                continue
            readback, observed, _ = self.snapshot()
            if observed == tag or readback != fence:
                raise Conflict("Could not establish a fence on the evidence object.")
            status = "evidence folder upload pending" if intent["result"] == "stored" else "expiry pending"
            break
        else:
            raise Conflict("Evidence write remains ambiguous.")
        resolved = self.mark_trace(book, intent["slot"], status)
        self.journal.finish_recovery(journal, journal_tag, intent, resolved)


def evidence_template(intake):
    return {"format": 1, "intake": key(intake), "traces": {}}


CANDIDATE_SLOT_BYTES = 5 * 1024 * 1024


def candidate_template(book):
    return {"purpose": "epub-v5-candidate-slot", "book": key(book)}


class CandidateStore:
    """Update a dedicated, unpublished staging object with exact verified bytes."""

    def __init__(self, drive, scope, journal, item, qualified_drives=()):
        self.drive, self.scope, self.journal, self.item = drive, scope, journal, key(item)
        self.qualified_drives = qualified_drives

    def qualify(self):
        import secrets
        data, original, tag = self.snapshot("disposable")
        if not self.placeholder(data, "disposable"):
            raise DriveError("Candidate CAS probe is not a disposable binary staging object.")
        # A reparent or metadata change must invalidate even the media token.
        _, metadata_tag = self.drive.tagged_meta(self.item)
        self.drive.patch_metadata(self.item, metadata_tag, {
            "properties": {"epubV5BinaryProbe": secrets.token_hex(16)}})
        unchanged, refreshed, changed_tag = self.snapshot("disposable")
        if changed_tag == tag or refreshed["sha256"] != original["sha256"] or unchanged != data:
            raise DriveError("Binary media ETag does not fence metadata changes.")
        try:
            self.drive.patch_media(self.item, b"stale-probe", tag, "application/octet-stream")
        except Conflict:
            pass
        else:
            raise DriveError("Drive accepted a stale binary PATCH. Candidate writes remain disabled.")
        change = canonical({**candidate_template("disposable"), "fence": secrets.token_hex(16)})
        self.drive.patch_media(self.item, change, changed_tag, "application/octet-stream")
        readback, _, final_tag = self.snapshot("disposable")
        if readback != change or final_tag in {tag, changed_tag}:
            raise DriveError("Binary CAS probe did not verify exact current media update.")
        return original.get("driveId")

    def snapshot(self, book):
        from io import BytesIO
        meta = self.drive.meta(self.item)
        if (meta.get("mimeType") != "application/octet-stream" or meta.get("parents") != [self.scope.evidence]
                or meta.get("properties", {}).get("epubValidatorV5Candidate") != book
                or not meta.get("capabilities", {}).get("canEdit")):
            raise DriveError("Use a writable, book-bound staging object in the configured evidence folder.")
        source = identity(meta)
        data = BytesIO()
        tag = self.drive.read(self.item, CANDIDATE_SLOT_BYTES, data, source)
        if not strong_etag(tag):
            raise DriveError("The candidate staging object has no strong media ETag.")
        return data.getvalue(), source, tag

    @staticmethod
    def placeholder(data, book):
        if len(data) > 1024:
            return False
        try:
            value = json.loads(data)
        except (UnicodeError, ValueError):
            return False
        return (isinstance(value, dict) and value.get("purpose") == "epub-v5-candidate-slot"
                and value.get("book") == book and not (set(value) - {"purpose", "book", "fence"}))

    def store(self, owner, generation, record, candidate, expected):
        if not self.journal.qualified:
            raise DriveError("Qualify journal conditional updates before candidate staging.")
        source = record["source"]
        self.scope.current(self.drive, source)
        with candidate.open("rb") as stream:
            output = stream.read(CANDIDATE_SLOT_BYTES + 1)
        if (not output or len(output) > CANDIDATE_SLOT_BYTES or
                hashlib.sha256(output).hexdigest() != expected):
            raise DriveError("Candidate staging accepts up to 5 MiB of exact verified bytes.")
        data, slot, tag = self.snapshot(source["id"])
        if slot.get("driveId") not in self.qualified_drives:
            raise DriveError("This candidate slot requires a matched disposable binary CAS qualification.")
        if slot["sha256"] == expected:
            return {**record, "candidate": {"id": self.item, "sha256": expected, "status": "staged"}}
        if not self.placeholder(data, source["id"]):
            raise DriveError("Candidate slot is occupied. Preserve it and configure a new reserved ID.")
        intent = {"kind": "candidate", "id": stamp([self.item, source["id"], expected]),
                  "object": source["id"], "target": self.item, "etag": tag,
                  "sha256": expected, "source": source}
        self.journal.begin_operation(owner, generation, intent)
        self.drive.patch_media(self.item, output, tag, "application/octet-stream")
        if self.snapshot(source["id"])[1]["sha256"] != expected:
            raise Conflict("Candidate staging readback did not match its verified bytes.")
        try:
            self.scope.current(self.drive, source)
        except DriveError:
            status = "staged_from_stale_source"
        else:
            status = "staged"
        staged = {**record, "candidate": {"id": self.item, "sha256": expected, "status": status}}
        journal, journal_tag = self.journal.owned(owner, generation)
        self.journal.finish_recovery(journal, journal_tag, intent, staged)
        return staged

    def recover(self, owner, generation, *, takeover=False):
        import secrets
        if takeover:
            value, journal_tag, _ = self.journal.snapshot()
        else:
            value, journal_tag = self.journal.owned(owner, generation)
        intent = value.get("in_flight_physical")
        if not intent or intent.get("kind") != "candidate" or intent.get("target") != self.item:
            raise Conflict("Original staging identity is required to reconcile this operation.")
        book = intent["object"]
        for _ in range(3):
            data, current, tag = self.snapshot(book)
            if current.get("driveId") not in self.qualified_drives:
                raise DriveError("Requalify the candidate slot’s binary CAS route before reconciliation.")
            if current["sha256"] == intent["sha256"] and tag != intent["etag"]:
                try:
                    self.scope.current(self.drive, intent["source"])
                except DriveError:
                    status = "staged_from_stale_source"
                else:
                    status = "staged"
                break
            if tag != intent["etag"]:
                status = "staging_needs_retry" if self.placeholder(data, book) else "ambiguous"
                break
            if not self.placeholder(data, book):
                raise Conflict("Reserved candidate no longer has the original state.")
            fence = canonical({**candidate_template(book), "fence": secrets.token_hex(16)})
            try:
                self.drive.patch_media(self.item, fence, tag, "application/octet-stream")
            except Conflict:
                continue
            after, _, current_tag = self.snapshot(book)
            if current_tag == tag or after != fence:
                raise Conflict("Could not fence the reserved candidate slot.")
            status = "staging_needs_retry"
            break
        else:
            raise Conflict("The candidate upload is still ambiguous.")
        row = value["books"][book]
        checked = {**row, "candidate": {"id": self.item, "sha256": intent["sha256"], "status": status}}
        self.journal.finish_recovery(value, journal_tag, intent, checked)
