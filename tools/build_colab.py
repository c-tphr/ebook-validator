"""Regenerate the self-contained v5 notebook from this checkout."""

from base64 import b64encode
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
payload = BytesIO()
with ZipFile(payload, "w") as archive:
    for path in sorted((ROOT / "epub_triage").glob("*.py")):
        item = ZipInfo(path.relative_to(ROOT).as_posix(), (2026, 11, 19, 0, 0, 0))
        archive.writestr(item, path.read_bytes(), compress_type=ZIP_DEFLATED)
data = payload.getvalue()
encoded = b64encode(data).decode("ascii")
source = f"""# @title Open the EPUB validator
import base64
import hashlib
import io
import sys
import tempfile
import zipfile

bundle = base64.b64decode("{encoded}", validate=True)
if hashlib.sha256(bundle).hexdigest() != "{sha256(data).hexdigest()}":
    raise RuntimeError("Validator bundle digest does not match.")
bundle_folder = tempfile.TemporaryDirectory(prefix="epub-validator-source-")
with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
    archive.extractall(bundle_folder.name)
sys.path.insert(0, bundle_folder.name)
from epub_triage.colab_ui import show
show()
"""
intro = """# EPUB validator v5

Open this notebook in hosted Google Colab, connect a CPU runtime, then run the cell below. Select **Set up** to install and qualify local workers. Select **Connect Drive** to authorize the Drive API. Enter the folder IDs for your intake and destinations. **Report-only** is enabled by default. **Open status** reads existing records. **Resume** resumes only when requested, and a writer change requires explicit takeover.

Use the V5-COLAB.md release guide for journal provisioning, conditional write qualification, supported dispositions, and reviewer readiness. The notebook includes its controller source and requests that Colab omit cell outputs on save.
"""
notebook = {
    "nbformat": 4, "nbformat_minor": 5,
    "metadata": {"colab": {"name": "EPUB validator v5", "toc_visible": True,
                           "include_colab_link": True, "provenance": [], "private_outputs": True},
                 "kernelspec": {"name": "python3", "display_name": "Python 3"},
                 "language_info": {"name": "python"}},
    "cells": [
        {"id": "instructions", "cell_type": "markdown", "metadata": {}, "source": intro.splitlines(True)},
        {"id": "workflow", "cell_type": "code", "execution_count": None, "metadata": {"cellView": "form"},
         "outputs": [], "source": source.splitlines(True)}
    ],
}
(ROOT / "EPUB-validator-v5.ipynb").write_text(json.dumps(notebook, indent=1) + "\n")
