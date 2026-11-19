"""Open the distributed notebook in a fresh local Jupyter kernel and exercise setup."""
from pathlib import Path
import tempfile

import nbformat
from nbclient import NotebookClient

probe = '''
import contextlib, io, json
from ipywidgets import Button
from ipywidgets.widgets.widget import _instances
buttons = {w.description: w for w in _instances.values() if isinstance(w, Button)}
assert {"Set up", "Open status", "Resume", "Take over and resume", "Request primary", "Second opinion"} <= set(buttons)
with contextlib.redirect_stdout(io.StringIO()) as transcript:
    buttons["Set up"].click()
print(json.dumps({"buttons": sorted(buttons), "setup_output": transcript.getvalue()}))
'''
root = Path(__file__).resolve().parents[1]
nb = nbformat.read(root / "EPUB-validator-v5.ipynb", as_version=4)
nbformat.validate(nb)
assert all(not c.get("outputs") for c in nb.cells)
nb.cells.append(nbformat.v4.new_code_cell(probe))
with tempfile.TemporaryDirectory() as fresh:
    NotebookClient(nb, timeout=360, kernel_name="python3", resources={"metadata": {"path": fresh}}).execute()
for result in nb.cells[-1].outputs:
    if result.output_type == "stream":
        print(result.text.strip())
