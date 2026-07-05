import shutil
import subprocess
from pathlib import Path

import pytest


def test_dane_generator_handoff_contract():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for the browser handoff contract test")

    subprocess.run(
        [node, str(Path("tests/js/test_generator_handoff.js"))],
        check=True,
    )
