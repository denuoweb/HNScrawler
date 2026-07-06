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


def test_app_link_and_search_helpers_contract():
    node = shutil.which("node")
    if not node:
        pytest.skip("node is required for the browser app contract test")

    subprocess.run(
        [node, str(Path("tests/js/test_app_links_search.js"))],
        check=True,
    )
