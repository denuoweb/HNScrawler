import subprocess
from pathlib import Path


def test_nightly_scripts_parse_as_bash():
    for script in [
        Path("scripts/full-nightly-job.sh"),
        Path("scripts/gcloud-run-indexer-pipeline.sh"),
    ]:
        subprocess.run(["bash", "-n", str(script)], check=True)


def test_full_nightly_stops_hsd_before_live_checks():
    script = Path("scripts/full-nightly-job.sh").read_text(encoding="utf-8")

    assert 'START_HSD_FOR_UPDATES="${START_HSD_FOR_UPDATES:-1}"' in script
    assert 'STOP_HSD_AFTER_UPDATES="${STOP_HSD_AFTER_UPDATES:-1}"' in script
    assert "trap cleanup_hsd EXIT" in script
    assert '\nstart_hsd_for_update\nif [ "$CHECK_HSD_READY" = "1" ]; then' in script
    assert '\nscripts/run-incremental.sh\nstop_hsd_after_update\nif [ "$RUN_LIVE_CHECKS" = "1" ]; then' in script
