import subprocess
from pathlib import Path

import pytest

from core.clone_engine import CloneEngine
from core.modifier import CloneConfig
from storage.workspace import Workspace


def test_workspace_never_touches_original(fixture_apk: Path, tmp_path):
    original_bytes = fixture_apk.read_bytes()
    with Workspace(base_dir=tmp_path) as ws:
        ws.import_original(fixture_apk)
        # mutate the workspace copy, not the original
        ws.original_copy.write_bytes(b"mutated")
        assert ws.verify_original_untouched(fixture_apk) is True
    assert fixture_apk.read_bytes() == original_bytes


def test_full_clone_pipeline_success(fixture_apk: Path, tmp_path):
    engine = CloneEngine()
    config = CloneConfig(
        new_app_name="My Clone",
        new_package_id="com.ratul.myclone",
        new_version_name="2.0",
        new_version_code="2",
    )
    result = engine.run(
        source_apk=fixture_apk,
        config=config,
        destination_dir=tmp_path / "out",
        output_name="MyClone",
    )

    assert result.success is True, result.reason
    assert result.output_apk is not None
    assert result.output_apk.is_file()
    assert result.original_untouched is True
    assert all(result.validation.checks.values())

    # Independently verify with the real apksigner/aapt tools, not our own code.
    verify = subprocess.run(
        ["apksigner", "verify", str(result.output_apk)],
        capture_output=True, text=True,
    )
    assert verify.returncode == 0

    badging = subprocess.run(
        ["aapt", "dump", "badging", str(result.output_apk)],
        capture_output=True, text=True,
    )
    assert "com.ratul.myclone" in badging.stdout
    assert "versionName='2.0'" in badging.stdout

    assert (tmp_path / "out" / "clone-info.json").is_file()


def test_clone_invalid_package_id_fails_before_build(fixture_apk: Path, tmp_path):
    engine = CloneEngine()
    config = CloneConfig(new_package_id="123.not.valid")
    result = engine.run(fixture_apk, config, tmp_path / "out2", "Bad")
    assert result.success is False
    assert result.output_apk is None


def test_clone_missing_source_apk_fails_gracefully(tmp_path):
    engine = CloneEngine()
    result = engine.run(tmp_path / "missing.apk", CloneConfig(), tmp_path / "out3", "X")
    assert result.success is False
    assert result.reason  # never empty on failure
