from pathlib import Path
import pytest

from core.analyzer import ApkAnalyzer, AnalysisError


def test_analyze_valid_fixture(fixture_apk: Path):
    profile = ApkAnalyzer().analyze(fixture_apk)
    assert profile.package_id == "com.example.fixture"
    assert profile.app_name == "Fixture App"
    assert profile.version_name == "1.0"
    assert profile.version_code == "1"
    assert profile.min_sdk == "21"
    assert profile.target_sdk == "23"
    assert "com.example.fixture.MainActivity" in profile.activities
    assert "android.permission.INTERNET" in profile.permissions
    assert profile.dex_files == ["classes.dex"]
    assert profile.cloneability in ("FULL", "GOOD", "LIMITED", "HIGH RISK")


def test_analyze_corrupt_apk_raises(corrupt_apk: Path):
    with pytest.raises(AnalysisError):
        ApkAnalyzer().analyze(corrupt_apk)


def test_analyze_missing_file_raises(tmp_path: Path):
    with pytest.raises(AnalysisError):
        ApkAnalyzer().analyze(tmp_path / "nope.apk")
