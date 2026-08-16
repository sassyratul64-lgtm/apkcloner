from pathlib import Path

from core.builder import ApkBuilder
from core.manifest_manager import ManifestManager
from core.permission_manager import PermissionManager
from core.component_manager import ComponentManager


def _decode(fixture_apk: Path, tmp_path: Path) -> Path:
    out = tmp_path / "decoded"
    ApkBuilder().decode(fixture_apk, out)
    return out


def test_manifest_package_rename(fixture_apk, tmp_path):
    decoded = _decode(fixture_apk, tmp_path)
    mm = ManifestManager(decoded / "AndroidManifest.xml")
    assert mm.get_package() == "com.example.fixture"
    mm.set_package("com.ratul.renamed")
    mm.save()

    mm2 = ManifestManager(decoded / "AndroidManifest.xml")
    assert mm2.get_package() == "com.ratul.renamed"


def test_permission_removal_reports_correctly(fixture_apk, tmp_path):
    decoded = _decode(fixture_apk, tmp_path)
    mm = ManifestManager(decoded / "AndroidManifest.xml")
    pm = PermissionManager(mm)
    assert "android.permission.INTERNET" in pm.list_permissions()

    log = []
    assert pm.remove("android.permission.INTERNET", log) is True
    assert "android.permission.INTERNET" in log
    # second removal of the same (already gone) permission must report False, not silently pretend
    assert pm.remove("android.permission.INTERNET", log) is False


def test_component_disable_warns_on_launcher_activity(fixture_apk, tmp_path):
    decoded = _decode(fixture_apk, tmp_path)
    mm = ManifestManager(decoded / "AndroidManifest.xml")
    cm = ComponentManager(mm)
    warning = cm.warn_if_essential("activity", "com.example.fixture.MainActivity")
    assert warning is not None  # it's the launcher activity, must warn

    disabled = cm.disable("activity", "com.example.fixture.MainActivity")
    assert disabled is True

    unknown = cm.disable("activity", "com.example.fixture.DoesNotExist")
    assert unknown is False
