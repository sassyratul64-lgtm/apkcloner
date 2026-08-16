"""
tests/conftest.py

Builds a minimal, structurally valid test APK at test-collection time
using locally installed `aapt` + a hand-built empty DEX. No external
APKs are downloaded - this keeps the test suite self-contained and
avoids any question about the legality/provenance of test fixtures.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

import pytest

MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.fixture"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="23"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="@string/app_name" android:icon="@mipmap/ic_launcher">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

STRINGS_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">Fixture App</string>
</resources>
"""


def _build_empty_dex() -> bytes:
    """Hand-constructs a minimal, structurally valid DEX file (0 classes)
    with correct header, checksum and signature so real tools (apktool,
    androguard) accept it as genuine input."""
    HEADER_SIZE = 0x70
    MAP_OFF = HEADER_SIZE
    map_list = struct.pack("<I", 2)
    map_list += struct.pack("<HHII", 0x0000, 0, 1, 0)
    map_list += struct.pack("<HHII", 0x1000, 0, 1, MAP_OFF)
    file_size = HEADER_SIZE + len(map_list)

    def build_header(checksum: int, signature: bytes) -> bytes:
        h = b"dex\n035\x00"
        h += struct.pack("<I", checksum)
        h += signature
        h += struct.pack("<I", file_size)
        h += struct.pack("<I", HEADER_SIZE)
        h += struct.pack("<I", 0x12345678)
        h += struct.pack("<I", 0)  # link_size
        h += struct.pack("<I", 0)  # link_off
        h += struct.pack("<I", MAP_OFF)
        for _ in range(5):  # string/type/proto/field/method ids: size,off pairs
            h += struct.pack("<II", 0, 0)
        h += struct.pack("<II", 0, 0)  # class_defs size/off
        h += struct.pack("<I", len(map_list))  # data_size
        h += struct.pack("<I", MAP_OFF)  # data_off
        assert len(h) == HEADER_SIZE
        return h

    draft = build_header(0, b"\x00" * 20) + map_list
    signature = hashlib.sha1(draft[32:]).digest()
    draft2 = build_header(0, signature) + map_list
    checksum = zlib.adler32(draft2[12:]) & 0xFFFFFFFF
    return build_header(checksum, signature) + map_list


@pytest.fixture(scope="session")
def fixture_apk(tmp_path_factory) -> Path:
    aapt = shutil.which("aapt")
    if aapt is None:
        pytest.skip("aapt not installed - cannot build test fixture APK")

    android_jar_candidates = list(Path("/usr/lib/android-sdk/platforms").glob("android-*/android.jar"))
    if not android_jar_candidates:
        pytest.skip("No android.jar platform found - cannot build test fixture APK")
    android_jar = android_jar_candidates[0]

    workdir = tmp_path_factory.mktemp("fixture_src")
    (workdir / "res" / "values").mkdir(parents=True)
    (workdir / "res" / "mipmap-mdpi").mkdir(parents=True)
    (workdir / "AndroidManifest.xml").write_text(MANIFEST_XML)
    (workdir / "res" / "values" / "strings.xml").write_text(STRINGS_XML)

    from PIL import Image
    Image.new("RGBA", (48, 48), (255, 0, 0, 255)).save(
        workdir / "res" / "mipmap-mdpi" / "ic_launcher.png"
    )

    out_apk = workdir / "fixture.apk"
    subprocess.run(
        [aapt, "package", "-f", "-M", "AndroidManifest.xml", "-S", "res",
         "-I", str(android_jar), "-F", str(out_apk)],
        cwd=workdir, check=True, capture_output=True,
    )

    dex_path = workdir / "classes.dex"
    dex_path.write_bytes(_build_empty_dex())
    with zipfile.ZipFile(out_apk, "a") as zf:
        zf.write(dex_path, "classes.dex")

    return out_apk


@pytest.fixture
def corrupt_apk(tmp_path) -> Path:
    p = tmp_path / "corrupt.apk"
    p.write_bytes(b"not a real zip/apk")
    return p
