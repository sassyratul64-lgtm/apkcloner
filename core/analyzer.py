"""
core/analyzer.py

Real static analysis of an APK. No network access, no execution of any
code contained in the APK. Everything here is passive inspection of the
zip archive, the binary manifest, and the DEX/resource structure.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from androguard.core.apk import APK


@dataclass
class ApkProfile:
    path: Path
    app_name: str = "Unknown"
    package_id: str = "unknown"
    version_name: str = "unknown"
    version_code: str = "0"
    min_sdk: str = "unknown"
    target_sdk: str = "unknown"
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    intent_filters_count: int = 0
    deep_links: list[str] = field(default_factory=list)
    native_abis: list[str] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)
    is_signed: bool = False
    signing_schemes: list[str] = field(default_factory=list)
    is_split_apk: bool = False
    split_names: list[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    debuggable: bool = False
    zip_entry_count: int = 0
    raw_manifest_xml: str = ""
    risks: list[str] = field(default_factory=list)
    cloneability: str = "UNKNOWN"


class AnalysisError(Exception):
    pass


class ApkAnalyzer:
    def analyze(self, apk_path: Path) -> ApkProfile:
        if not apk_path.is_file():
            raise AnalysisError(f"APK not found: {apk_path}")

        # Validate it is actually a zip/APK before trusting anything else.
        if not zipfile.is_zipfile(apk_path):
            raise AnalysisError("File is not a valid ZIP/APK archive.")

        try:
            with zipfile.ZipFile(apk_path) as zf:
                bad = zf.testzip()
                if bad is not None:
                    raise AnalysisError(f"Corrupt entry in APK archive: {bad}")
                names = zf.namelist()
        except zipfile.BadZipFile as e:
            raise AnalysisError(f"Corrupt ZIP structure: {e}")

        if "AndroidManifest.xml" not in names:
            raise AnalysisError("AndroidManifest.xml missing - not a valid APK.")

        try:
            apk = APK(str(apk_path))
        except Exception as e:
            raise AnalysisError(f"Failed to parse APK: {e}")

        profile = ApkProfile(path=apk_path)
        profile.zip_entry_count = len(names)

        profile.app_name = apk.get_app_name() or "Unknown"
        profile.package_id = apk.get_package() or "unknown"
        profile.version_name = apk.get_androidversion_name() or "unknown"
        profile.version_code = str(apk.get_androidversion_code() or "0")
        profile.min_sdk = str(apk.get_min_sdk_version() or "unknown")
        profile.target_sdk = str(apk.get_target_sdk_version() or "unknown")

        profile.activities = list(apk.get_activities())
        profile.services = list(apk.get_services())
        profile.receivers = list(apk.get_receivers())
        profile.providers = list(apk.get_providers())
        profile.permissions = list(apk.get_permissions())
        try:
            dbg = apk.get_attribute_value("application", "debuggable")
        except Exception:
            dbg = None
        profile.debuggable = str(dbg).lower() == "true"

        try:
            profile.raw_manifest_xml = apk.get_android_manifest_axml().get_xml().decode(
                "utf-8", errors="replace"
            )
        except Exception:
            profile.raw_manifest_xml = ""

        profile.intent_filters_count = profile.raw_manifest_xml.count("<intent-filter>")
        profile.deep_links = sorted(set(re.findall(r'android:scheme="([^"]+)"', profile.raw_manifest_xml)))

        profile.native_abis = sorted({
            n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2
        })
        profile.dex_files = sorted(n for n in names if re.match(r"classes\d*\.dex$", n))

        # Signing detection: v1 (META-INF/*.SF/.RSA/.DSA/.EC), v2/v3 (APK Signing Block)
        v1_present = any(
            n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
            for n in names
        )
        schemes = []
        if v1_present:
            schemes.append("v1 (JAR signing)")
        v2v3_present = self._has_apk_signing_block(apk_path)
        if v2v3_present:
            schemes.append("v2/v3 (APK Signature Scheme)")
        profile.is_signed = bool(schemes)
        profile.signing_schemes = schemes

        # Split APK detection
        manifest_split = "split=" in profile.raw_manifest_xml.lower()
        filename_hints = apk_path.name.lower()
        looks_like_split = any(k in filename_hints for k in ["config.", "split_", ".split."])
        profile.is_split_apk = manifest_split or looks_like_split
        if profile.is_split_apk:
            m = re.search(r'split="([^"]+)"', profile.raw_manifest_xml)
            if m:
                profile.split_names.append(m.group(1))

        # Obfuscation heuristic: short/meaningless class-like package path segments in DEX-derived class list
        profile.obfuscation_detected = self._detect_obfuscation(apk)

        self._assess_risks(profile)
        self._score_cloneability(profile)
        return profile

    @staticmethod
    def _has_apk_signing_block(apk_path: Path) -> bool:
        """Looks for the APK Signing Block magic that precedes v2/v3
        signatures, located just before the central directory."""
        magic = b"APK Sig Block 42"
        try:
            with open(apk_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                read_len = min(size, 1 << 20)  # last 1MB is plenty
                f.seek(size - read_len)
                tail = f.read(read_len)
            return magic in tail
        except Exception:
            return False

    @staticmethod
    def _detect_obfuscation(apk: APK) -> bool:
        """Heuristic: parses the primary DEX and checks what fraction of
        class names are 1-2 characters long (typical of ProGuard/R8-style
        obfuscation). If the DEX can't be parsed at all, we don't guess -
        we report 'not detected' rather than fabricating a signal."""
        try:
            from androguard.core.dex import DEX

            dex_bytes = apk.get_dex()
            if not dex_bytes:
                return False
            d = DEX(dex_bytes)
            names = [c.get_name() for c in d.get_classes()]
            if len(names) < 10:
                return False
            short = [
                n for n in names
                if re.search(r"/[a-zA-Z]{1,2};$", n)
            ]
            return (len(short) / max(len(names), 1)) > 0.4
        except Exception:
            return False

    @staticmethod
    def _assess_risks(profile: ApkProfile):
        if not profile.is_signed:
            profile.risks.append("No recognizable signature found on the source APK.")
        if profile.native_abis:
            profile.risks.append(
                f"Native libraries detected ({', '.join(profile.native_abis)}) - "
                "these are not decompiled and are carried through as-is."
            )
        if profile.is_split_apk:
            profile.risks.append(
                "Split/Configuration APK structure detected - standalone cloning is not guaranteed."
            )
        if profile.obfuscation_detected:
            profile.risks.append(
                "Obfuscated code detected - renamed package references inside code may not fully resolve."
            )
        if len(profile.dex_files) > 1:
            profile.risks.append(
                f"Multidex app ({len(profile.dex_files)} DEX files) - rebuild time and risk increase."
            )
        if profile.debuggable:
            profile.risks.append("App is marked debuggable in the manifest.")

    @staticmethod
    def _score_cloneability(profile: ApkProfile):
        risk_count = len(profile.risks)
        if profile.is_split_apk:
            profile.cloneability = "HIGH RISK"
        elif profile.obfuscation_detected and profile.native_abis:
            profile.cloneability = "LIMITED"
        elif risk_count == 0:
            profile.cloneability = "FULL"
        elif risk_count <= 2:
            profile.cloneability = "GOOD"
        else:
            profile.cloneability = "LIMITED"
