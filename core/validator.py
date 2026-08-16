"""
core/validator.py

This is the single source of truth for whether a clone is allowed to be
reported as successful. Every check is a real, independent verification
against the actual output file - nothing here is assumed.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from androguard.core.apk import APK

from core.aligner import ApkAligner
from core.signer import ApkSigner


@dataclass
class ValidationResult:
    checks: dict[str, bool] = field(default_factory=dict)
    details: dict[str, str] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return len(self.checks) > 0 and all(self.checks.values())


class ApkValidator:
    def __init__(self, aligner: ApkAligner, signer: ApkSigner):
        self.aligner = aligner
        self.signer = signer

    def validate(self, apk_path: Path, expected_package_id: str) -> ValidationResult:
        result = ValidationResult()

        # 1. File exists and is readable
        exists = apk_path.is_file()
        result.checks["apk_file_exists"] = exists
        if not exists:
            result.details["apk_file_exists"] = "Output file was not written."
            return result  # nothing else can be checked meaningfully

        # 2. ZIP integrity
        try:
            zip_ok = zipfile.is_zipfile(apk_path)
            if zip_ok:
                with zipfile.ZipFile(apk_path) as zf:
                    bad = zf.testzip()
                    zip_ok = bad is None
                    names = zf.namelist()
            else:
                names = []
        except Exception as e:
            zip_ok = False
            names = []
            result.details["zip_integrity"] = str(e)
        result.checks["zip_integrity"] = zip_ok

        # 3. Manifest present
        manifest_present = "AndroidManifest.xml" in names
        result.checks["manifest_present"] = manifest_present

        # 4. Package ID correct
        pkg_ok = False
        try:
            apk = APK(str(apk_path))
            actual_pkg = apk.get_package()
            pkg_ok = actual_pkg == expected_package_id
            result.details["package_id"] = f"expected={expected_package_id} actual={actual_pkg}"
        except Exception as e:
            result.details["package_id"] = f"Could not re-parse APK: {e}"
        result.checks["package_id_correct"] = pkg_ok

        # 5. DEX present
        dex_present = any(n.startswith("classes") and n.endswith(".dex") for n in names)
        result.checks["dex_present"] = dex_present

        # 6. Resources present (resources.arsc is standard, but some minimal
        # apps may lack it - only fail this check if res/ entries exist but
        # resources.arsc doesn't)
        has_res_dir_entries = any(n.startswith("res/") for n in names)
        has_arsc = "resources.arsc" in names
        result.checks["resources_valid"] = (not has_res_dir_entries) or has_arsc

        # 7. Alignment
        aligned = self.aligner.verify(apk_path)
        result.checks["alignment"] = aligned

        # 8. Signature
        sig_ok, sig_detail = self.signer.verify(apk_path)
        result.checks["signature_valid"] = sig_ok
        result.details["signature"] = sig_detail[-500:]

        return result
