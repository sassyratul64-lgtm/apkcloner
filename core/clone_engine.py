"""
core/clone_engine.py

Orchestrates the full Detect -> Analyze -> Configure -> Clone -> Modify ->
Rebuild -> Align -> Sign -> Verify -> Save pipeline. A clone is only ever
reported successful if ApkValidator.validate(...) says so.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from core.analyzer import ApkAnalyzer, ApkProfile, AnalysisError
from core.builder import ApkBuilder, BuildError
from core.aligner import ApkAligner, AlignError
from core.signer import ApkSigner, SignError
from core.validator import ApkValidator, ValidationResult
from core.modifier import ApkModifier, CloneConfig, ModificationReport
from security.keystore import KeystoreManager, KeystoreHandle
from storage.workspace import Workspace

MAX_REPAIR_ATTEMPTS = 3


@dataclass
class CloneResult:
    success: bool = False
    stage_failed: str | None = None
    reason: str = ""
    output_apk: Path | None = None
    profile: Optional[ApkProfile] = None
    modification_report: Optional[ModificationReport] = None
    validation: Optional[ValidationResult] = None
    log_lines: list[str] = field(default_factory=list)
    original_untouched: bool = True
    repair_attempts: int = 0


class CloneEngine:
    def __init__(self, log_fn: Callable[[str], None] | None = None):
        self.analyzer = ApkAnalyzer()
        self.builder = ApkBuilder()
        self.aligner = ApkAligner()
        self.signer = ApkSigner()
        self.keystore_mgr = KeystoreManager()
        self.validator = ApkValidator(self.aligner, self.signer)
        self.log_fn = log_fn or (lambda msg: None)
        self._log_lines: list[str] = []

    def _log(self, msg: str):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        self._log_lines.append(line)
        self.log_fn(line)

    def run(
        self,
        source_apk: Path,
        config: CloneConfig,
        destination_dir: Path,
        output_name: str,
        keystore: KeystoreHandle | None = None,
    ) -> CloneResult:
        result = CloneResult()
        self._log_lines = []

        with Workspace() as ws:
            try:
                ws.import_original(source_apk)
                self._log("APK copied into isolated workspace")

                profile = self.analyzer.analyze(ws.original_copy)
                result.profile = profile
                self._log(f"Analysis complete - cloneability: {profile.cloneability}")

                if profile.cloneability == "UNSUPPORTED":
                    result.stage_failed = "analysis"
                    result.reason = "APK was assessed as UNSUPPORTED for cloning."
                    return result

                decoded_dir = ws.decode_dir
                self.builder.decode(ws.original_copy, decoded_dir)
                self._log("APK decoded (apktool)")

                modifier = ApkModifier(decoded_dir)
                mod_report = modifier.apply(config)
                result.modification_report = mod_report
                for line in mod_report.applied:
                    self._log(f"Modification applied: {line}")
                for line in mod_report.skipped_unsupported:
                    self._log(f"Modification skipped (unsupported): {line}")

                unsigned_apk = ws.root / "build" / "unsigned.apk"
                unsigned_apk = self._build_with_recovery(decoded_dir, unsigned_apk, result)
                self._log("APK rebuilt (apktool)")

                aligned_apk = ws.root / "build" / "aligned.apk"
                self.aligner.align(unsigned_apk, aligned_apk)
                self._log("APK aligned (zipalign)")

                if keystore is None:
                    ks_path = ws.root / "keystore" / "clone.jks"
                    keystore = self.keystore_mgr.generate_new_keystore(ks_path)
                    self._log("New signing keystore generated")
                else:
                    self._log("Using provided existing signing keystore")

                signed_apk = ws.root / "build" / "signed.apk"
                self.signer.sign(aligned_apk, signed_apk, keystore)
                self._log("APK signed (apksigner)")

                expected_pkg = config.new_package_id or profile.package_id
                validation = self.validator.validate(signed_apk, expected_pkg)
                result.validation = validation
                for check, ok in validation.checks.items():
                    self._log(f"Validation [{check}]: {'PASS' if ok else 'FAIL'}")

                if not validation.passed:
                    result.stage_failed = "validation"
                    result.reason = "One or more final validation checks failed."
                    return result

                destination_dir.mkdir(parents=True, exist_ok=True)
                final_path = destination_dir / f"{output_name}.apk"
                shutil.copy2(signed_apk, final_path)
                result.output_apk = final_path
                self._log(f"Final APK saved to {final_path}")

                result.original_untouched = ws.verify_original_untouched(source_apk)
                if not result.original_untouched:
                    # This should be structurally impossible given we only ever
                    # read source_apk, but we verify anyway and refuse to claim
                    # success if it somehow happened.
                    result.stage_failed = "integrity"
                    result.reason = "Original APK hash changed during cloning - aborting."
                    return result

                self._write_clone_info(destination_dir, source_apk, profile, config, mod_report, validation)

                result.success = True
                return result

            except AnalysisError as e:
                result.stage_failed = "analysis"
                result.reason = str(e)
                return result
            except BuildError as e:
                result.stage_failed = e.stage
                result.reason = str(e)
                return result
            except AlignError as e:
                result.stage_failed = "alignment"
                result.reason = str(e)
                return result
            except SignError as e:
                result.stage_failed = "signing"
                result.reason = str(e)
                return result
            except Exception as e:
                result.stage_failed = "unexpected"
                result.reason = f"{type(e).__name__}: {e}"
                return result
            finally:
                result.log_lines = list(self._log_lines)

    def _build_with_recovery(self, decoded_dir: Path, output_apk: Path, result: CloneResult) -> Path:
        last_error: BuildError | None = None
        for attempt in range(1, MAX_REPAIR_ATTEMPTS + 1):
            try:
                return self.builder.build(decoded_dir, output_apk)
            except BuildError as e:
                last_error = e
                result.repair_attempts = attempt
                self._log(f"Build failed (attempt {attempt}/{MAX_REPAIR_ATTEMPTS}): {e}")
                fixed = self._attempt_repair(decoded_dir, e)
                if not fixed:
                    self._log("No safe automatic repair available for this error.")
                    break
                self._log(f"Applied automatic repair, retrying build...")
        raise last_error

    @staticmethod
    def _attempt_repair(decoded_dir: Path, error: BuildError) -> bool:
        """Very conservative, safe repairs only. If nothing applicable is
        found, returns False rather than guessing - we do not want to mask
        real errors with blind retries."""
        text = error.raw_output.lower()

        # Common apktool issue: leftover build/ dirs from a previous attempt
        stale = decoded_dir / "build"
        if stale.is_dir() and ("build" in text or "already exists" in text):
            shutil.rmtree(stale, ignore_errors=True)
            return True

        # Common apktool issue: framework resource cache corruption
        if "framework" in text and ("aapt" in text or "resource" in text):
            framework_cache = Path.home() / ".local" / "share" / "apktool" / "framework"
            if framework_cache.is_dir():
                shutil.rmtree(framework_cache, ignore_errors=True)
                return True

        return False

    @staticmethod
    def _write_clone_info(destination_dir, source_apk, profile, config, mod_report, validation):
        info = {
            "tool_version": "1.0.0",
            "original_package_id": profile.package_id,
            "new_package_id": config.new_package_id or profile.package_id,
            "original_version": {"name": profile.version_name, "code": profile.version_code},
            "new_version": {
                "name": config.new_version_name or profile.version_name,
                "code": config.new_version_code or profile.version_code,
            },
            "clone_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "enabled_customizations": mod_report.applied,
            "skipped_customizations": mod_report.skipped_unsupported,
            "warnings": mod_report.warnings,
            "validation_status": {k: v for k, v in validation.checks.items()},
            "source_apk_filename": source_apk.name,
        }
        with open(destination_dir / "clone-info.json", "w") as f:
            json.dump(info, f, indent=2)
