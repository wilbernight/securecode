"""
tests.e2e_licensing — OFFLINE end-to-end test of the full licensing stack.

Simulates, with NO network and NO GUI, the complete customer lifecycle using
the shipped DEMO keypair (demo-assets/demo_keypair.sec, which matches the
public key embedded in target_demo/protection/pubkey_blob.py):

    1. vendor side: parse a machine code, issue a signed serial
       (protector core) and store it in the encrypted DB
    2. client side: FINGERPRINT the real machine, ACTIVATE with the serial,
       VERIFY on launch (signature, machine binding, expiry, clock)
    3. negative tests: wrong machine / tampered serial / wrong product
    4. clock-rollback simulation and rollback-exceeded block
    5. blacklist revocation + signed transfer-permit deactivation
    6. DB backup/restore round-trip

All state (keystore/db/license/reg-stores) is redirected into a TEMP
sandbox; the only real-machine touch is the hardware fingerprint itself
plus one HKCU registry value which is cleaned up at the end.

Run from the repo root:
    python -m tests.e2e_licensing
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    """Tiny assert-with-bookkeeping."""
    global PASS, FAIL
    mark = "✅" if condition else "⛔"
    print(f"  {mark} {name}" + (f" — {detail}" if detail and not condition else ""))
    if condition:
        PASS += 1
    else:
        FAIL += 1


class Sandbox:
    """Redirects every state location (env vars) into a temp dir."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="securecode-e2e-"))
        for name in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA"):
            setattr(self, name, os.environ.get(name))
            os.environ[name] = str(self.root / name)
            (self.root / name).mkdir(exist_ok=True)

    def cleanup(self) -> None:
        for name in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA"):
            if getattr(self, name, None):
                os.environ[name] = getattr(self, name)
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)
        # Remove the HKCU clock-store value this test may have created.
        try:
            import winreg  # Windows only; absent on macOS/Linux
        except ImportError:
            return
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\SecureCode\SecureNotepad", 0,
                                winreg.KEY_ALL_ACCESS) as key:
                try:
                    winreg.DeleteValue(key, "SessionStore")
                except OSError:
                    pass
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                             r"Software\SecureCode\SecureNotepad")
        except OSError:
            pass


def main() -> int:
    global PASS, FAIL
    # Windows consoles often default to legacy code pages — keep emoji output
    # safe regardless of the terminal.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print("SecureCode — end-to-end licensing test (fully offline)\n" + "=" * 60)

    # Delay heavy imports until the sandbox env is not yet active but PATH
    # is fine (imports below read env only at call time).
    from protector.core.crypto_engine import KeyStore, unwrap_container, sign_blob
    from protector.core.serial_factory import (
        SerialRequest,
        build_blacklist,
        build_transfer_permit,
        issue_serial,
        verify_serial,
    )
    from protector.core.db import LicenseDB
    from protector.core.fingerprint import parse_fingerprint
    from target_demo.protection import (
        DEMO_PRODUCT_ID,
        LicenseClient,
        LicenseState,
        ProtectionConfig,
    )
    from target_demo.protection.crypto_utils import derive_machine_key
    from target_demo.protection.fingerprint import machine_code, matches
    from shared.exceptions import SignatureError, SerialFormatError

    sandbox = Sandbox()
    try:
        # ------------------------------------------------------------------
        # 0) the shipped demo keypair (matches the embedded public key)
        # ------------------------------------------------------------------
        demo_blob = (_REPO_ROOT / "demo-assets" / "demo_keypair.sec").read_bytes()
        demo = unwrap_container("demo-demo-demo", demo_blob)
        check("demo keypair unwraps", demo.get("format") == "securecode-keyexport")
        import base64

        seed = base64.b64decode(demo["private_key"])
        pub = base64.b64decode(demo["public_key"])
        signer = lambda msg: sign_blob(seed, msg)  # noqa: E731

        config = ProtectionConfig(product_id=DEMO_PRODUCT_ID,
                                  product_name="SecureNotepad",
                                  company_name="SecureCode")

        # ------------------------------------------------------------------
        # 1) hardware fingerprint (real machine)
        # ------------------------------------------------------------------
        print("\n[1] hardware fingerprint")
        code = machine_code()
        info = parse_fingerprint(code)
        check("machine code format", len(code) == 19 and code.count("-") == 3,
              f"got {code!r}")
        check("code parses (components recorded)", len(info.present_names) >= 1,
              str(info.present_names))
        check("code is self-matching", matches(code, tolerance=1))

        # ------------------------------------------------------------------
        # 2) vendor issues serial + stores in encrypted DB
        # ------------------------------------------------------------------
        print("\n[2] serial issuance (vendor side)")
        request = SerialRequest(
            customer="E2E Test Corp",
            fingerprint=code,
            product_id=DEMO_PRODUCT_ID,
            duration_days=365,
            feature_flags={"core": True, "pro_module": False},
            tolerance=1,
            rollback_allowance=1,
        )
        issued = issue_serial(request, signer)
        payload = verify_serial(issued.serial, pub)
        check("serial signature verifies (admin side)",
              payload.customer == "E2E Test Corp")
        check("serial is compact", len(issued.serial) < 900,
              f"{len(issued.serial)} chars")

        db = LicenseDB(sandbox.root / "licenses.db", os.urandom(32))
        record_id = db.add_serial(issued.serial, issued.payload, "e2e note")
        stored = db.get_record(record_id)
        check("DB round-trip (encrypted fields decrypt)",
              stored is not None and stored.serial == issued.serial
              and stored.customer == "E2E Test Corp" and stored.notes == "e2e note")
        check("DB status is active", stored.status == "active")
        check("DB fingerprint filter", db.list_records(search="e2e test"))
        hist = db.monthly_histogram(12)
        check("monthly histogram counts the issue",
              hist[-1][1] == 1 or sum(v for _, v in hist) == 1, str(hist[-3:]))

        # ------------------------------------------------------------------
        # 3) client activates on THIS machine
        # ------------------------------------------------------------------
        print("\n[3] activation (client side)")
        client = LicenseClient(config)
        result = client.activate(issued.serial)
        check("activation succeeds", result.ok, result.message)
        status = client.verify_installed()
        check("launch verification passes", status.state is LicenseState.VALID,
              status.message)
        check("payload carries feature flags",
              status.payload is not None
              and status.payload.feature_flags == {"core": True, "pro_module": False})

        # ------------------------------------------------------------------
        # 4) negative tests
        # ------------------------------------------------------------------
        print("\n[4] negative tests")
        tampered = issued.serial[:-6] + ("AAAAAA" if not issued.serial.endswith("AAAAAA") else "BBBBBB")
        bad = client.activate(tampered)
        check("tampered serial rejected", not bad.ok
              and bad.state is LicenseState.INVALID)

        # A serial for a DIFFERENT machine: fake fingerprint (flip a char).
        wrong_fp = list(code)
        wrong_fp[0] = "A" if wrong_fp[0] != "A" else "B"
        wrong_req = SerialRequest(customer="x", fingerprint="".join(wrong_fp),
                                  product_id=DEMO_PRODUCT_ID, duration_days=30)
        wrong = issue_serial(wrong_req, signer)
        bad2 = client.activate(wrong.serial)
        # NOTE: activation replaces the installed license only on success,
        # so the good license from step 3 remains installed.
        check("other-machine serial rejected", not bad2.ok
              and bad2.state is LicenseState.WRONG_MACHINE)

        other_product = SerialRequest(customer="x", fingerprint=code,
                                      product_id=str(uuid.uuid4()), duration_days=30)
        bad3 = client.activate(issue_serial(other_product, signer).serial)
        check("foreign-product serial rejected", not bad3.ok
              and bad3.state is LicenseState.INVALID)

        # After failed activations the GOOD license still verifies.
        check("installed license unaffected by failed attempts",
              client.verify_installed().state is LicenseState.VALID)

        # ------------------------------------------------------------------
        # 5) clock rollback
        # ------------------------------------------------------------------
        print("\n[5] clock-rollback guard")
        # Simulate a rollback by writing a FUTURE last_seen into the license
        # file's encrypted store through the guard itself.
        guard = client._clock_guard()  # method resolves/creates the instance
        my_code = client.machine_code()
        # 3 days in the future -> now appears 3 days behind: one event.
        guard._write_registry(my_code, int(time.time()) + 3 * 86400, 0)
        guard._write_decoy_file(my_code, int(time.time()) + 3 * 86400, 0)
        status = client.verify_installed()
        check("first rollback tolerated (grace)",
              status.state is LicenseState.VALID, status.message)
        # Second rollback while allowance = 1 -> blocked.
        guard._write_registry(my_code, int(time.time()) + 5 * 86400, 1)
        guard._write_decoy_file(my_code, int(time.time()) + 5 * 86400, 1)
        status = client.verify_installed()
        check("rollback beyond allowance blocks",
              status.state is LicenseState.CLOCK_TAMPERED, status.message)

        # ------------------------------------------------------------------
        # 6) reactivation, revocation blacklist
        # ------------------------------------------------------------------
        print("\n[6] revocation + blacklist")
        # Fresh activation (clock tampering needs reactivation).
        config.license_path().unlink(missing_ok=True)
        result = client.activate(issued.serial)
        check("re-activation after reset", result.ok, result.message)

        # Corrupted blacklist is ignored (never bricks the app).
        config.blacklist_path().write_text("GARBAGE-NOT-A-VALID-ENVELOPE",
                                           encoding="utf-8")
        status = client.verify_installed()
        check("corrupt blacklist ignored", status.state is LicenseState.VALID)

        # Revocation uses a second serial so `issued` stays usable for [7].
        doomed = issue_serial(SerialRequest(
            customer="E2E revoked", fingerprint=code, product_id=DEMO_PRODUCT_ID,
            duration_days=30), signer)
        result = client.activate(doomed.serial)
        check("second serial activates", result.ok, result.message)
        blacklist_text = build_blacklist([doomed.payload.nonce], signer)
        config.blacklist_path().write_text(blacklist_text, encoding="utf-8")
        status = client.verify_installed()
        check("blacklisted serial blocked",
              status.state is LicenseState.REVOKED, status.message)

        # Sticky: deleting/corrupting the blacklist must NOT un-revoke.
        config.blacklist_path().unlink(missing_ok=True)
        status = client.verify_installed()
        check("revocation survives blacklist deletion",
              status.state is LicenseState.REVOKED, status.message)
        config.blacklist_path().write_text("GARBAGE-NOT-A-VALID-ENVELOPE",
                                           encoding="utf-8")
        status = client.verify_installed()
        check("revocation survives corrupt blacklist",
              status.state is LicenseState.REVOKED, status.message)
        config.blacklist_path().unlink(missing_ok=True)

        # Wiping license.dat and re-activating the revoked serial is refused.
        config.license_path().unlink(missing_ok=True)
        result = client.activate(doomed.serial)
        check("revoked serial cannot be re-activated",
              not result.ok and result.state is LicenseState.REVOKED,
              result.message)

        # A different, non-revoked serial still activates normally.
        result = client.activate(issued.serial)
        check("non-revoked serial activates after a revocation", result.ok,
              result.message)
        status = client.verify_installed()
        check("non-revoked serial valid", status.state is LicenseState.VALID,
              status.message)

        # ------------------------------------------------------------------
        # 7) machine transfer (deactivation request -> permit)
        # ------------------------------------------------------------------
        print("\n[7] machine transfer")
        config.blacklist_path().unlink(missing_ok=True)
        request_file = sandbox.root / "deactivation_request.json"
        client.make_deactivation_request(request_file)
        import json

        request_data = json.loads(request_file.read_text(encoding="utf-8"))
        check("deactivation request carries the signed serial",
              request_data["nonce"] == issued.payload.nonce)

        permit = build_transfer_permit(issued.payload.nonce, code, signer,
                                       note="e2e transfer")
        permit_file = sandbox.root / "transfer_permit.sec"
        permit_file.write_text(permit, encoding="utf-8")
        ok, message = client.deactivate_with_permit(permit_file)
        check("permit deactivates the old machine", ok, message)
        check("license removed after deactivation",
              client.verify_installed().state is LicenseState.MISSING)
        wrong_permit = build_transfer_permit("deadbeef" * 4, code, signer)
        (sandbox.root / "wrong_permit.sec").write_text(wrong_permit, encoding="utf-8")
        ok2, _ = client.deactivate_with_permit(sandbox.root / "wrong_permit.sec")
        check("permit for another serial refused", not ok2)

        # ------------------------------------------------------------------
        # 8) DB backup / restore
        # ------------------------------------------------------------------
        print("\n[8] encrypted backup/restore")
        backup_path = sandbox.root / "backup.sec"
        db.backup(backup_path, "backup-passphrase-123")
        db2 = LicenseDB(sandbox.root / "licenses2.db", os.urandom(32))
        imported = db2.restore(backup_path, "backup-passphrase-123")
        check("backup restores all records", imported == 1, f"{imported} imported")
        restored = db2.get_record(db2.list_records()[0].id)
        check("restored serial matches", restored.serial == issued.serial)

        # ------------------------------------------------------------------
        print("\n" + "=" * 60)
        print(f"RESULT: {PASS} passed, {FAIL} failed")
        return 1 if FAIL else 0
    finally:
        sandbox.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
