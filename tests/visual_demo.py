"""
tests.visual_demo — VISUAL demonstration driver of the demo application.

Runs the REAL demo flow end-to-end on the real machine (full protection
stack active — no SC_DEV), capturing a screenshot of every stage:

    01_activation_dialog.png — first launch: machine fingerprint + serial box
    02_licensed_main.png     — activated: SecureNotepad + license badge
    03_expired_error.png     — "a year later": expiry error screen
    04_wrong_machine.png     — serial bound to another computer (rejected)

The vendor side (serial issuance with the shipped demo keypair) is done in
the same run, exactly as the protector would do it — everything logged to
the console. After the run the machine is left VALIDLY LICENSED, so the user
can re-run `python -m target_demo.main` and go straight into the notepad.
"""

from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

OUT = _REPO / "demo-run"
OUT.mkdir(exist_ok=True)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def log(msg: str) -> None:
    print(msg, flush=True)


from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication([])
app.setApplicationName("SecureNotepad")
app.setOrganizationName("SecureCode")

# ---------------------------------------------------------------------------
# 1) protection bootstrap — anti-debug watchdog + self-integrity LIVE
# ---------------------------------------------------------------------------
from target_demo.protection import (  # noqa: E402
    DEMO_PRODUCT_ID,
    LicenseClient,
    ProtectionConfig,
    ProtectionRuntime,
)
from target_demo.protection.fingerprint import machine_code  # noqa: E402

config = ProtectionConfig(
    product_id=DEMO_PRODUCT_ID,
    product_name="SecureNotepad",
    company_name="SecureCode",
)
runtime = ProtectionRuntime.bootstrap(config)
log("[1/7] بوت‌استرپ پروتکشن — آنتی-دیباگ + چک یکپارچگی فعال شد (حالت واقعی، بدون SC_DEV)")

# ---------------------------------------------------------------------------
# 2) first launch state → activation dialog
# ---------------------------------------------------------------------------
client = LicenseClient(config, clock_guard=runtime.clock_guard)
code = machine_code()
log(f"[2/7] کد اثر انگشت این ماشین (fingerprint): {code}")

from target_demo.ui.activation_dialog import ActivationDialog  # noqa: E402

dialog = ActivationDialog(client)
dialog.show()
app.processEvents()
dialog.grab().save(str(OUT / "01_activation_dialog.png"), "PNG")
log("[3/7] پنجره فعال‌سازی ثبت شد — شامل کد اثر انگشت ماشین + فیلد سریال")

# ---------------------------------------------------------------------------
# 3) vendor side: issue a real 1-year serial with the shipped demo keypair
#    (this is exactly what the protector GUI does — no shortcuts)
# ---------------------------------------------------------------------------
from protector.core.crypto_engine import sign_blob, unwrap_container  # noqa: E402
from protector.core.serial_factory import (  # noqa: E402
    SerialRequest,
    issue_serial,
    verify_serial,
)

demo = unwrap_container(
    "demo-demo-demo", (_REPO / "demo-assets" / "demo_keypair.sec").read_bytes())
seed = base64.b64decode(demo["private_key"])
pub = base64.b64decode(demo["public_key"])

request = SerialRequest(
    customer="استودیو پارس (مشتری دمو)",
    fingerprint=code,
    product_id=DEMO_PRODUCT_ID,
    duration_days=365,
    feature_flags={"core": True, "pro_module": True},
    tolerance=1,
    rollback_allowance=3,
)
issued = issue_serial(request, lambda msg: sign_blob(seed, msg))
payload = verify_serial(issued.serial, pub)  # admin-side re-verification
log(f"[4/7] سمت فروشنده: سریال ۱ ساله صادر و امضا شد — nonce: {payload.nonce[:8]}…")
log("      سریال (همین را به مشتری می‌دهید):")
for i in range(0, len(issued.serial), 110):
    log("        " + issued.serial[i:i + 110])

# ---------------------------------------------------------------------------
# 4) activate through the dialog itself (same handler as the button click)
# ---------------------------------------------------------------------------
dialog.serial_edit.setPlainText(issued.serial)
dialog._activate()
if not dialog.activated:
    log("!! فعال‌سازی ناموفق بود: " + dialog.status_label.text())
    sys.stdout.flush()
    os._exit(1)
log("[5/7] مشتری سریال را پیست کرد و Activate زد — فعال‌سازی موفق ✓")

# ---------------------------------------------------------------------------
# 5) main window with license badge
# ---------------------------------------------------------------------------
from target_demo.ui.main_window import SecureNotepadWindow  # noqa: E402

status = client.verify_installed()
window = SecureNotepadWindow(client, status.payload)
window.show()
window.editor.setPlainText(
    "این متن فقط با سریال معتبر اجرا می‌شود.\n\n"
    "• قفل سخت‌افزاری: سریال فقط روی همین ماشین کار می‌کند\n"
    "• محدودیت زمانی: ۱ سال از تاریخ صدور\n"
    "• ۱۰۰٪ آفلاین: هیچ اتصال شبکه‌ای برای لایسنس انجام نمی‌شود")
app.processEvents()
window.grab().save(str(OUT / "02_licensed_main.png"), "PNG")
log("[6/7] پنجره اصلی با بج «Licensed to …» در نوار وضعیت ثبت شد")

# ---------------------------------------------------------------------------
# 6) "one year later": expired license → professional error screen
# ---------------------------------------------------------------------------
# NOTE: verify_installed() re-verifies the SIGNATURE of the stored serial on
# every launch, so editing the stored payload would prove nothing. The honest
# simulation is a serial that was really SIGNED ~400 days ago and expired
# two days ago — built here exactly like the protector would have issued it
# back then (same key, same format, past timestamps).
# ---------------------------------------------------------------------------
from shared.codec import encode_envelope  # noqa: E402
from shared.payload_schema import LicensePayload  # noqa: E402
from target_demo.protection.license_client import _LicenseFile  # noqa: E402
from target_demo.ui.license_error import LicenseErrorDialog  # noqa: E402

now = int(time.time())
expired_payload = LicensePayload(
    fingerprint=code,
    product_id=DEMO_PRODUCT_ID,
    issued_at=now - 400 * 86400,   # signed 400 days ago
    expires_at=now - 2 * 86400,   # expired two days ago
    customer=payload.customer,
    nonce=payload.nonce,
    feature_flags={"core": True},
)
expired_body = expired_payload.canonical_bytes()
expired_serial = encode_envelope(expired_body, sign_blob(seed, expired_body))
client._write_license_file(_LicenseFile(
    serial=expired_serial.replace("-", ""),
    payload=expired_payload.to_dict(),
    activated_at=now - 400 * 86400,
    last_seen=now - 2 * 86400,
    rollbacks=0,
    machine_code=code,
))
expired_status = client.verify_installed()
assert expired_status.state.value == "expired", expired_status.state
error_dialog = LicenseErrorDialog(expired_status, code)
error_dialog.show()
app.processEvents()
error_dialog.grab().save(str(OUT / "03_expired_error.png"), "PNG")
log("[6b] شبیه‌سازی «یک سال بعد» → صفحه خطای حرفه‌ای انقضای لایسنس ثبت شد")

# ---------------------------------------------------------------------------
# 7) a serial bound to ANOTHER machine is refused
# ---------------------------------------------------------------------------
wrong_request = SerialRequest(
    customer="مشتری دیگر",
    fingerprint="AABB-CCDD-EEFF-2345",  # some other machine's code (valid Base32 form)
    product_id=DEMO_PRODUCT_ID,
    duration_days=365,
)
wrong = issue_serial(wrong_request, lambda msg: sign_blob(seed, msg))
refused = client.activate(wrong.serial)
log(f"[6c] سریالِ مخصوص ماشین دیگر: رد شد؟ {'بله ✓' if not refused.ok else 'خیر!!'} "
    f"(پیام: {refused.message})")

# ---------------------------------------------------------------------------
# restore the valid license so the user can play with the demo afterwards
# ---------------------------------------------------------------------------
client.activate(issued.serial)
final = client.verify_installed()
log(f"[7/7] لایسنس معتبر بازگردانده شد — وضعیت نهایی: {final.state.value} "
    f"(روز باقی‌مانده: {max(0, final.seconds_left // 86400)})")
log(f"اسکرین‌شات‌ها در: {OUT}")
log("برای اجرای بعدی خود برنامه:  python -m target_demo.main")

sys.stdout.flush()
os._exit(0)
