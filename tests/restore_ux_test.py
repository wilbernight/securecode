"""Verify the restore-failure UX strings + DB-level restore behavior.

Checks:
  1. The three new toast strings exist in the FA translation table with
     keys exactly matching the strings built in settings_page._restore.
  2. Wrong passphrase still raises WrongPassphraseError at DB level (the UI
     layer now converts it to the clear bilingual message).
  3. A correct-passphrase backup/restore round trip still imports records.
Run from the repository root:  python tests/restore_ux_test.py
"""

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

root = tempfile.mkdtemp(prefix="restore-ux-")

from protector.core.crypto_engine import (  # noqa: E402
    KeyStore,
    WrongPassphraseError,
)
from protector.core.db import LicenseDB  # noqa: E402
from protector.ui import i18n  # noqa: E402
from shared.payload_schema import LicensePayload  # noqa: E402

i18n.set_language("fa")

# 1) the three new strings translate (exact key match with settings_page)
keys = [
    "Wrong backup passphrase — this is the passphrase you chose when "
    "CREATING the backup, not the keystore passphrase.",
    "This file is not a valid SecureCode backup.",
    "No new records — this backup's records are already in the database.",
]
for key in keys:
    value = i18n.tr(key)
    assert value != key, "missing translation for: " + key[:50]
    print("fa:", (value[:60] + "…") if len(value) > 60 else value)

# 2) db-level behavior unchanged: wrong pass -> WrongPassphraseError
ks = KeyStore(os.path.join(root, "k.dat"))
ks.create("pass-12345678")
db = LicenseDB(os.path.join(root, "l.db"), ks.db_master)
bak = os.path.join(root, "b.sec")
db.backup(bak, "backup-pass-12345")
try:
    db.restore(bak, "wrong-pass")
    raise AssertionError("wrong passphrase did not raise")
except WrongPassphraseError:
    print("wrong pass -> WrongPassphraseError (UI converts to clear message)")

# 3) correct-pass round trip still green
lp = LicensePayload(
    fingerprint="AABBCCDD-EEFF-1122", product_id="p1",
    issued_at=int(time.time()), expires_at=int(time.time()) + 86400,
    customer="X", nonce="n-1", feature_flags={"core": True},
    tolerance=1, rollback_allowance=3,
)
db.add_serial("S-1", lp, "", {"core": True})
bak2 = os.path.join(root, "b2.sec")
db.backup(bak2, "ok-pass-12345")
db3 = LicenseDB(os.path.join(root, "l3.db"), ks.db_master)
n = db3.restore(bak2, "ok-pass-12345")
assert n == 1, f"round trip imported {n} != 1"
print("correct-pass restore: 1 record — round trip OK")

ks.close()
print("restore UX strings: PASS")
sys.stdout.flush()
os._exit(0)
