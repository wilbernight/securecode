"""
protector.core.db — the encrypted local license store (SQLite).

Every customer-facing field that could be abused if the admin machine were
breached — the FULL serial text (which activates a machine!), the customer
name, notes — is stored as AES-256-GCM ciphertext (key: the DB master key
from the keystore; AAD binds each ciphertext to its row identity + column).

Plaintext columns are only non-secret, operational fields: fingerprint
code, product id, timestamps, status flags, nonce (needed for blacklist
export and lookups), serial hash (duplicate detection).

Schema (v1):
    serials(
      id, serial_hash UNIQUE, nonce UNIQUE, fingerprint_code, product_id,
      issued_at, expires_at, revoked, tolerance, rollback_allowance,
      flags_json, created_at, updated_at,
      customer_enc BLOB, notes_enc BLOB, serial_enc BLOB
    )

Status is COMPUTED (never stored stale): revoked > expired > expiring (<30d)
> active / lifetime.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .crypto_engine import aes_gcm_decrypt, aes_gcm_encrypt, wrap_container, unwrap_container

DB_SCHEMA_VERSION = 1
EXPIRING_SOON_DAYS = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS serials (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hash        TEXT NOT NULL UNIQUE,
    nonce              TEXT NOT NULL UNIQUE,
    fingerprint_code   TEXT NOT NULL,
    product_id         TEXT NOT NULL,
    issued_at          INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    revoked            INTEGER NOT NULL DEFAULT 0,
    tolerance          INTEGER NOT NULL DEFAULT 1,
    rollback_allowance INTEGER NOT NULL DEFAULT 3,
    flags_json         TEXT NOT NULL DEFAULT '{}',
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    customer_enc       BLOB NOT NULL,
    notes_enc          BLOB NOT NULL,
    serial_enc         BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_serials_expires ON serials(expires_at);
CREATE INDEX IF NOT EXISTS idx_serials_product ON serials(product_id);
"""


class DBError(Exception):
    """Raised on database structural problems (corruption, bad key)."""


# ---------------------------------------------------------------------------
# Row model
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class SerialRecord:
    """One decrypted serial row (as used by the GUI)."""

    id: int
    serial_hash: str
    nonce: str
    fingerprint_code: str
    product_id: str
    issued_at: int
    expires_at: int
    revoked: bool
    tolerance: int
    rollback_allowance: int
    flags: dict[str, bool]
    created_at: int
    updated_at: int
    customer: str
    notes: str
    serial: str  # full grouped serial text — SECRET, handle carefully

    # -------------------------------------------------- status computation
    @staticmethod
    def status_of(expires_at: int, revoked: bool, now: int | None = None) -> str:
        """Compute status: 'revoked' | 'expired' | 'expiring' | 'active' | 'lifetime'."""
        if revoked:
            return "revoked"
        now = int(now or time.time())
        if expires_at == 0:
            return "lifetime"
        if now >= expires_at:
            return "expired"
        if expires_at - now < EXPIRING_SOON_DAYS * 86400:
            return "expiring"
        return "active"

    @property
    def status(self) -> str:
        return self.status_of(self.expires_at, self.revoked)

    @property
    def days_left(self) -> int | None:
        """Days until expiry (None for lifetime)."""
        if self.expires_at == 0:
            return None
        return max(0, (self.expires_at - int(time.time())) // 86400)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
class LicenseDB:
    """Thread-safe encrypted SQLite license store.

    All public methods take/return FULLY DECRYPTED SerialRecord objects;
    encryption/decryption is invisible to callers and happens per row.
    """

    def __init__(self, path: Path, db_key: bytes) -> None:
        if len(db_key) != 32:
            raise DBError("DB master key must be 32 bytes")
        self._key = db_key
        self._lock = threading.RLock()
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    # -------------------------------------------------- crypto helpers
    def _enc(self, serial_hash: str, column: str, value: str) -> bytes:
        return aes_gcm_encrypt(self._key, value.encode("utf-8"),
                               aad=f"{serial_hash}:{column}".encode())

    def _dec(self, serial_hash: str, column: str, blob: bytes) -> str:
        return aes_gcm_decrypt(self._key, blob,
                               aad=f"{serial_hash}:{column}".encode()).decode("utf-8")

    @staticmethod
    def hash_serial(serial_flat: str) -> str:
        """Stable, non-secret index of a serial (dup detection + AAD basis)."""
        return hashlib.sha256(serial_flat.encode("ascii")).hexdigest()

    # -------------------------------------------------- row mapping
    def _to_record(self, row: sqlite3.Row) -> SerialRecord:
        serial_hash = row["serial_hash"]
        return SerialRecord(
            id=row["id"],
            serial_hash=serial_hash,
            nonce=row["nonce"],
            fingerprint_code=row["fingerprint_code"],
            product_id=row["product_id"],
            issued_at=row["issued_at"],
            expires_at=row["expires_at"],
            revoked=bool(row["revoked"]),
            tolerance=row["tolerance"],
            rollback_allowance=row["rollback_allowance"],
            flags=json.loads(row["flags_json"] or "{}"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            customer=self._dec(serial_hash, "customer", row["customer_enc"]),
            notes=self._dec(serial_hash, "notes", row["notes_enc"]),
            serial=self._dec(serial_hash, "serial", row["serial_enc"]),
        )

    # -------------------------------------------------- writes
    def add_serial(self, serial: str, payload, notes: str = "",
                   feature_flags: dict | None = None) -> int:
        """Store a freshly issued serial (payload = LicensePayload).

        Returns the new row id. Raises ValueError on duplicates.
        """
        flat = serial.replace("-", "")
        serial_hash = self.hash_serial(flat)
        now = int(time.time())
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO serials (
                       serial_hash, nonce, fingerprint_code, product_id,
                       issued_at, expires_at, revoked, tolerance,
                       rollback_allowance, flags_json, created_at, updated_at,
                       customer_enc, notes_enc, serial_enc)
                   VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?,?,?)""",
                (
                    serial_hash, payload.nonce, payload.fingerprint,
                    payload.product_id, payload.issued_at, payload.expires_at,
                    payload.tolerance, payload.rollback_allowance,
                    json.dumps(feature_flags or payload.feature_flags
                               or {}, sort_keys=True),
                    now, now,
                    self._enc(serial_hash, "customer", payload.customer),
                    self._enc(serial_hash, "notes", notes),
                    self._enc(serial_hash, "serial", serial),
                ),
            )
            return self._conn.execute(
                "SELECT last_insert_rowid()").fetchone()[0]

    def set_revoked(self, record_id: int, revoked: bool) -> None:
        """Flip the revocation flag (affects blacklist export)."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE serials SET revoked=?, updated_at=? WHERE id=?",
                (1 if revoked else 0, int(time.time()), record_id))

    def replace_serial(self, record_id: int, new_serial: str, payload,
                       notes: str | None = None) -> None:
        """Replace the serial of an existing record (extend/renew flow).

        Regenerates the encrypted fields because the AAD (serial hash)
        changes with the new key.
        """
        flat = new_serial.replace("-", "")
        serial_hash = self.hash_serial(flat)
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT id, serial_hash FROM serials WHERE id=?",
                (record_id,)).fetchone()
            if row is None:
                raise DBError(f"record {record_id} not found")
            old_notes = self._dec(row["serial_hash"], "notes",
                                  self._conn.execute(
                                      "SELECT notes_enc FROM serials WHERE id=?",
                                      (record_id,)).fetchone()[0])
            self._conn.execute(
                """UPDATE serials SET
                       serial_hash=?, nonce=?, fingerprint_code=?,
                       product_id=?, issued_at=?, expires_at=?, tolerance=?,
                       rollback_allowance=?, flags_json=?, updated_at=?,
                       customer_enc=?, notes_enc=?, serial_enc=?
                   WHERE id=?""",
                (
                    serial_hash, payload.nonce, payload.fingerprint,
                    payload.product_id, payload.issued_at, payload.expires_at,
                    payload.tolerance, payload.rollback_allowance,
                    json.dumps(payload.feature_flags or {}, sort_keys=True),
                    int(time.time()),
                    self._enc(serial_hash, "customer", payload.customer),
                    self._enc(serial_hash, "notes",
                             old_notes if notes is None else notes),
                    self._enc(serial_hash, "serial", new_serial),
                    record_id,
                ),
            )

    def update_notes(self, record_id: int, notes: str) -> None:
        """Update the notes column of a record."""
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT serial_hash FROM serials WHERE id=?",
                (record_id,)).fetchone()
            if row is None:
                raise DBError(f"record {record_id} not found")
            self._conn.execute(
                "UPDATE serials SET notes_enc=?, updated_at=? WHERE id=?",
                (self._enc(row["serial_hash"], "notes", notes),
                 int(time.time()), record_id))

    def delete_record(self, record_id: int) -> None:
        """Hard-delete a record (admin action, confirm in GUI)."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM serials WHERE id=?", (record_id,))

    # -------------------------------------------------- reads
    def get_record(self, record_id: int) -> SerialRecord | None:
        """Fetch one record (decrypted) or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM serials WHERE id=?", (record_id,)).fetchone()
        return self._to_record(row) if row else None

    def find_by_nonce(self, nonce: str) -> SerialRecord | None:
        """Fetch the record holding a nonce (blacklist workflow)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM serials WHERE nonce=?", (nonce,)).fetchone()
        return self._to_record(row) if row else None

    def list_records(self, search: str = "", status: str = "all",
                     product_id: str = "") -> list[SerialRecord]:
        """List records with GUI filters (search: customer/fingerprint/serial)."""
        now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM serials ORDER BY issued_at DESC").fetchall()
        records = [self._to_record(r) for r in rows]
        if search:
            needle = search.strip().lower()
            records = [r for r in records if needle in r.customer.lower()
                      or needle in r.fingerprint_code.lower()
                      or needle in r.serial.lower()]
        if product_id:
            records = [r for r in records if r.product_id == product_id]
        if status and status != "all":
            records = [r for r in records
                       if r.status == status
                       or (status == "active" and r.status == "lifetime")
                       or (status == "expiring" and r.status == "expiring")]
        return records

    def revocation_nonces(self) -> list[str]:
        """All nonces marked revoked (for blacklist generation)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT nonce FROM serials WHERE revoked=1 ORDER BY nonce"
            ).fetchall()
        return [r["nonce"] for r in rows]

    # -------------------------------------------------- dashboard stats
    def counts(self) -> dict[str, int]:
        """Status counters for the Dashboard cards."""
        now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                "SELECT expires_at, revoked FROM serials").fetchall()
        out = {"total": len(rows), "active": 0, "expiring": 0, "expired": 0,
               "revoked": 0, "lifetime": 0}
        for row in rows:
            status = SerialRecord.status_of(row["expires_at"], bool(row["revoked"]), now)
            out[status] = out.get(status, 0) + 1
        return out

    def monthly_histogram(self, months: int = 12) -> list[tuple[str, int]]:
        """Issued-per-month counts for the last N months: [(YYYY-MM, count)]."""
        from datetime import datetime, timezone

        with self._lock:
            rows = self._conn.execute(
                "SELECT issued_at FROM serials").fetchall()
        now = datetime.now(timezone.utc)
        # Build the list of month keys ending with the current month.
        year, month = now.year, now.month
        keys: list[str] = []
        for _ in range(months):
            keys.append(f"{year:04d}-{month:02d}")
            month -= 1
            if month == 0:
                month, year = 12, year - 1
        keys.reverse()
        buckets = {k: 0 for k in keys}
        for row in rows:
            key = datetime.fromtimestamp(row["issued_at"],
                                         tz=timezone.utc).strftime("%Y-%m")
            if key in buckets:
                buckets[key] += 1
        return [(k, buckets[k]) for k in keys]

    # -------------------------------------------------- backup / restore
    def backup(self, path: Path, passphrase: str) -> Path:
        """Full ENCRYPTED export (passphrase-wrapped container)."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM serials").fetchall()
        dump = []
        for row in rows:
            rec = self._to_record(row)
            dump.append({
                "serial": rec.serial, "nonce": rec.nonce,
                "fingerprint": rec.fingerprint_code, "product_id": rec.product_id,
                "issued_at": rec.issued_at, "expires_at": rec.expires_at,
                "revoked": rec.revoked, "tolerance": rec.tolerance,
                "rollback": rec.rollback_allowance, "flags": rec.flags,
                "created_at": rec.created_at,
                "customer": rec.customer, "notes": rec.notes,
            })
        container = {
            "format": "securecode-db-backup",
            "version": DB_SCHEMA_VERSION,
            "exported_at": int(time.time()),
            "records": dump,
        }
        Path(path).write_bytes(wrap_container(passphrase, container))
        return Path(path)

    def restore(self, path: Path, passphrase: str, *, replace: bool = True) -> int:
        """Import a backup. Returns number of imported records."""
        payload = unwrap_container(passphrase, Path(path).read_bytes())
        if payload.get("format") != "securecode-db-backup":
            raise DBError("not a SecureCode backup file")
        records = payload.get("records", [])
        imported = 0
        for item in records:
            from shared.payload_schema import LicensePayload
            lp = LicensePayload(
                fingerprint=item["fingerprint"], product_id=item["product_id"],
                issued_at=int(item["issued_at"]), expires_at=int(item["expires_at"]),
                customer=str(item.get("customer", "")), nonce=str(item["nonce"]),
                feature_flags=dict(item.get("flags") or {}),
                tolerance=int(item.get("tolerance", 1)),
                rollback_allowance=int(item.get("rollback", 3)),
            )
            try:
                self.add_serial(item["serial"], lp, str(item.get("notes", "")),
                               dict(item.get("flags") or {}))
                if item.get("revoked"):
                    self.set_revoked(
                        self.find_by_nonce(lp.nonce).id, True)  # type: ignore[union-attr]
                imported += 1
            except sqlite3.IntegrityError:
                continue  # duplicate — skip on restore
        return imported

    def close(self) -> None:
        """Close the connection (does NOT wipe the in-memory key copy)."""
        with self._lock:
            self._conn.close()


__all__ = ["DBError", "LicenseDB", "SerialRecord"]
