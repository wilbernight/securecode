"""
protector.core — non-Qt core of the protector application.

Modules:
    crypto_engine  — Ed25519 + AES-256-GCM + passphrase-wrapped keystore
    serial_factory — serial issuance / verification / blacklist / permits
    fingerprint    — parse machine codes and fingerprint export files (admin side)
    db             — encrypted SQLite license store
    settings       — encrypted application settings

No module in this package may import PySide6 (keeps core testable headless).
"""

from __future__ import annotations
