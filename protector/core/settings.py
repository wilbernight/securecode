"""
protector.core.settings — encrypted application settings for the protector.

A single JSON document, AES-256-GCM encrypted with the keystore's DB master
key, stored next to the keystore. Holds:
    * theme (dark/light) + accent color
    * product catalog (name / UUID / version) — used by the Generate page
    * issuance defaults (duration, tolerance, rollback allowance)
    * window geometry (restored on start)
    * misc operational paths (last backup dir)

No secrets live here (keystore holds those); still encrypted because the
customer catalog itself is business data worth protecting.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .crypto_engine import aes_gcm_decrypt, aes_gcm_encrypt

log = logging.getLogger("protector.settings")

#: Preloaded product catalog entry for the demo (matches the demo build).
DEMO_PRODUCT = {
    "name": "SecureNotepad (demo)",
    "id": "7e9a6cec-c185-45bb-a2fb-d31e96484f7e",
    "version": "1.0.0",
}

_DEFAULTS: dict[str, Any] = {
    "theme": "light",
    "accent": "#2563EB",
    "language": "en",
    "products": [DEMO_PRODUCT],
    "default_product_id": DEMO_PRODUCT["id"],
    "default_duration_days": 365,
    "default_tolerance": 1,
    "default_rollback": 3,
    "default_feature_flags": {"core": True, "pro_module": True},
    "last_backup_dir": "",
    "window_geometry": None,
    "created_at": 0,
}


class SettingsError(Exception):
    """Settings file unreadable or wrong key."""


class AppSettings:
    """Typed access + autosave wrapper around the encrypted settings file."""

    def __init__(self, path: Path, key: bytes) -> None:
        if len(key) != 32:
            raise SettingsError("settings key must be 32 bytes")
        self._path = Path(path)
        self._key = key
        self._data: dict[str, Any] = dict(_DEFAULTS)
        self._load()

    # -------------------------------------------------- persistence
    def _load(self) -> None:
        if not self._path.is_file():
            self._data = dict(_DEFAULTS)
            self._data["created_at"] = int(time.time())
            self._save()
            return
        try:
            blob = self._path.read_bytes()
            plain = aes_gcm_decrypt(self._key, blob)
            loaded = json.loads(plain.decode("utf-8"))
            if not isinstance(loaded, dict):
                raise SettingsError("settings payload is not an object")
            self._data = dict(_DEFAULTS)
            self._data.update(loaded)
        except Exception as exc:
            # Encrypted with a key that no longer matches (e.g. a keystore
            # key import from before the "preserve DB master key" fix, or a
            # manual key rotation). Reset to defaults instead of bricking
            # the application — settings hold no irreplaceable data.
            log.warning("settings unreadable with the current master key "
                        "(%s) — resetting to defaults", type(exc).__name__)
            self._data = dict(_DEFAULTS)
            self._data["created_at"] = int(time.time())
            self._save()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        blob = aes_gcm_encrypt(self._key,
                               json.dumps(self._data, indent=2).encode("utf-8"))
        tmp = self._path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(self._path)

    # -------------------------------------------------- generic access
    def get(self, key: str, default: Any = None) -> Any:
        """Read a setting (returns default when missing)."""
        return self._data.get(key, _DEFAULTS.get(key, default))

    def set(self, key: str, value: Any, *, save: bool = True) -> None:
        """Write a setting and (by default) persist immediately."""
        self._data[key] = value
        if save:
            self._save()

    # -------------------------------------------------- typed helpers
    @property
    def theme(self) -> str:
        return str(self.get("theme", "light"))

    @theme.setter
    def theme(self, value: str) -> None:
        if value not in ("dark", "light"):
            raise ValueError("theme must be 'dark' or 'light'")
        self.set("theme", value)

    @property
    def accent(self) -> str:
        return str(self.get("accent", "#2563EB"))

    @accent.setter
    def accent(self, value: str) -> None:
        if not (isinstance(value, str) and value.startswith("#")
                and len(value) == 7):
            raise ValueError("accent must be a #RRGGBB hex string")
        self.set("accent", value)

    @property
    def language(self) -> str:
        return "fa" if self.get("language", "en") == "fa" else "en"

    @language.setter
    def language(self, value: str) -> None:
        if value not in ("en", "fa"):
            raise ValueError("language must be 'en' or 'fa'")
        self.set("language", value)

    # --- products ---------------------------------------------------------
    def products(self) -> list[dict[str, str]]:
        """The product catalog: [{name, id, version}, ...]."""
        products = self.get("products", [])
        return [dict(p) for p in products if isinstance(p, dict) and "id" in p]

    def add_product(self, name: str, product_id: str, version: str) -> dict:
        """Add a product to the catalog (id must be a UUID)."""
        import uuid
        uuid.UUID(str(product_id))  # raises ValueError if invalid
        products = self.products()
        entry = {"name": name, "id": str(product_id), "version": version}
        products.append(entry)
        self.set("products", products)
        log.info("product added: %s (%s)", name, product_id)
        return entry

    def remove_product(self, product_id: str) -> None:
        """Remove a product from the catalog."""
        products = [p for p in self.products() if p["id"] != str(product_id)]
        self.set("products", products)
        if self.get("default_product_id") == product_id and products:
            self.set("default_product_id", products[0]["id"])

    # --- window geometry ----------------------------------------------------
    def save_geometry(self, geometry: str) -> None:
        """Persist window geometry (base64 from QWidget.saveGeometry())."""
        self.set("window_geometry", geometry)

    def load_geometry(self) -> str | None:
        return self.get("window_geometry") or None


__all__ = ["AppSettings", "DEMO_PRODUCT", "SettingsError"]
