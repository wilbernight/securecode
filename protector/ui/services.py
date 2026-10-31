"""
protector.ui.services — the dependency container shared by all pages.

Instead of module-level singletons (which make testing and lifecycle
management painful), every page receives a Services instance holding the
unlocked keystore, the DB, settings, the theme manager and small utilities
(toasts, navigation). The ShellWindow owns it and closes it on exit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from PySide6.QtWidgets import QApplication

from ..core.crypto_engine import KeyStore
from ..core.db import LicenseDB
from ..core.settings import AppSettings
from .theme import ThemeManager


@dataclass  # intentionally NO slots: the shell attaches a refresh hook
class Services:
    """Everything a page needs; constructed once after keystore unlock."""

    app: QApplication
    keystore: KeyStore
    db: LicenseDB
    settings: AppSettings
    theme: ThemeManager
    toast: object = field(default=None)          # set by ShellWindow (ToastManager)
    navigate: Callable[[str], None] = field(default=lambda page: None)
    prefill_generate: Callable[..., None] = field(
        default=lambda fp, customer, platform="windows": None)
    # (fingerprint, customer, platform="windows") — platform comes from the
    # fingerprint export file / Reader page and only drives display labels.
    refresh_hook: Callable[[], None] | None = field(default=None)
    set_language: Callable[[str], None] = field(default=lambda code: None)
    window: object = field(default=None)                 # the live ShellWindow

    def refresh_all(self) -> None:
        """Ask the shell to refresh visible data pages (no-op before start)."""
        if self.refresh_hook is not None:
            self.refresh_hook()
