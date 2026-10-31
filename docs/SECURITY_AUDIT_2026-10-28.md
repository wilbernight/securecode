# SecureCode — Security & Robustness Audit

**Date:** 2026-10-28
**Scope:** crypto/licensing core of the SecureCode toolkit (protector admin
tool + the reusable Python client SDK in `target_demo/protection/` + the shared
wire-format layer). Mobile SDK ports (`sdks/`) were reviewed only at the
wire-format/contract level via the conformance vectors.
**Platform under test:** macOS 27 (Apple Silicon, arm64), Python 3.14, PySide6 6.12.

---

## 1. Executive summary

The cryptographic design is **sound** and matches what a serious offline
licensing product should look like:

- **Signing:** Ed25519 over canonical (sorted-key, compact, ASCII) JSON. The
  client re-verifies the signature of the stored serial on *every* launch, so a
  locally edited/forged license file never passes.
- **Key custody:** the Ed25519 **private** key exists only inside the
  protector's passphrase-wrapped keystore (AES-256-GCM, KEK via PBKDF2-HMAC-SHA256,
  600 000 iterations, 16-byte random salt). The client embeds only the public
  key, cross-checked against a SHA-256 digest (anti pubkey-swap).
- **Local artifacts:** license file, clock stores and DB secrets are encrypted
  with machine-bound keys (`HKDF-SHA256(master‖machine_code, salt=product_id,
  info=purpose)`), so copying a license to another PC fails AES-GCM auth before
  any license logic runs. The license DB encrypts each secret column with AES-GCM
  and binds it to `row_hash:column` via AAD.
- **Defense in depth:** anti-debug (ctypes-only), self-integrity (pubkey digest +
  module manifest + critical-constant digest), multi-store anti-clock-rollback,
  and `SecureBuffer` memory hygiene.

The honest, documented ceiling still holds: in **source** form the Python is
trivially patchable; the whole model's strength rests on the **Nuitka native
compilation + integrity manifest** release pipeline. That is by design and
documented in `docs/SECURITY.md`.

No key-leak, signature-bypass, or forgeable-serial vulnerability was found.
The issues found were **cross-platform correctness bugs** that broke the
documented macOS workflow and the client on non-Windows, plus minor hardening
gaps. The five code issues below were **fixed in this pass**; the build issues
were fixed while producing the macOS `.app`.

---

## 2. Findings & fixes

### F1 — Client SDK unimportable on macOS/Linux *(High, correctness)* — FIXED
`target_demo/protection/clock_guard.py` and `fingerprint.py` did an
unconditional top-level `import winreg` (Windows-only stdlib). Because
`protection/__init__.py` imports both eagerly, the **entire protection package
failed to import** on macOS/Linux with `ModuleNotFoundError: No module named
'winreg'`. This broke:
- the README's documented macOS source workflow (`python3 -m target_demo.main`), and
- the offline self-test `python -m tests.e2e_licensing` (crashed at import).

**Fix:** guarded the import (`try/except ImportError → winreg = None`) in both
modules; the HKCU registry clock-store read/write now no-op off-Windows (the
decoy-file store and the AES-GCM-authenticated license file remain
authoritative, so anti-rollback still has two independent stores).

### F2 — Protected app silently self-exits on non-Windows *(Medium, correctness)* — FIXED
In `anti_debug.py`, `run_all_checks()` called the Windows API handles
(`_KERNEL32.IsDebuggerPresent()` …) which are `None` off-Windows. The resulting
`AttributeError` was caught and routed to `_on_detection(quiet=True)`, and in the
**default** `DetectAction.EXIT` mode that schedules `os._exit(0)` — i.e. any
protected app running in non-dev mode on macOS/Linux would silently terminate.

**Fix:** `run_all_checks()` now returns "clean" immediately when the Windows
APIs are absent (anti-debug is a Windows-only layer; the app still runs and
licensing is still enforced).

### F3 — No POSIX hardware fingerprint → empty binding off-Windows *(Low, hardening)* — FIXED
`fingerprint.py` collected only Windows identifiers (WMI/PowerShell/registry),
so on macOS/Linux the machine code was derived from zero components (no hardware
binding; e2e `present >= 1` assertion failed).

**Fix:** added a POSIX fallback for the GUID slot — `IOPlatformUUID` via `ioreg`
on macOS, `/etc/machine-id` (or the D-Bus machine id) on Linux — so the
pure-Python reference client produces a stable, bound machine code
cross-platform. (The shipped native mobile SDKs already use their own
platform identifiers.)

### F4 — Binding-relaxation knobs unbounded in the signed payload *(Low, hardening)* — FIXED
`LicensePayload.validate()` accepted any `tolerance`. A serial with
`tolerance >= len(COMPONENT_ORDER)` would let `fingerprint.matches()` succeed
with *all* components dropped — effectively no hardware binding. (Not remotely
exploitable, since serials are vendor-signed, but a mis-issued serial could
silently become machine-agnostic.)

**Fix:** `validate()` now requires `0 <= tolerance < len(COMPONENT_ORDER)` and
`rollback_allowance >= 0`.

### F5 — Fingerprint export mislabels platform *(Low, correctness)* — FIXED
`export_fingerprint_file()` hard-coded `"platform": "windows"`. Exports created
on macOS are now labelled `macos` (falls back to `windows`), matching
`shared.payload_schema.KNOWN_PLATFORMS`.

### B1 — macOS build script produced no installable app *(build, correctness)* — FIXED
`build_protector.sh` combined `--onefile` with `--macos-create-app-bundle`,
which on Nuitka 4.3.1 yields a bare binary + an **empty** `.app` skeleton; and
Nuitka auto-downloads an **x86_64** `ccache` that cannot invoke the arm64
`xcrun` on Apple Silicon (`missing compatible architecture … need x86_64`).

**Fix:** switched to `--standalone --macos-create-app-bundle`, added
`--disable-ccache` and `--macos-app-icon=none`, auto-rename the bundle to
`SecureCode Protector.app`, and `--deep` ad-hoc codesign. A proper
`SecureCode Protector.app` now builds, signs and installs into `/Applications`.

---

## 3. Verification

| Check | Before | After |
|---|---|---|
| `python3 -m tests.e2e_licensing` (macOS) | crash at import | **28 passed, 0 failed** |
| `python3 -m tests.cross_platform_vectors` | pass | pass (unchanged) |
| `import target_demo.protection` on darwin | `ModuleNotFoundError` | imports OK |
| macOS `.app` build + install + launch | n/a (broken) | builds, signs, runs from `/Applications` |

---

## 4. Residual recommendations (not changed — your call)

1. **Keystore passphrase minimum (Low).** `derive_kek()` enforces a 4-char
   minimum for the keystore (the private-key export already requires 8). Since
   the passphrase is the last line of defense if the admin machine is breached,
   consider raising the keystore minimum to 8–12+ and/or adding a strength meter
   in `UnlockDialog`.
2. **Make `nonce` mandatory (Low).** Serials issued without a nonce cannot be
   revoked via the blacklist. The protector always sets one, so consider making
   `nonce` required in `LicensePayload.validate()` to prevent an unrevocable
   serial ever being issued by a future code path.
3. **`b32_decode` repair heuristic (Info).** Stripping `0/1/8/9` to repair
   transcription is safe today (signature verification catches any real
   tampering), but it means two distinct inputs can map to one serial. Harmless;
   noted for awareness.
4. **DB plaintext operational columns (Info, by design).** `fingerprint_code`,
   `product_id`, timestamps and `nonce` are stored in clear (needed for
   lookups/blacklist). Secrets (serial text, customer, notes) are AES-GCM
   encrypted. Acceptable; documented here for completeness.
5. **Doc/behavior nits (Info).** `LicenseDB.add_serial` docstring says "Raises
   ValueError on duplicates" but raises `sqlite3.IntegrityError`; `restore()`'s
   `replace=True` parameter is currently ignored (never clears existing rows).
   Cosmetic, not security.

---

## 5. Files changed in this pass

- `target_demo/protection/clock_guard.py` — guarded `winreg`; registry store no-ops off-Windows.
- `target_demo/protection/fingerprint.py` — guarded `winreg`; POSIX GUID fallback; platform label.
- `target_demo/protection/anti_debug.py` — `run_all_checks()` clean no-op off-Windows.
- `shared/payload_schema.py` — bounded `tolerance` / `rollback_allowance` in `validate()`.
- `build_protector.sh` — standalone `.app`, `--disable-ccache`, auto-rename + deep ad-hoc sign.
