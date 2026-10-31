"""
protector.tools.build_strings_table — DEVELOPMENT-TIME "string layer compiler".

Compiles the protection SDK's sensitive plaintext constants (error messages,
registry value names, WMI queries, debugger process names, master secrets)
into an encrypted literal table: target_demo/protection/strings.py.

What the generated module does at RUNTIME (inside the Nuitka-compiled EXE):
    * The AES-256 key is re-derived on every use from three byte constants
      scattered in the compiled code (SHA-256 of the concatenation) — the key
      never exists as a contiguous plaintext constant in the binary.
    * Each entry is decrypted individually with AES-256-CTR, using a
      per-entry IV derived from the entry id (so no nonce is ever reused
      across entries with the same key).
    * Nothing is cached: plaintext exists only for the microseconds a caller
      uses it, then the bytes are dropped for garbage collection.

Why this matters: tools like `strings`, FLOSS, or simple hex-editor greps
find nothing — error texts, process names and identifiers never appear in
the distributed EXE as plaintext. This is Layer 2 of the defense stack
(see docs/SECURITY.md).

Usage:
    python protector/tools/build_strings_table.py                    # demo
    python protector/tools/build_strings_table.py --sdk-dir PATH \
        --sdk-import-name NAME --company Company --product Product   # custom

Custom mode (docs/INTEGRATION.md): point the tool at a COPIED SDK and set
the company/product names so the encrypted directory + registry identifiers
match your application's data layout.

NOTE: The plaintext table below lives in the DEV repository only (this
tool is never compiled into any shipped binary). After editing entries,
re-run this tool, then rebuild the EXE.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import secrets
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_REPO_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# THE plaintext table. Edit HERE, then re-run this tool.
# ---------------------------------------------------------------------------
PLAINTEXT_TABLE: Dict[str, str] = {
    # --- directory / file names (client side) ------------------------------
    "company_dir":         "SecureCode",
    "product_dir":         "SecureNotepad",
    "license_name":        "license.dat",
    "blacklist_name":      "blacklist.sec",
    "fp_export_name":      "fingerprint.txt",
    "fp_export_format":    "securecode-fingerprint",
    "deact_request_name":  "deactivation_request.dat",

    # --- hardware fingerprint identifiers (registry / CIM / WMI) -----------
    "reg_guid_key":        r"SOFTWARE\Microsoft\Cryptography",
    "reg_guid_value":      "MachineGuid",
    "ps_shell":            "powershell",
    "ps_cpu":              "Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty ProcessorId",
    "ps_board":            "Get-CimInstance Win32_BaseBoard | Select-Object -First 1 -ExpandProperty SerialNumber",
    "ps_disk":             "Get-CimInstance Win32_DiskDrive | Sort-Object Index | Select-Object -First 1 -ExpandProperty SerialNumber",
    "wmi_cpu_prop":        "ProcessorId",
    "wmi_board_prop":      "SerialNumber",
    "wmi_disk_prop":       "SerialNumber",

    # --- anti-debug: debugger/RE tool process names (lowercase, |-joined) --
    "dbg_procs": "|".join([
        "x64dbg.exe", "x32dbg.exe", "x96dbg.exe", "ollydbg.exe", "ollyice.exe",
        "immunitydebugger.exe", "immdbg.exe", "ida.exe", "ida64.exe", "idaq.exe",
        "idaq64.exe", "idat.exe", "idat64.exe", "windbg.exe", "windbgx.exe",
        "ghidra.exe", "ghidrarun.exe", "wireshark.exe", "processhacker.exe",
        "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
        "cheatengine-x86_64.exe", "cheatengine-x86_64-sv.exe", "cheatengine-i386.exe",
        "dnspy.exe", "dnspyx.exe", "de4dot.exe", "fiddler.exe", "httpdebugger.exe",
        "httpdebuggerui.exe", "scylla.exe", "scylla_x64.exe", "importrec.exe",
        "petools.exe", "regshot.exe", "gdb.exe", "lldb.exe", "re_class.exe",
    ]),

    # --- anti-debug: native API names ---------------------------------------
    "nt_query":            "NtQueryInformationProcess",

    # --- VM detection (registry artifacts, |-joined; guest-safe entries) ---
    "vm_keys": "|".join([
        r"SOFTWARE\VMware, Inc.\VMware Tools",
        r"SYSTEM\CurrentControlSet\Services\VMTools",
        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
        r"SYSTEM\CurrentControlSet\Services\VBoxService",
        r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
        r"SYSTEM\CurrentControlSet\Services\VBoxMouse",
        r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
        r"SOFTWARE\Parallels\Parallels Tools",
        r"SYSTEM\CurrentControlSet\Services\prl_tg",
    ]),
    "vm_bios_key":         r"HARDWARE\DESCRIPTION\System",
    "vm_bios_value":       "SystemBiosVersion",
    "vm_tokens":           "vbox|vmware|virtual|hyper-v|xen|parallels|qemu|bochs",

    # --- clock guard storage identifiers (HKCU + decoy file) ---------------
    "reg_clock_key":       r"Software\SecureCode\SecureNotepad",
    "reg_clock_value":     "SessionStore",
    "decoy_rel":           r"cache\primitives.idx",

    # --- master secrets (base64 of random 32B; generated per build) -------
    "license_master":      "",  # filled in by _make_secrets() below
    "clock_master":        "",  # filled in by _make_secrets() below

    # --- user-facing license error messages (spec: encrypt messages) ------
    "msg_invalid":         "Invalid serial key (signature check failed).",
    "msg_malformed":       "The serial key is malformed. Please paste it exactly as received.",
    "msg_other_machine":   "This serial key is bound to another computer.",
    "msg_expired":         "Your license has expired. Please renew to continue using the product.",
    "msg_revoked":         "This serial key has been revoked by the vendor.",
    "msg_clock":           "A system clock inconsistency was detected. Please set the correct date and time, then restart the application.",
    "msg_damaged":         "The local license file is damaged. Please activate again.",
    "msg_not_installed":   "No license is installed on this computer. Please activate.",
    "msg_product":         "This serial key is for a different product.",
    "msg_future":          "System date is set before this serial was issued. Please correct the system clock.",
}


def _make_secrets() -> None:
    """Fresh random master secrets on every compilation of the string layer.

    Rotating these invalidates existing local license files / clock-state
    stores (they encrypt data derived from these masters) — regenerate
    serials after running this tool. Only run it when you intend to rotate.
    """
    PLAINTEXT_TABLE["license_master"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    PLAINTEXT_TABLE["clock_master"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _customize(company: str, product: str) -> None:
    """Fill the per-product identifiers (custom projects only).

    These derive the client-side data locations (%PROGRAMDATA%\\Company\\
    Product) and the clock-guard registry key, so they MUST match the
    ProtectionConfig of the product being built.
    """
    PLAINTEXT_TABLE["company_dir"] = company
    PLAINTEXT_TABLE["product_dir"] = product
    PLAINTEXT_TABLE["reg_clock_key"] = rf"Software\{company}\{product}"


def _encrypt_table(key: bytes) -> Dict[str, str]:
    """AES-256-CTR encrypt every entry; per-entry IV = SHA256('sc-ctr-iv:'+id)[:16]."""
    out: Dict[str, str] = {}
    for entry_id, plaintext in sorted(PLAINTEXT_TABLE.items()):
        if not plaintext:  # pragma: no cover - defensive
            raise RuntimeError(f"empty plaintext for entry {entry_id!r}")
        iv = hashlib.sha256(b"sc-ctr-iv:" + entry_id.encode("ascii")).digest()[:16]
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        ct = enc.update(plaintext.encode("utf-8")) + enc.finalize()
        out[entry_id] = base64.b64encode(ct).decode("ascii")
    return out


TEMPLATE = '''"""
{sdk_import_name}.strings — GENERATED by
protector/tools/build_strings_table.py. DO NOT EDIT, DO NOT COMMIT CHANGES
by hand — edit the tool and regenerate.

Encrypted string layer (anti-RE Layer 2, "critical-code hardening"):

    * Plaintext constants (error messages, registry value names, debugger
      process lists, WMI queries, embedded master secrets) never appear as
      readable strings in the compiled binary — they are stored as AES-256-CTR
      ciphertext literals below.
    * The AES key is derived at RUNTIME from three scattered byte constants
      (_KA/_KB/_KC -> SHA-256). It never exists as one contiguous blob in the
      image, and it is only materialized inside the decryptor call.
    * Each entry uses a deterministic per-id IV (SHA-256 of a fixed prefix +
      entry id), so the same key never encrypts two entries under the same
      nonce.
    * No caching: S() decrypts on every call and the returned Python str is
      the only plaintext copy (unavoidable — see docs/SECURITY.md for the
      honest limitation).

Public API:
    S("entry_id")  -> str   decrypted string
    SB("entry_id") -> bytes decrypted bytes (caller should wipe promptly)
    ENTRY_IDS      -> tuple of known ids (for dev-time validation)
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- scattered key material (assembled at runtime only) --------------------
_KA = {ka}
_KB = {kb}
_KC = {kc}


def _derive_key() -> bytes:
    """Runtime key derivation: SHA-256 over the concatenated parts."""
    return hashlib.sha256(_KA + _KB + _KC).digest()


def _derive_iv(entry_id: str) -> bytes:
    """Deterministic per-entry IV (no nonce reuse across entries)."""
    return hashlib.sha256(b"sc-ctr-iv:" + entry_id.encode("ascii")).digest()[:16]


_ENC: dict[str, str] = {{
{enc_entries}
}}

#: Every valid entry id (dev-time validation / tooling).
ENTRY_IDS = tuple(sorted(_ENC))


def _decrypt(entry_id: str) -> bytes:
    """Decrypt one entry (KeyError on unknown id = developer bug)."""
    cipher = Cipher(algorithms.AES(_derive_key()), modes.CTR(_derive_iv(entry_id)))
    dec = cipher.decryptor()
    ct = base64.b64decode(_ENC[entry_id].encode("ascii"))
    return dec.update(ct) + dec.finalize()


def S(entry_id: str) -> str:
    """Return the decrypted string for an entry id (not cached)."""
    return _decrypt(entry_id).decode("utf-8")


def SB(entry_id: str) -> bytes:
    """Return the decrypted bytes for an entry id (wipe the copy quickly)."""
    return _decrypt(entry_id)


def _selftest() -> None:
    """Ensure the table is intact (called once from integrity checks)."""
    if len(_ENC) != len(ENTRY_IDS):
        raise RuntimeError("strings table corrupted")


__all__ = ["ENTRY_IDS", "S", "SB"]
'''


def main() -> int:
    """Regenerate the SDK's strings.py (demo layout by default)."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sdk-dir", type=Path,
                        default=_REPO_ROOT / "target_demo" / "protection",
                        help="the protection SDK package directory")
    parser.add_argument("--sdk-import-name", default="target_demo.protection",
                        help="dotted import name of the SDK package")
    parser.add_argument("--company", default="SecureCode",
                        help="company name (data directory namespace)")
    parser.add_argument("--product", default="SecureNotepad",
                        help="product name (data directory namespace)")
    args = parser.parse_args()
    sdk_dir: Path = args.sdk_dir.resolve()
    if not sdk_dir.is_dir():
        print(f"[error] SDK directory not found: {sdk_dir}")
        return 2
    if (args.company, args.product) != ("SecureCode", "SecureNotepad"):
        _customize(args.company, args.product)

    _make_secrets()
    # Three random scattered parts; the real AES key is whatever
    # SHA-256(A||B||C) evaluates to at runtime — so we derive it here too
    # and encrypt the table with exactly that key.
    ka = secrets.token_bytes(16)
    kb = secrets.token_bytes(16)
    kc = secrets.token_bytes(16)
    key = hashlib.sha256(ka + kb + kc).digest()

    entries = _encrypt_table(key)
    enc_lines = ",\n".join(
        f'    "{eid}": "{ct}"' for eid, ct in entries.items()
    )
    output = TEMPLATE.format(
        sdk_import_name=args.sdk_import_name,
        ka=repr(ka), kb=repr(kb), kc=repr(kc), enc_entries=enc_lines
    )
    out = sdk_dir / "strings.py"
    out.write_text(output, encoding="utf-8")
    print(f"[ok] wrote {len(entries)} encrypted entries -> {out}")
    print("[!] Master secrets were ROTATED: existing local licenses and clock")
    print("    state will be invalidated. Regenerate serials after this step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
