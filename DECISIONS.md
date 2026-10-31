# DECISIONS.md — design decisions & their rationale

The brief allowed sensible professional decisions with documentation. These
are the calls that were made where the spec left room (or where reality
required a deviation). Nothing here weakens a hard requirement.

## Cryptography & protocol

1. **Ed25519 exactly as specified.** Private key only inside the protector's
   passphrase-wrapped keystore (`PBKDF2-HMAC-SHA256`, 600k iterations,
   AES-256-GCM). Public key embedded in the EXE via `pubkey_blob.py` +
   SHA-256 digest cross-check. Serial = `Base32(payload_json || 64B_sig)`,
   minified key-sorted JSON so signing/verification bytes are identical.
2. **Base32, not Base64**, for serials: case-insensitive, no 0/O or 1/l
   ambiguity — survives manual transcription. Decoders strip dashes,
   whitespace and (heuristic repair) the digits Base32 never uses.
3. **Compact JSON payload, not CBOR/msgpack.** The spec offered a choice.
   JSON keeps the codec dependency-free and debuggable; a serial is
   ~500–600 chars for 1 year — long but fine for copy/paste delivery.
   Compression (zlib) was evaluated and rejected: payloads this small grow
   or break even, and it adds a versioning edge (noted as future work if
   feature-flag lists get big).
4. **Fingerprint code = 80 bits** (`mask byte + SHA-256[:9]`, Base32 → 16
   chars): collision-infeasible for a realistic customer base while staying
   human-typeable. The mask nibble encodes which components were present, so
   the tolerance mechanism (drop-up-to-N components) can re-derive codes
   deterministically.
5. **`wmi` package (DCOM), not `wmic.exe`.** wmic.exe is deprecated and
   removed in Windows 11 24H2 — a build on it would break on new machines.
   Fallback chain: WMI/DCOM → PowerShell `Get-CimInstance` → `py-cpuinfo`
   static-CPU hash → missing component (tolerated by mask).
6. **`py-cpuinfo` is a last-resort fallback only**, included per the brief's
   dependency list; it produces a stable-but-weak identifier (hash of static
   CPU fields) when DCOM and CIM are both blocked. Documented as such.
7. **Clock-rollback allowance is per-serial** (payload `rb`, default 3) —
   the grace mechanism the brief requested. Watermarks in three stores:
   GCM-authenticated license file (authoritative), HKCU registry value
   (obfuscated name), decoy file. `GetTickCount64` uptime is used as a
   mid-session sanity cross-check.
8. **Blacklist file is ignored if unreadable** (never bricks a customer app
   on a corrupted transfer), but always applies if correctly signed.
9. **Machine transfer**: old machine consumes a vendor-signed permit → local
   license + clock stores wiped + receipt file; the new machine gets a NEW
   serial (serials are fingerprint-bound, so "moving" = re-issuing). The
   deactivation *request* file carries the original signed serial so the
   vendor can verify authenticity before issuing the permit.

## Anti-reverse-engineering

10. **VM detection ships OFF by default** (config flag). False positives on
    legitimate customers' machines (Hyper-V/WSL2 hosts, corporate VDIs) cost
    more support grief than the marginal protection. Guest-only artifacts
    are used (VMware Tools / VBox additions / guest parameters), and the
    `hvservice` host key was deliberately excluded for this reason.
11. **On detection: delayed `os._exit(0)`** (default) — exit code zero,
    2–8 s randomized delay, no message, nothing in logs that hints at the
    cause. `DEGRADE` alternative makes licensing fail with a generic
    "damaged" error. Watchdog thread runs at jittered 20–45 s intervals.
12. **Integrity manifest honesty.** In Nuitka-frozen builds there are no
    source files to hash, so Layer 4 verifies: embedded pubkey digest,
    critical-constant digest, and that every SDK module imports and carries
    Nuitka's `__compiled__` marker. Whole-PE self-hashing is listed in
    SECURITY.md as a documented future step (external packer / post-build
    digest injection) because a binary cannot embed a hash of itself
    without a chicken-and-egg problem.
13. **Anti-debug never raises or shows UI**; a failing check degrades rather
    than crashes the app (availability for legit users beats paranoia).

## GUI

14. **QSS composed programmatically** (`ui/theme/theme.py`) instead of a
    static `.qss` resource: live dark/light + accent switching is a spec
    requirement, impossible with a static file. A `theme_snapshot.qss` is
    still written to `protector/assets/` on every apply for
    review/build-artifact purposes.
15. **Frameless window with native WM_NCHITTEST handling** — drag, 8-edge
    resize and Aero Snap behave exactly like a first-class Win32
    application; plain mouse-drag fallback exists for non-Windows dev.
16. **Vector line icons as inline SVG** (`protector/ui/theme/icons.py`,
    Lucide visual language, ISC) instead of binary icon assets. v1/v2 used
    emoji, which rendered inconsistently (missing glyphs, monochrome
    offscreen, wrong baseline); the SVGs are rasterized by QtSvg at the
    device pixel ratio and re-tinted on every theme/accent switch. Still
    zero binary resources to ship. Only the
    EXE icon is a real `.ico` (generated programmatically by
    `target_demo/tools/make_icon.py` — no Pillow dependency).
17. **QThread workers + spinner overlay for every crypto/DB call** (spec
    requirement); `Worker` + `run_task` centralize it.
18. **Services dataclass** dependency injection instead of module-level
    singletons — keeps pages testable and lifecycle (keystore wipe on
    close) in one place.
19. **`os._exit()` after `app.exec()`** in both apps: PySide6 on Windows can
    fail-fast (0xC0000409) during interpreter/Qt teardown in arbitrary
    order; secrets are wiped in `closeEvent` and logs flushed first.

## Product decisions

20. **Demo keypair shipped** (`demo-assets/demo_keypair.sec`, passphrase
    `demo-demo-demo`) so the repo runs end-to-end immediately. Prominently
    documented as demo-only; the protector generates real keypairs itself.
21. **Serial Manager "extend" = re-sign as a new record state** (new nonce +
    new serial, same machine binding). Revocation of the old serial is a
    separate, explicit decision (blacklist) — safer than auto-revoking.
22. **`tests/` ships with the product** — the E2E test doubles as living
    documentation of the protocol and is a release sanity gate.

## UI decisions (v2 restyle - O&O-style professional GUI)

23. **Bilingual dashboard (English + Persian)** - every caption on the
    Dashboard (and key headers/tooltips elsewhere) is shown in BOTH
    languages; Persian lines render in the bundled Vazirmatn font via the
    `class="fa"` QSS hook. The app stays English-primary (a professional
    admin tool), Persian is additive - never a separate translated build.
24. **Vazirmatn font bundled** (`protector/assets/fonts`, SIL OFL 1.1,
    rastikerdar/vazirmatn v33.003): registered at runtime via
    `QFontDatabase.addApplicationFont` so Persian renders correctly even
    on machines without Persian fonts, including a future frozen build
    (note for the protector packaging step: include the TTFs with
    `--include-data-files=protector/assets/fonts/*.ttf`).
25. **Jalali calendar = a faithful Python port of Doran core**
    (`protector/core/jalali.py`; Doran is MIT, (c) Doran Contributors,
    https://github.com/amiralibg/Doran). Doran itself is a TypeScript/
    JavaScript ecosystem (@doranjs/core) and cannot run inside PySide6,
    so its battle-tested conversion algorithm (Borkowski/Noruzi Niya, the
    same math behind jalaali-js/moment-jalaali), fa/en locale names and
    Persian-digit helpers are ported 1:1 and credited. Verified by
    `tests/jalali_test.py` (historical anchors + round-trip of every day
    1970-2030). Used by: Dashboard today-chip, status-bar date, bilingual
    tooltips, and the `JalaliDateEdit` picker (custom date expiry).
26. **O&O-Software-style visual language** (https://www.oo-software.com):
    light-first professional theme - white cards on a soft gray canvas, a
    branded deep-blue title bar with white text, grouped sidebar sections
    (OVERVIEW/LICENSING/TOOLS/GENERAL), Segoe UI typography, flatter
    radii, utilitarian density. Dark mode remains as the secondary theme.
    Default theme/accent changed to light + `#0069B4` (existing users'
    saved settings keep their choice; the stale-encrypted settings file
    resets to these defaults once).
27. **Sidebar/nav styling moved fully into the global QSS** (object names
    `#navRail/#navBrand/#navFooter` + `navButton` property): a local
    stylesheet per widget kept losing the cascade battle against the app
    stylesheet; centralizing it also made live theme switching instant.

## UI decisions (v3 - "SecureCode console" redesign + EN/FA switch)

28. **Neutral console design replaces the O&O look** (supersedes 26): soft
    gray canvas, white / deep-slate cards with 12px radii and hairline
    borders, a neutral title bar (accent only on the logo mark, primary
    buttons, selected nav item and focus rings), semantic "soft" tints for
    badges. Light and dark are equal first-class themes; the unlock gate
    follows the Windows light/dark setting because the saved theme is
    encrypted until unlock. Default accent is now `#2563EB` (the old
    `#0069B4` stays selectable as "Classic").
29. **Live re-skinning via a callback registry** (`theme.on_theme`): things
    QSS cannot reach (icon pixmaps, QPainter widgets, per-swatch colors)
    register a callback that runs after every `ThemeManager.apply()`;
    widgets are held weakly. Pages never set colors in local stylesheets
    - they tag widgets (class / badge / iconBadge properties) for the
    global QSS. The v2 `background: transparent` sheets on container
    widgets were removed: an unscoped local sheet cascades to every child
    and was what made primary buttons render without a fill.
30. **One-click English / Persian UI** (`protector/ui/i18n.py`, title-bar
    FA/EN button, Ctrl+L, Settings > Appearance), replacing the v2
    "English + Persian side by side" captions (supersedes 23). Source
    strings stay English and go through `tr()`; Persian mode switches the
    app to right-to-left, puts Vazirmatn first in the font stack (1px
    larger) and uses Persian digits and Jalali dates. A switch rebuilds
    the shell window (same session, keystore untouched) instead of
    re-translating live widgets - far less code, no stale strings. Latin
    runs inside Persian text (dates, key ids) are wrapped in Unicode
    isolates so bidi cannot reorder them.
31. **Persian text rendering**: no letter-spacing in RTL mode (it breaks
    the joins of cursive Persian), and the app font uses
    `PreferNoHinting` + antialiasing - Windows grid-fitting distorts
    Vazirmatn's thin strokes at UI sizes.


## Documentation & tooling decisions (v2.1)

28. **docs/INTEGRATION.md (bilingual)** — the human-facing guide for
    protecting a THIRD-PARTY application with this system: the five-step
    path (copy SDK, embed own key, entry-point wrapper, strings+manifest,
    Nuitka build), vendor workflow, API reference, pre-release checklist
    and FAQ. docs/AI_PROMPT.md (EN + FA) holds a copy-paste prompt that
    walks an AI assistant through the same contract without letting it
    invent its own licensing scheme.
29. **protector/tools/export_pubkey_blob.py** — writes a product's
    pubkey_blob.py from the ACTIVE keystore (asked-for integration step 2;
    previously only the demo keypair generator could produce that file).
30. **build_strings_table / make_integrity_manifest generalized** — both
    tools now accept --sdk-dir/--sdk-import-name/--company/--product and
    DISCOVER modules from the directory, so a copied SDK in an arbitrary
    project layout gets a valid encrypted-strings layer and Layer-4
    manifest. Defaults reproduce the shipped demo behavior exactly.
    integrity.py's dev-mode source check now resolves modules through the
    import system instead of a guessed parents[2] depth (the old guess
    only worked for the demo layout). Verified end-to-end on a synthetic
    custom project layout (integrity PASS) and re-verified the demo
    (manifest regenerated, e2e 28/28).

## Frozen-build integrity fix (v2.2)

31. **Nuitka import-system quirk fixed** — first frozen EXE exited silently
    with "integrity self-check failed: 3 problem(s)". The diagnostic rebuild
    (integrity.py now logs module NAMES, not just counts) pinpointed them:
    the three package __init__ entries (shared.__init__, target_demo.__init__,
    target_demo.protection.__init__). CPython tolerates the synthetic
    submodule spelling "pkg.__init__" in importlib.import_module; Nuitka's
    compiled import system does NOT. Fix: _import_name() normalizes
    "pkg.__init__" -> "pkg" before import in BOTH frozen and dev branches
    (the __init__ IS the package module — same object, same file, same hash).
    Pipeline re-run: manifest regenerated, dev integrity PASS, e2e 28/28,
    final rebuild, frozen EXE verified alive with the activation dialog.
    NOTE for real deployments: Nuitka postprocessing hit AV file-lock
    warnings (error 22, retried OK) while attaching version resources —
    add the dist folder to AV exclusions to avoid flaky builds/disappearing
    artifacts.

## Protector console EXE (v2.3)

32. **build_protector.bat — the vendor dashboard itself ships as an EXE.**
    Nuitka onefile, 26.6 MB, ProductName="SecureCode Protector". Includes
    --include-package=protector + shared, bundles the Vazirmatn fonts
    (--include-data-dir) and the shipped demo keypair (so "import demo
    keypair" works on fresh machines), and EXCLUDES the dev-time tools
    (--nofollow-import-to=protector.tools). Runtime state stays OUTSIDE the
    binary (%APPDATA%\SecureCode\Protector\ keystore/settings/licenses.db),
    so the EXE opens the vendor's existing keystore with their passphrase.
    Verified: process alive at the Unlock dialog, fonts + keypair extracted
    to the right onefile paths, correct version metadata.

## Click-to-copy product UUID (v2.4)

33. **Settings -> Products: clicking a UUID cell copies it.** cellClicked
    handler on column 1 (UUID) copies the cell text via QGuiApplication
    clipboard and confirms with a success toast (bilingual: "برای کپی کردن
    UUID محصول کلیک کنید" tooltip / "UUID محصول در کلیپ‌بورد کپی شد" toast).
    UUID cells are now underlined (monospace font kept) so the clickability
    affordance is visible without hovering. ui_smoke re-run green; protector
    EXE rebuilt with the feature.

## Restore UX fix (v2.5)

34. **"Restore failed — authentication failed" was a wrong backup
    passphrase, said unclearly.** Diagnosed against the user's actual
    E:\licenses_backup.sec: the container is structurally valid; DB-level
    round-trip (fresh restore / duplicate-skip / revoked-preserve /
    wrong-pass / tampered-file) is all green. The failure was almost
    certainly the user typing the KEYSTORE passphrase where the BACKUP
    passphrase (chosen at creation time) is required — and the old toast
    showed the cryptic crypto message. Fix: _restore() now maps
    WrongPassphraseError to a bilingual message explaining the passphrase
    distinction, KeystoreError to "not a valid backup", and the 0-imports
    duplicate case to an explicit "already in the database" note.
    Verified by tests/restore_ux_test.py (fa strings, error mapping,
    round trip) + ui_smoke.

## Cross-platform SDKs + macOS protector (v3.1)

35. **The wire format is FROZEN, ports reproduce Python byte-for-byte.** No
    platform "reinterprets" the serial: every SDK re-implements the exact
    canonical JSON (`sort_keys`, `(",",":")`, `ensure_ascii` — lowercase-hex
    `\uXXXX`, surrogate pairs, keys sorted by code point), RFC 4648 Base32
    with repair heuristics, RFC 8032 Ed25519 over those bytes, RFC 5869 HKDF
    (`ikm = master+"|"+machine_code`, `salt = product_id`, `info = context`)
    and the `SCLIC1` AES-256-GCM license container (no AAD). Result: a
    serial issued by the Windows protector verifies unchanged on Android,
    iOS and macOS — and the fingerprint codes are the same 16 chars
    everywhere. There is no "platform" field in the payload; platforms never
    leak into the signed bytes.
36. **The four fingerprint slots are stable hash LABELS, not literal
    components.** `cpu/board/disk/guid` keep their names on every OS; each
    platform pours its own identifiers in: Windows (WMI cpu/board/disk +
    MachineGuid — unchanged), Android (cpu=Widevine MediaDrm ID,
    board=SSAID, disk=optional Keystore digest), iOS (cpu=Keychain UUID,
    board=IDFV), macOS (cpu=en0 MAC, board=IOPlatformSerialNumber,
    guid=IOPlatformUUID). Picks optimize for the Windows UX: the default
    Android profile keeps the SAME machine code across uninstall/reinstall
    (same serial re-activates); tolerance=1 absorbs factory-reset SSAID /
    IDFV changes. The optional `platform` key in fingerprint EXPORT FILES
    is UI metadata for the protector only (labels + platform badge);
    legacy exports without it are Windows.
37. **Android Ed25519 is hand-implemented (RFC 8032, BigInteger).**
    `java.security` Ed25519 needs API 33 while minSdk is 24 — and Conscrypt
    would be a third-party dependency (rejected: the SDK is pure Kotlin,
    zero dependencies). The algorithm was parity-proven against OpenSSL
    signatures BEFORE porting (mutual verification). Two traps documented
    for future porters: the group order L is
    2^252+27742317777372353535851937790883648493 (NOT 277478...), and the
    SHA-512 hash h is interpreted LITTLE-endian when reducing mod L.
38. **Apple SDK = one SwiftPM package, CryptoKit, manual HKDF.** iOS 13+/
    macOS 10.15+ (CryptoKit Ed25519/AES-GCM; HKDF is hand-rolled because
    CryptoKit's HKDF needs iOS 14). Clock stores use AES-GCM files (never
    cross-platform interop needed — internal format per platform). macOS
    integrity adds a SecCode signature check (opt-in,
    `requireCodeSignature`, because unsigned dev builds would break).
39. **Flutter plugin embeds copies of the native SDKs (`sync_native.py`).**
    A pub package must be self-contained, so the Kotlin/Swift sources are
    sync-copied into the plugin (never hand-edited; `--check` verifies).
    The Dart layer is a thin typed wrapper over a method channel
    (`securecode/licensing`); LicenseState names map via enum `.name`/
    `.rawValue`. `sharedDarwinSource` (needs Flutter 3.27) serves iOS+macOS
    from one darwin/ tree.
40. **Correctness = conformance vectors, not vibes.** `tests/cross_platform_vectors.py`
    generates `sdks/vectors.json` (serials, fingerprints, Ed25519 triples,
    HKDF, Base32/canonical-JSON cases) consumed by EVERY SDK's test suite;
    SDKs print selftest reports `{sdk, all_ok, results:[…]}` validated via
    `--check`. Rationale: no JVM/Kotlin/Flutter/Swift toolchains exist on
    this Windows machine, so ports cannot be compiled locally — vectors +
    line-by-line porting (from the Python reference) carry the correctness
    argument, and `gradle test`/`swift test`/`flutter test` on proper
    machines are the release gate. The vector generator self-tests the
    Python side and is part of the repo test suite.
41. **Every SDK embeds the DEMO public key by default** (plus its own random
    32-hex master secret from `sdks/gen_strings_masters.json` via
    `sdks/gen_strings.py`), so demo serials verify out-of-the-box on every
    platform. Documented loudly in every README + the security notes: real
    deployments must export their own key from the protector and rotate the
    masters (regenerated masters are never committed).
42. **Protector runs on macOS natively** (Windows unchanged): app state
    moves to `~/Library/Application Support/SecureCode/Protector/`
    (XDG fallback on Linux), `icacls` ACL hardening maps to `chmod 600` on
    POSIX, font stacks fall back to Helvetica Neue/Menlo when Segoe UI/
    Cascadia Mono are absent, `requirements.txt` uses env markers
    (`sys_platform == "win32"`) for wmi/pywin32/py-cpuinfo, and
    `build_protector.sh` produces the Nuitka .app bundle (ad-hoc signed,
    with Developer-ID guidance). The Windows client (target_demo) stays
    Windows-only by design — mobile clients use the native SDKs.

## Security & cleanliness audit (v3.1) — findings + hardening

43. **Input size caps everywhere (all four implementations).** An audit
    pass flagged that every local artifact read (license.dat, blacklist.sec,
    transfer permits, clock decoy store, fingerprint exports) was read
    into memory unbounded — a dropped multi-GB file would OOM-crash the
    client instead of failing into a clean DAMAGED/malformed state. Fixed
    with pre-read `stat()` checks and uniform caps: license/permit/
    export 1 MiB, blacklist 16 MiB (a legit 100k-nonce vendor list is
    ~4-5 MB — headroom), clock store 4096 B. Applied to the Python client,
    the Kotlin SDK, the Swift SDK (then re-synced into the Flutter
    plugin), and the protector's fingerprint reader. Oversized blacklist
    is IGNORED (never bricks); oversized license maps to the existing
    DAMAGED state; oversized permit to the existing "malformed" reply.
44. **Malformed-export crash fixed + exception hierarchy alignment.**
    `read_fingerprint_file` crashed with an unhandled ValueError when
    `created` was non-numeric or the JSON was a non-object; it now
    validates shape and raises controlled `FingerprintParseError`s with
    specific `user_message=`s. `FingerprintParseError` now inherits
    `(SecureCodeError, ValueError)` so it supports the shared
    user-message pattern while staying catchable as a ValueError for
    existing callers. Oversized exports are refused pre-read (1 MiB cap).
45. **Flutter glue hardened + cleaned.** The Kotlin plugin's bare `!!`
    unwraps became explicit validation (`requirePath`/`requireContext`/
    `requireConfig` throwing descriptive IllegalArgumentException/
    IllegalStateException surfaced as clean PlatformExceptions), the
    redundant `client()!!` double-unwrap was removed, the single-thread
    executor is shut down on engine detach, and detached state clears
    `config` too. The Swift glue was already guard-based (no change).
46. **Audit-passed items recorded as "considered and accepted"** (full
    checklists + reusable bilingual audit prompt: `docs/AUDIT_PROMPT.md`):
    no shell=True/eval/exec/pickle anywhere; SQL fully parameterized; all
    crypto randomness from CSPRNGs (`secrets`/SecureRandom/CryptoKit) with
    the single documented exception of anti-debug jitter delays; timing
    side-channels on machine codes/nonces judged NON-issues because every
    compared value is public (sent by customers in e-mails) or
    signature-protected; broad `except Exception` confined to documented
    availability-critical fallback paths; PBKDF2 600k + GCM keystore with
    SecureBuffer wiping unchanged; no secrets in logs (verified statement
    by statement). Cleanup: FA translations added for the new platform
    component labels + badges; the Layer-4 integrity manifest was
    regenerated after the client-source changes; e2e 28/28, platform
    fingerprint 13/13, UI smoke, vectors and sync --check all green
    post-hardening.
