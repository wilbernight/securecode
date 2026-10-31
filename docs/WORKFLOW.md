# WORKFLOW.md — the vendor's day-to-day operating manual

Everything here is 100 % offline. No server, no activation service, no
telemetry — file exchange (e-mail, USB) is the only "protocol" you run.

---

## 1. One-time setup (per business)

1. Install: `pip install -r requirements.txt`.
2. Launch the protector: `python -m protector.main`.
3. **First run** → create your keystore passphrase (≥ 8 chars, strong:
   it wraps the key that signs EVERY serial you will ever issue).
4. **Immediately**: Settings → *Export private key…* → choose a SEPARATE
   passphrase → store the `.sec` file offline (USB stick in a safe). This
   is your disaster recovery.
5. Define your product(s): Settings → Product catalog → name + version
   (UUID is generated). The UUID must match `product_id` compiled into
   that product's EXE (`ProtectionConfig`).
6. Optional: rename/adjust the Build page defaults; test-drive the whole
   flow on your own machine with the shipped demo keypair.

> Using the shipped demo keypair? Settings → *Import shipped demo keypair…*
> (passphrase `demo-demo-demo`) — the protector then issues serials the
> demo EXE accepts. Switch to your OWN keypair before real customers.

---

## 2. Customer lifecycle

```
┌────────────────────────────────────────────────────────────────────────┐
│ CUSTOMER                                VENDOR (you)                    │
├────────────────────────────────────────────────────────────────────────┤
│ 1. installs the protected EXE                                         │
│    └─ activation dialog shows                                          │
│       machine code XXXX-XXXX-XXXX-XXXX                                 │
│        │ "Save fingerprint file…" → fingerprint.txt ──── e-mail ────▶  │
│                                              2. Fingerprint Reader tab │
│                                                 paste / open file      │
│                                                 ✅ validated           │
│                                              3. Generate Serial tab    │
│                                                 (code pre-filled)      │
│                                                 customer, duration,    │
│                                                 flags → Issue serial   │
│        ◀──────── .lic file / pasted serial ──────────────────────────  │
│ 4. pastes serial → Activate → app runs                                 │
│    (every launch re-verifies silently: signature, machine, expiry,      │
│     clock, blacklist — all offline)                                    │
│                                                                        │
│ 5. … a year passes …                                                   │
│        ◀──────── new serial (1y) ── 4'. Extend the row (re-sign) ─────  │
│                                                                        │
│ 6. hardware failure / new PC:                                          │
│    "Deactivation request" file ─────────────────────────── e-mail ──▶  │
│                                              7. verify its serial       │
│                                                 (Manager → detail),     │
│                                                 revoke the old serial, │
│                                                 get the NEW machine's   │
│                                                 fingerprint, issue     │
│                                                 permit + new serial    │
│        ◀── transfer_permit.sec + new serial ──────────────────────────  │
│ 8. OLD PC: "Deactivate with vendor permit" (wipes license,             │
│    writes receipt → send it back as proof)                              │
│    NEW PC: activate with the new serial                                │
│                                                                        │
│ 9. chargeback / piracy:                                                │
│    Manager → revoke serial → Export signed blacklist → distribute      │
│    blacklist.sec → all installs block within one launch               │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Issuing a serial (the daily loop)

1. **Fingerprint Reader** tab → paste the 16-char code (or open their
   `fingerprint.txt`; age > 90 days triggers a warning — ask for a fresh
   one).
2. Read the component list: ✅ CPU / motherboard / disk / machine GUID.
   Missing components → consider tolerance ≥ 1 (survives one component
   swap) — 1 is already the default.
3. **Generate serial for this machine** → form pre-filled → set customer
   (invoice no. works great), duration, feature flags, notes → **Issue**.
4. Copy / save `.lic` → deliver. The record is now in the encrypted DB.

### 2.2 Monitoring

* **Dashboard**: totals, active, expiring < 30 d, expired, revoked, and
  the 12-month issuance chart.
* Weekly habit: open the Manager, filter status = *Expiring*, proactively
  send renewals (issue a new serial, or Extend the row: re-signs with a new
  validity — deliver the new key; the old one stays valid until its own
  expiry unless you revoke it).

### 2.3 Renewal (30-second version)

Manager → select row → **Extend…** → days (0 = lifetime) → the re-signed
serial lands in your clipboard → paste into your reply e-mail.

### 2.4 Machine transfer (offline, two files)

1. Customer on the OLD machine (activation dialog): *Deactivate with
   vendor permit* is the last step — first they send you the
   **deactivation request** file (it contains their original signed
   serial).
2. You: Manager → open the row (verify the serial matches the request),
   collect the NEW machine's fingerprint code.
3. Manager → **Transfer permit…** → paste new code → save
   `transfer_permit.sec`.
4. Issue a NEW serial for the new machine code (normal flow).
5. Customer: OLD machine consumes the permit (license wiped, receipt
   written — ask them to send it back), NEW machine activates with the
   new serial. Revoke the old serial if you want it dead immediately.

### 2.5 Revocation

Manager → **Revoke** → **Export signed blacklist** → distribute
`blacklist.sec` (e-mail/USB; customer drops it into
`%PROGRAMDATA%\SecureCode\<Product>\`). Every install blocks the revoked
nonce on next launch. Restoring a serial works the same way (revoke flag
off, re-export the blacklist).

---

## 3. Backups (do weekly)

Settings → **Create encrypted backup…** → passphrase-wrapped `.sec`
containing the full DB. Store next to your private-key export (two
different passphrases is fine and even advisable). Restoring imports and
skips duplicates — safe to run on any machine.

**What you must back up:** keystore export (`signing_key.sec`), DB
backups, and this repo's `tools/` (the string-layer source of truth).

## 4. Releasing a new build of your product

```
protector\tools\build_strings_table.py     # rotate masters (breaks old licenses!)
target_demo\tools\gen_demo_keypair.py       # demo builds only
protector\tools\make_integrity_manifest.py  # Layer-4 manifest of final sources
build.bat                                   # or the Build tab's generated one
python -m tests.e2e_licensing               # 28/28 must pass
```

> Rotating the string layer invalidates existing local licenses (master
> secrets changed) — plan the release as a re-activation event, or skip
> the rotation when the string table didn't change (then only the
> manifest step is needed if sources changed).

## 4.1 Reissuing the same product after key rotation

If you ever regenerate the keypair (Settings → Regenerate keypair):
every outstanding serial dies. Customers re-activate with new serials;
you still have the DB records to know who to contact (Dashboard →
Export/copy). This is why keypair regeneration asks you to type
`REGENERATE`.

## 5. Support quick-reference

| Customer says | Cause | Your move |
|---|---|---|
| "Invalid serial" | typo / truncated paste | send the `.lic` file instead |
| "Bound to another computer" | wrong machine (or restored image) | verify fingerprint code, then transfer flow (§2.4) |
| "Serial expired" | validity over | renew (§2.3) |
| "Clock inconsistency" | system clock rolled back > allowance | correct the clock; if it persists, re-issue serial (resets counters at activation) |
| "License revoked" | on your blacklist | check Manager row → restore if mistake |
| Reinstalled Windows, same PC | machine GUID changed | tolerance may still pass (mask permits); if not, §2.4 |
