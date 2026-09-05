#!/usr/bin/env python3
"""Whisper — triage the collected package and surface the exfiltration chain.

Runs over the extracted evidence root and answers the three questions in the
brief, in order:

    1. what AI tool was installed      -> audit EXECVE + services + sockets
    2. what it was used for            -> ~/.ollama/history, keyword-scored
    3. what was staged for exfil       -> Trash deletion-date outlier + the
                                          hidden encrypted archive

Usage:  python3 triage.py /path/to/whisper_evidence
Stdlib only.
"""

import argparse
import collections
import datetime
import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wzaes import AESZipReader, _KEY_LEN            # noqa: E402

# Prompts that would make a SOC analyst sit up. Weighted so that a single
# "how do I create a zip" does not outrank "delete the script afterwards".
SUSPICIOUS = {
    "encrypted zip": 5, "aes encrypted": 5, "password protected": 4,
    "pyzipper": 4, "upload the archive": 5, "remote server": 3,
    "delete the script": 5, "clean the bash history": 5, "no traces": 5,
    "use the password": 5, "derive an encryption key": 4, "passphrase": 3,
    "reads all csv files": 4,
}

EXEC_RE = re.compile(r'type=EXECVE msg=audit\((\d+)\.\d+:\d+\): argc=\d+ (.*)')
ARG_RE = re.compile(r'a\d+="([^"]*)"')

AI_TOOLS = ("ollama", "llama-server", "lm-studio", "llamafile", "gpt4all",
            "localai", "whisper", "jan", "text-generation-webui")


def ts(epoch):
    return datetime.datetime.fromtimestamp(
        int(epoch), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def rule(title):
    print(f"\n\033[1m== {title} \033[0m".ljust(88, "="))


def audit_execve(root):
    """Yield (epoch, [argv]) for every EXECVE in the collected audit logs."""
    for path in sorted(glob.glob(os.path.join(root, "var/log/audit/audit.log*"))):
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                m = EXEC_RE.search(line)
                if m:
                    yield int(m.group(1)), ARG_RE.findall(m.group(2))


def q1_identify_tool(root):
    rule("Q1  what AI tool was installed")
    hits = [(e, a) for e, a in audit_execve(root)
            if any(t in " ".join(a).lower() for t in AI_TOOLS)]
    # Collapse to one line per distinct (program, verb): the installer and the
    # GPU probe fire dozens of near-identical execs and drown out the signal.
    seen = set()
    for epoch, argv in sorted(hits):
        prog = os.path.basename(argv[0]) if argv else "?"
        verb = argv[1] if len(argv) > 1 else ""
        if prog in ("sudo", "install", "id", "usermod", "useradd", "tee"):
            continue
        key = (prog, verb.split("=")[0][:24])
        if key in seen:
            continue
        seen.add(key)
        print(f"  {ts(epoch)}  {' '.join(argv)[:88]}")

    for rel, label in (("system_info/running_services.txt", "service"),
                       ("system_info/network_sockets.txt", "socket")):
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            continue
        for line in open(path, errors="replace"):
            if any(t in line.lower() for t in AI_TOOLS):
                print(f"  [{label}] {line.strip()[:96]}")


def q2_prompt_history(root):
    rule("Q2  what it was used for  (~/.ollama/history)")
    for path in glob.glob(os.path.join(root, "home/*/.ollama/history")):
        lines = [l.rstrip("\n") for l in open(path, errors="replace")]
        print(f"  {path}  ({len(lines)} prompts)\n")
        scored = []
        for n, line in enumerate(lines, 1):
            low = line.lower()
            score = sum(w for k, w in SUSPICIOUS.items() if k in low)
            if score:
                scored.append((score, n, line))
        for score, n, line in sorted(scored, key=lambda x: x[1]):
            print(f"    line {n:>3}  [score {score:>2}]  {line}")
        secret = [l for _, _, l in scored if "use the password" in l.lower()]
        if secret:
            print(f"\n  >> passphrase dictated in cleartext: "
                  f"{secret[0].split('password', 1)[1].strip()}")


def q3_deleted_script(root):
    rule("Q3a  GNOME Trash, ranked by deletion date (newest first)")
    info_dir = glob.glob(os.path.join(root, "home/*/.local/share/Trash/info"))
    for d in info_dir:
        rows = []
        for f in os.listdir(d):
            body = open(os.path.join(d, f), errors="replace").read()
            orig = re.search(r"Path=(.*)", body)
            when = re.search(r"DeletionDate=(.*)", body)
            if orig and when:
                # trashinfo dates are not reliably zero-padded, so parse the
                # fields rather than sorting the strings.
                raw = when.group(1).strip()
                bits = [int(x) for x in re.findall(r"\d+", raw)]
                key = tuple(bits + [0] * (6 - len(bits)))[:6]
                rows.append((key, raw, orig.group(1).strip(),
                             f[:-len(".trashinfo")]))
        rows.sort(reverse=True)
        buckets = collections.Counter("%04d-%02d" % r[0][:2] for r in rows)
        print(f"  {len(rows)} trashed items, by month: "
              f"{', '.join(f'{k}×{v}' for k, v in sorted(buckets.items()))}")
        print("  newest 3:")
        for _key, when, orig, name in rows[:3]:
            files = os.path.join(os.path.dirname(d), "files", name)
            size = os.path.getsize(files) if os.path.exists(files) else "?"
            print(f"    {when}  {orig}  ({size} B)")
        if len(buckets) > 1:
            print("\n  >> a single item sits a year after every other deletion "
                  "— that is the one to read")


def q3_find_archive(root):
    rule("Q3b  encrypted archives hidden in the user profile")
    plain = []
    for dirpath, _dirs, files in os.walk(os.path.join(root, "home")):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as fh:
                    if fh.read(4) != b"PK\x03\x04":
                        continue
                    fh.seek(0)
                    blob = fh.read()
            except OSError:
                continue
            try:
                z = AESZipReader(p)
            except Exception:                       # truncated / not a real zip
                continue
            enc = [m for m in z.members if m.strength]
            rel = os.path.relpath(p, root)
            if not enc:
                # Almost all of these are cached wheels under ~/.cache/pip.
                # Not the archive we want, but the package names matter later.
                dist = next((m.name.split("/")[0] for m in z.members
                             if m.name.endswith(".dist-info/METADATA")), "?")
                plain.append((rel, dist, len(blob)))
                continue
            print(f"  {rel}  ({len(blob)} B, {len(z.members)} members)"
                  f"  <-- WinZip-AES ENCRYPTED")
            for m in z.members:
                bits = f"AES-{_KEY_LEN[m.strength] * 8}" if m.strength else "store"
                stamp = "%04d-%02d-%02d %02d:%02d:%02d" % m.date_time
                print(f"      {m.name:26} {m.uncomp_size:>8} B  {bits:<8} {stamp}")

    if plain:
        names = sorted({d for _, d, _ in plain if d != "?"})
        print(f"\n  {len(plain)} other zip-shaped files (pip's wheel cache), packages:")
        print(f"    {', '.join(names)}")
        print("  >> pyzipper in the pip cache is the corroboration: the library "
              "the LLM\n     was asked about really was fetched onto this host")


def timeline(root):
    rule("incident timeline (UTC, from the audit log)")
    keys = ("ollama pull", "ollama run", "ollama list", "-m venv",
            "cache_mgr", "internal_api_keys", "Trash", ".ollama/history",
            "if=/dev/urandom", "collect_final", "pip3")
    rows = []
    for epoch, argv in audit_execve(root):
        joined = " ".join(argv)
        if any(k in joined for k in keys):
            rows.append((epoch, joined[:100]))
    seen = set()
    for epoch, joined in sorted(rows):
        if joined in seen:
            continue
        seen.add(joined)
        print(f"  {ts(epoch)}  {joined}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="extracted whisper_evidence/ directory")
    args = ap.parse_args()
    if not os.path.isdir(args.root):
        sys.exit(f"not a directory: {args.root}")
    q1_identify_tool(args.root)
    q2_prompt_history(args.root)
    q3_deleted_script(args.root)
    q3_find_archive(args.root)
    timeline(args.root)


if __name__ == "__main__":
    main()


