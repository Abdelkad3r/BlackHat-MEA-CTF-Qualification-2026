#!/usr/bin/env python3
"""Whisper — derive the archive password and recover the exfiltrated data.

The passphrase the developer dictated to the local LLM is *not* the archive
password. The script the LLM produced (recovered from the GNOME Trash) runs it
through BLAKE2b first:

    ARCHIVE_PASSWORD = blake2b(passphrase, digest_size=32).hexdigest()[:20]

Usage:
    python3 solve.py session.zip [-p PASSPHRASE] [-o OUTDIR]

Stdlib only. WinZip-AES handling lives in wzaes.py.
"""

import argparse
import base64
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wzaes import AESZipReader, _KEY_LEN            # noqa: E402

PASSPHRASE = "Gr33nF0x42!D1amond"                   # from ~/.ollama/history
FLAG_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")


def derive(passphrase: str) -> bytes:
    """Reproduce cache_mgr.py's key derivation, byte for byte."""
    return hashlib.blake2b(
        passphrase.encode(), digest_size=32
    ).hexdigest()[:20].encode()


def hunt_flag(name: str, blob: bytes):
    """Any base64 blob in the recovered data that decodes to a flag."""
    for cand in FLAG_RE.findall(blob):
        try:
            dec = base64.b64decode(cand + b"=" * (-len(cand) % 4), validate=True)
        except Exception:
            continue
        if b"FlagY{" in dec or b"flag{" in dec.lower():
            return cand.decode(), dec.decode("utf-8", "replace")
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("archive", help="path to session.zip")
    ap.add_argument("-p", "--passphrase", default=PASSPHRASE)
    ap.add_argument("-o", "--outdir", default="recovered")
    args = ap.parse_args()

    password = derive(args.passphrase)
    print(f"passphrase      : {args.passphrase}")
    print(f"blake2b-256     : {hashlib.blake2b(args.passphrase.encode(), digest_size=32).hexdigest()}")
    print(f"archive password: {password.decode()}   (first 20 hex chars)\n")

    z = AESZipReader(args.archive)
    os.makedirs(args.outdir, exist_ok=True)

    flag = None
    for m in z.members:
        bits = _KEY_LEN[m.strength] * 8 if m.strength else 0
        blob = z.read(m, password)                  # raises if HMAC/verifier fail
        dest = os.path.join(args.outdir, os.path.basename(m.name))
        with open(dest, "wb") as fh:
            fh.write(blob)
        assert len(blob) == m.uncomp_size, "size mismatch"
        print(f"[ ok ] {m.name:24} AES-{bits}  {len(blob):>7} B  hmac verified  -> {dest}")
        hit = hunt_flag(m.name, blob)
        if hit:
            flag = (m.name,) + hit

    print(f"\n{len(z.members)}/{len(z.members)} members recovered")
    if flag:
        member, b64, plain = flag
        print(f"\nflag found in {member}")
        print(f"  base64 : {b64}")
        print(f"  decoded: {plain}")
    else:
        print("\nno flag located")


if __name__ == "__main__":
    main()
