#!/usr/bin/env python3
"""Decrypt files encrypted by the Qfact ransomware HTA.

Recovered scheme (see ../README.md):

    key = UTF8("Fx7mK9vL2nQ4wPz!".PadRight(32)[:32])     # 16 chars + 16 spaces
    iv  = MD5(UTF8($env:COMPUTERNAME + $env:USERNAME))
    AES-256-CBC / PKCS#7

The dropper sets `$a.Mode=0`, which is not a valid .NET CipherMode. The setter
throws, `$ErrorActionPreference='SilentlyContinue'` swallows it, and the object
keeps its default -- CBC. Treating it as ECB will not decrypt.

Usage:
    python3 decrypt_files.py EncryptedFiles/ -o decrypted/ \
        --computername DESKTOP-KLPAT9O --username jmartin
"""
import argparse
import hashlib
import pathlib
import sys

from miniaes import aes_cbc_decrypt

PASSPHRASE = "Fx7mK9vL2nQ4wPz!"


def derive(computername, username, passphrase=PASSPHRASE):
    key = passphrase.ljust(32)[:32].encode("utf-8")
    iv = hashlib.md5(f"{computername}{username}".encode("utf-8")).digest()
    return key, iv


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("indir", type=pathlib.Path, help="directory holding *.enc files")
    ap.add_argument("-o", "--outdir", type=pathlib.Path, default=pathlib.Path("decrypted"))
    ap.add_argument("--computername", default="DESKTOP-KLPAT9O")
    ap.add_argument("--username", default="jmartin")
    ap.add_argument("--passphrase", default=PASSPHRASE)
    args = ap.parse_args()

    key, iv = derive(args.computername, args.username, args.passphrase)
    print(f"key (hex) : {key.hex()}")
    print(f"iv  (hex) : {iv.hex()}   <- MD5('{args.computername}{args.username}')")
    print()

    enc_files = sorted(args.indir.rglob("*.enc"))
    if not enc_files:
        sys.exit(f"no *.enc files under {args.indir}")

    failures = 0
    for src in enc_files:
        rel = src.relative_to(args.indir)
        dst = args.outdir / rel.with_suffix("")       # strip the .enc
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            plain = aes_cbc_decrypt(key, iv, src.read_bytes())
        except ValueError as exc:
            print(f"[FAIL] {rel}: {exc}")
            failures += 1
            continue
        dst.write_bytes(plain)
        print(f"[ ok ] {rel}  ->  {dst}  ({len(plain)} bytes)")

    print()
    print(f"{len(enc_files) - failures}/{len(enc_files)} files recovered")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
