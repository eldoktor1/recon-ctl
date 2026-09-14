#!/usr/bin/env python3
"""Print the signing certificate of an APK: SHA-256 fingerprint, then subject.

WHY THIS IS NOT keytool. Modern Play-distributed APKs are signed with scheme v2/v3 only and carry
no META-INF/*.RSA block, so keytool has nothing to read and reports the app as unsigned. The signer
certificate lives in the APK Signing Block, between the last local file entry and the central
directory. This parses that block.

WHY IT MATTERS AT ALL. The APK comes from a public mirror, not from the vendor, so a package-name
match is not proof of origin - the same rule the bucket lane learned from the global S3 namespace.
The archive itself carries the proof. A signer that CHANGES between versions means either a key
rotation or a repack, and mining a repack teaches us nothing about the real app.

Usage: apk_signer.py <apk> [<apk> ...]
       one line per distinct certificate: "<sha256>  <subject>"
"""
import hashlib
import struct
import subprocess
import sys

MAGIC = b"APK Sig Block 42"
# v3/v3.1 rotate keys and carry the same certificate structure as v2 in their signed data.
SCHEMES = {0x7109871A: "v2", 0xF05368C0: "v3", 0x1B93AD61: "v3.1"}


def _seq(buf):
    """Split a length-prefixed sequence (uint32 length, then that many bytes, repeated)."""
    out, p = [], 0
    while p + 4 <= len(buf):
        n = struct.unpack_from("<I", buf, p)[0]
        out.append(buf[p + 4:p + 4 + n])
        p += 4 + n
    return out


def certificates(path):
    data = open(path, "rb").read()
    i = data.rfind(MAGIC)
    if i < 0:
        return []
    size = struct.unpack_from("<Q", data, i - 8)[0]
    start = i - 8 - (size - 24) - 8
    if start < 0:
        return []
    block = data[start + 8:i - 8]
    found, off = [], 0
    while off + 12 <= len(block):
        length = struct.unpack_from("<Q", block, off)[0]
        pair_id = struct.unpack_from("<I", block, off + 8)[0]
        value = block[off + 12:off + 8 + length]
        off += 8 + length
        if pair_id not in SCHEMES or length <= 4:
            continue
        for signer in _seq(value[4:]):
            parts = _seq(signer)
            if not parts:
                continue
            inner = _seq(parts[0])          # signed data: [digests][certificates][...]
            if len(inner) < 2:
                continue
            for der in _seq(inner[1]):
                if der[:1] == b"\x30":      # DER SEQUENCE - an X.509 certificate
                    found.append(der)
    return found


def subject(der):
    """openssl is used rather than a python x509 library so the lane has no extra dependency."""
    try:
        p = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject"],
                           input=der, capture_output=True, timeout=20)
        return p.stdout.decode(errors="replace").strip().replace("subject=", "").strip()
    except Exception:
        return "?"


def main():
    rc = 1
    for path in sys.argv[1:]:
        seen = set()
        for der in certificates(path):
            fp = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
            if fp in seen:
                continue
            seen.add(fp)
            print(f"{fp}  {subject(der)}")
            rc = 0
        if not seen:
            print(f"NO-SIGNING-BLOCK  {path}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
