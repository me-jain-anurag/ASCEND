"""
SSH key fingerprinting, in pure Python.

The credential-reuse chokepoint — the headline claim of the thin slice — rests
on matching a private key found on one host against the authorized_keys files of
other hosts. That match must be a real cryptographic fingerprint comparison, not
a filename or comment guess, or the finding is worthless.

Doing it in Python rather than by shelling out to `ssh-keygen -lf` means the
target hosts need no OpenSSH client installed, and the collector behaves
identically across transports.

Fingerprints are OpenSSH's modern format: SHA256:<base64 of sha256(keyblob)>,
unpadded — byte-identical to what `ssh-keygen -lf` prints.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct

PRIVATE_HEADERS = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)

_OPENSSH_MAGIC = b"openssh-key-v1\x00"


def looks_like_private_key(text: str) -> bool:
    head = text.lstrip()[:200]
    return any(head.startswith(h) for h in PRIVATE_HEADERS)


def fingerprint_blob(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


# ─── SSH wire-format string reader ────────────────────────────────────────────

def _read_string(buf: bytes, offset: int) -> tuple[bytes, int]:
    """Read one uint32-length-prefixed string. Raises ValueError if truncated."""
    if offset + 4 > len(buf):
        raise ValueError("truncated length prefix")
    (length,) = struct.unpack(">I", buf[offset:offset + 4])
    offset += 4
    if offset + length > len(buf):
        raise ValueError("truncated string body")
    return buf[offset:offset + length], offset + length


# ─── Public keys (authorized_keys lines, *.pub files) ─────────────────────────

def parse_public_key_line(line: str) -> dict | None:
    """Parse one authorized_keys / *.pub line.

    Handles leading options (e.g. command="...",no-pty ssh-ed25519 AAAA...) by
    scanning for the first field that base64-decodes into a well-formed key blob
    whose embedded type matches the preceding field.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    fields = line.split()
    for i, field in enumerate(fields[:-1]):
        if not field.startswith(("ssh-", "ecdsa-", "sk-")):
            continue
        b64 = fields[i + 1]
        try:
            blob = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            keytype, _ = _read_string(blob, 0)
        except ValueError:
            continue
        if keytype.decode("ascii", "replace") != field:
            continue
        return {
            "type": field,
            "fingerprint": fingerprint_blob(blob),
            "bits": _bits_for(field, blob),
            "comment": " ".join(fields[i + 2:]) or None,
            "options": " ".join(fields[:i]) or None,
        }
    return None


def parse_authorized_keys(text: str) -> list[dict]:
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        entry = parse_public_key_line(line)
        if entry:
            entry["line_number"] = lineno
            out.append(entry)
    return out


# ─── Private keys (openssh-key-v1) ────────────────────────────────────────────

def parse_private_key(text: str) -> dict | None:
    """Extract the fingerprint and comment from an OpenSSH v1 private key.

    The openssh-key-v1 container embeds the *public* key blob in clear, even for
    passphrase-protected keys, so the fingerprint is always recoverable. The
    comment lives in the private section and is only readable when the key is
    unencrypted — which is itself a finding worth recording, so `encrypted` is
    returned too.

    Returns None for legacy PEM keys (BEGIN RSA PRIVATE KEY), which carry no
    public blob; those are reported by the caller without a fingerprint.
    """
    if _OPENSSH_MAGIC.decode("latin-1") not in text and "BEGIN OPENSSH" not in text:
        return None

    body = []
    inside = False
    for line in text.splitlines():
        if line.startswith("-----BEGIN"):
            inside = True
            continue
        if line.startswith("-----END"):
            break
        if inside:
            body.append(line.strip())
    try:
        data = base64.b64decode("".join(body), validate=True)
    except (binascii.Error, ValueError):
        return None

    if not data.startswith(_OPENSSH_MAGIC):
        return None

    offset = len(_OPENSSH_MAGIC)
    try:
        ciphername, offset = _read_string(data, offset)
        _kdfname, offset = _read_string(data, offset)
        _kdfopts, offset = _read_string(data, offset)
        if offset + 4 > len(data):
            return None
        (nkeys,) = struct.unpack(">I", data[offset:offset + 4])
        offset += 4
        if nkeys < 1:
            return None
        pubblob, offset = _read_string(data, offset)
        private_section, _ = _read_string(data, offset)
    except ValueError:
        return None

    keytype, _ = _read_string(pubblob, 0)
    encrypted = ciphername not in (b"none", b"")

    result = {
        "type": keytype.decode("ascii", "replace"),
        "fingerprint": fingerprint_blob(pubblob),
        "bits": _bits_for(keytype.decode("ascii", "replace"), pubblob),
        "encrypted": encrypted,
        "comment": None,
    }
    if not encrypted:
        result["comment"] = _comment_from_private_section(private_section)
    return result


def _comment_from_private_section(section: bytes) -> str | None:
    """The comment is the last wire-format string before the padding.

    Field layout differs per key type (ed25519 has 2 key strings, RSA has 6), so
    rather than special-case each type we strip the trailing 1,2,3,... padding
    and read strings forward; the final one is always the comment.
    """
    # Strip the incrementing pad bytes OpenSSH appends to reach the block size.
    end = len(section)
    expected = section[end - 1] if end else 0
    while end > 0 and 0 < section[end - 1] <= 8 and section[end - 1] == expected:
        end -= 1
        expected -= 1
    section = section[:end]

    offset = 8  # skip the two uint32 check values
    last: bytes | None = None
    while offset < len(section):
        try:
            value, offset = _read_string(section, offset)
        except ValueError:
            break
        last = value
    if last is None:
        return None
    try:
        return last.decode("utf-8").strip() or None
    except UnicodeDecodeError:
        return None


def _bits_for(keytype: str, blob: bytes) -> int | None:
    if "ed25519" in keytype:
        return 256
    if keytype.startswith("ssh-rsa"):
        try:
            _type, off = _read_string(blob, 0)
            _e, off = _read_string(blob, off)
            n, _ = _read_string(blob, off)
            n = n.lstrip(b"\x00")
            return len(n) * 8
        except ValueError:
            return None
    if "nistp256" in keytype:
        return 256
    if "nistp384" in keytype:
        return 384
    if "nistp521" in keytype:
        return 521
    return None
