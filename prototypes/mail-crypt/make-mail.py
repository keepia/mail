#!/usr/bin/env python3
"""Write the synthetic test messages of prototype #4 and their reference hashes.

Usage: python3 -I make-mail.py OUTDIR

Writes OUTDIR/pNN.eml for every message and OUTDIR/src.tsv with one line per
message: id, mailbox, variant, sha256, size, phase, dir23.
- sha256 and size are those of the message as IMAP sends it: bare LF turned
  into CRLF, existing CRLF kept.
- variant says how Dovecot 2.3 (phase A) or 2.4 (phase C) stores it.
- dir23 is the maildir++ directory 2.3's listescape plugin uses ("." = INBOX).

Deterministic: no clock, no randomness. Larger content comes from a sha256
counter. Only synthetic addresses at example.test.
"""
import base64
import hashlib
import os
import sys

DATE = "Wed, 11 Nov 2026 12:00:00 +0000"

# id, mailbox, variant, phase, dir23, kind
MESSAGES = [
    ("p01", "INBOX", "plain", "A", ".", "text"),
    ("p02", "INBOX", "crypt", "A", ".", "text"),
    ("p03", "INBOX", "crypt+gz", "A", ".", "text"),
    ("p04", "INBOX", "crypt+zstd", "A", ".", "text"),
    ("p05", "INBOX", "crypt+lz4", "A", ".", "utf8"),
    ("p06", "INBOX", "crypt+lz4", "A", ".", "crlf"),
    ("p07", "INBOX", "crypt+lz4", "A", ".", "attachment"),
    ("p08", "INBOX", "crypt+lz4", "A", ".", "big"),
    ("p09", "Archiv/2025", "crypt+lz4", "A", ".Archiv.2025", "text"),
    ("p10", "a.b", "crypt+lz4", "A", ".a\\2eb", "text"),
    ("p11", "~tilde", "crypt+lz4", "A", ".\\7etilde", "text"),
    ("p12", "x/~y", "crypt+lz4", "A", ".x.\\7ey", "text"),
    ("p13", "back\\slash", "crypt+lz4", "A", ".back\\5cslash", "text"),
    ("p14", "Entwürfe", "crypt+lz4", "A", ".Entw&APw-rfe", "text"),
    ("p15", "Sent & Co", "crypt+lz4", "A", ".Sent &- Co", "text"),
    ("p20", "INBOX", "crypt+lz4", "C", ".", "text"),
    ("p21", "Archiv/2025", "crypt+lz4", "C", ".Archiv.2025", "text"),
]


def stream(label, n):
    """n deterministic bytes from sha256(label || counter)."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{label}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def header(mid, subject, extra=""):
    return (
        f"From: Sender <sender@example.test>\n"
        f"To: Alice <alice@example.test>\n"
        f"Subject: {subject}\n"
        f"Date: {DATE}\n"
        f"Message-ID: <{mid}@example.test>\n"
        f"MIME-Version: 1.0\n"
        f"{extra}"
    )


def build(mid, mailbox, variant, kind):
    subject = f"proto4 {mid} {variant}"
    if kind == "text":
        body = "".join(
            f"Line {i} of synthetic message {mid} ({variant}).\n"
            for i in range(1, 41)
        )
        msg = header(mid, subject, "Content-Type: text/plain; charset=us-ascii\n") + "\n" + body
        return msg.encode("ascii")
    if kind == "utf8":
        body = "".join(
            f"Zeile {i}: Grüße aus Köln, ½ € für Ærøskøbing, 日本語 テキスト.\n"
            for i in range(1, 41)
        )
        msg = header(
            mid,
            subject,
            "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n",
        ) + "\n" + body
        return msg.encode("utf-8")
    if kind == "crlf":
        body = "".join(f"CRLF line {i} of {mid}.\n" for i in range(1, 41))
        msg = header(mid, subject, "Content-Type: text/plain; charset=us-ascii\n") + "\n" + body
        return msg.replace("\n", "\r\n").encode("ascii")
    if kind == "attachment":
        raw = stream(f"{mid}-attachment", 300 * 1024)
        b64 = base64.encodebytes(raw).decode("ascii")
        msg = (
            header(mid, subject, 'Content-Type: multipart/mixed; boundary="proto4-boundary"\n')
            + "\n"
            + "--proto4-boundary\n"
            + "Content-Type: text/plain; charset=us-ascii\n\n"
            + "Message with a 300 KiB binary attachment.\n\n"
            + "--proto4-boundary\n"
            + 'Content-Type: application/octet-stream; name="data.bin"\n'
            + "Content-Transfer-Encoding: base64\n"
            + 'Content-Disposition: attachment; filename="data.bin"\n\n'
            + b64
            + "--proto4-boundary--\n"
        )
        return msg.encode("ascii")
    if kind == "big":
        lines = []
        size = 0
        i = 0
        while size < 2 * 1024 * 1024:
            line = hashlib.sha256(f"{mid}-line:{i}".encode()).hexdigest() + "\n"
            lines.append(line)
            size += len(line)
            i += 1
        msg = header(mid, subject, "Content-Type: text/plain; charset=us-ascii\n") + "\n" + "".join(lines)
        return msg.encode("ascii")
    raise ValueError(kind)


def crlf(data):
    return data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: make-mail.py OUTDIR")
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    rows = []
    for mid, mailbox, variant, phase, dir23, kind in MESSAGES:
        data = build(mid, mailbox, variant, kind)
        with open(os.path.join(out, f"{mid}.eml"), "wb") as f:
            f.write(data)
        wire = crlf(data)
        rows.append(
            "\t".join(
                [mid, mailbox, variant, hashlib.sha256(wire).hexdigest(), str(len(wire)), phase, dir23]
            )
        )
    with open(os.path.join(out, "src.tsv"), "w", encoding="utf-8") as f:
        f.write("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
