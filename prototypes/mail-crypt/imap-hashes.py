#!/usr/bin/env python3
"""IMAP helper of prototype #4: build the commands, parse the transcript.

Usage (python3 -I imap-hashes.py ...):
  cmd MAILBOX [UID]        print the IMAP commands for `doveadm exec imap`:
                           SELECT, then UID FETCH 1:* (UID FLAGS RFC822.SIZE
                           BODY.PEEK[]) or, with UID, UID FETCH UID (UID BODY.PEEK[]),
                           then LOGOUT. MAILBOX is UTF-8; it is sent as
                           modified UTF-7, quoted.
  parse MAILBOX            read the transcript on stdin and print one TSV line
                           per message: mailbox, uid, sha256, rfc822.size, flags
                           (sorted, \\Recent dropped, "-" if none). Exits 1 on a
                           NO/BAD/BYE answer, a parse error or a body whose length
                           differs from RFC822.SIZE; the reason goes to stderr.
  single MAILBOX UID SHA   read the transcript of a `cmd MAILBOX UID` session on
                           stdin and print: mailbox, uid, result, sha256,
                           first 4 bytes (hex), announced literal size, bytes
                           received, reason. result is "same" if a complete body
                           with the given SHA came back, else "differs". Never
                           fails on the transcript (counter-proofs expect errors).

It reads literals by their byte count and hashes the bytes IMAP sends,
without any conversion.

\\Recent is dropped because Dovecot 2.3 and 2.4.5 both set it only for the
first session that sees a message, so it depends on which version reads
first, not on the stored data.
"""
import base64
import hashlib
import sys


class ParseError(Exception):
    pass


def mutf7(name):
    """RFC 3501 modified UTF-7."""
    out = []
    buf = []

    def flush():
        if buf:
            raw = "".join(buf).encode("utf-16-be")
            enc = base64.b64encode(raw).decode("ascii").rstrip("=").replace("/", ",")
            out.append("&" + enc + "-")
            buf.clear()

    for ch in name:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cmd(mailbox, uid=None):
    box = quote(mutf7(mailbox))
    if uid is None:
        fetch = "b UID FETCH 1:* (UID FLAGS RFC822.SIZE BODY.PEEK[])"
    else:
        fetch = f"b UID FETCH {int(uid)} (UID BODY.PEEK[])"
    sys.stdout.write(f"a SELECT {box}\r\n{fetch}\r\nc LOGOUT\r\n")


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def eof(self):
        return self.p >= len(self.d)

    def line(self):
        end = self.d.find(b"\r\n", self.p)
        if end < 0:
            end = self.d.find(b"\n", self.p)
            if end < 0:
                raise ParseError(f"no line end at offset {self.p}")
            ln = self.d[self.p:end]
            self.p = end + 1
            return ln
        ln = self.d[self.p:end]
        self.p = end + 2
        return ln

    def expect(self, b):
        if not self.d.startswith(b, self.p):
            raise ParseError(f"expected {b!r} at offset {self.p}, got {self.d[self.p:self.p + 20]!r}")
        self.p += len(b)

    def skip_spaces(self):
        while self.p < len(self.d) and self.d[self.p:self.p + 1] == b" ":
            self.p += 1

    def value(self):
        """atom, quoted string, literal or parenthesized list."""
        self.skip_spaces()
        c = self.d[self.p:self.p + 1]
        if c == b"(":
            self.p += 1
            items = []
            while True:
                self.skip_spaces()
                if self.d[self.p:self.p + 1] == b")":
                    self.p += 1
                    return items
                if self.eof():
                    raise ParseError("unterminated list")
                items.append(self.value())
        if c == b'"':
            self.p += 1
            out = bytearray()
            while True:
                if self.eof():
                    raise ParseError("unterminated string")
                ch = self.d[self.p:self.p + 1]
                self.p += 1
                if ch == b"\\":
                    out += self.d[self.p:self.p + 1]
                    self.p += 1
                elif ch == b'"':
                    return bytes(out)
                else:
                    out += ch
        if c in (b"{", b"~"):
            if c == b"~":
                self.p += 1
            end = self.d.find(b"}\r\n", self.p)
            if end < 0:
                raise ParseError("bad literal header")
            n = int(self.d[self.p + 1:end].rstrip(b"+"))
            self.p = end + 3
            body = self.d[self.p:self.p + n]
            self.p += n
            if len(body) != n:
                raise Truncated(n, body)
            return Literal(body)
        start = self.p
        depth = 0
        while not self.eof():
            ch = self.d[self.p:self.p + 1]
            if ch == b"[":
                depth += 1
            elif ch == b"]":
                depth -= 1
            elif depth == 0 and ch in (b" ", b")", b"(", b"\r", b"\n"):
                break
            self.p += 1
        if self.p == start:
            raise ParseError(f"empty atom at offset {self.p}")
        return self.d[start:self.p]


class Literal(bytes):
    pass


class Truncated(ParseError):
    def __init__(self, n, body):
        super().__init__(f"literal announced {n} bytes, received {len(body)}")
        self.n = n
        self.body = body


def read_session(data):
    """Return (fetches, tagged, errors). fetches: list of dicts."""
    r = Reader(data)
    fetches = []
    tagged = {}
    errors = []
    while not r.eof():
        start = r.p
        if r.d.startswith(b"* ", r.p):
            # untagged: maybe "* n FETCH ("
            rest_end = r.d.find(b" ", r.p + 2)
            word = r.d[r.p + 2:rest_end] if rest_end > 0 else b""
            if word.isdigit() and r.d.startswith(b" FETCH ", rest_end):
                r.p = rest_end + len(b" FETCH ")
                items = r.value()
                r.line()  # rest of line (CRLF)
                f = {}
                for i in range(0, len(items) - 1, 2):
                    f[bytes(items[i]).upper()] = items[i + 1]
                fetches.append(f)
                continue
            ln = r.line()
            if ln.startswith(b"* BYE") and not ln.startswith(b"* BYE Logging out"):
                errors.append(ln.decode("utf-8", "replace"))
            continue
        ln = r.line()
        parts = ln.split(b" ", 2)
        if len(parts) >= 2 and parts[0] in (b"a", b"b", b"c"):
            tagged[parts[0].decode()] = ln.decode("utf-8", "replace")
            if parts[1] != b"OK":
                errors.append(ln.decode("utf-8", "replace"))
        elif ln.strip():
            # stray stderr line (log) mixed in: keep for the reason
            if b"Error" in ln or b"Panic" in ln or b"Fatal" in ln:
                errors.append(ln.decode("utf-8", "replace"))
        if r.p == start:
            raise ParseError("no progress")
    return fetches, tagged, errors


def flags_str(v):
    fl = sorted(bytes(x).decode() for x in v if bytes(x) != b"\\Recent")
    return " ".join(fl) if fl else "-"


def parse(mailbox):
    data = sys.stdin.buffer.read()
    try:
        fetches, tagged, errors = read_session(data)
    except ParseError as e:
        print(f"parse error: {e}", file=sys.stderr)
        sys.exit(1)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)
    for t in ("a", "b", "c"):
        if t not in tagged:
            print(f"no tagged answer for {t}", file=sys.stderr)
            sys.exit(1)
    rows = []
    for f in fetches:
        if b"BODY[]" not in f:
            continue
        body = bytes(f[b"BODY[]"])
        size = int(f[b"RFC822.SIZE"])
        if len(body) != size:
            print(f"UID {int(f[b'UID'])}: body {len(body)} bytes, RFC822.SIZE {size}", file=sys.stderr)
            sys.exit(1)
        rows.append((int(f[b"UID"]), hashlib.sha256(body).hexdigest(), size, flags_str(f[b"FLAGS"])))
    for uid, sha, size, fl in sorted(rows):
        print(f"{mailbox}\t{uid}\t{sha}\t{size}\t{fl}")


def single(mailbox, uid, want):
    data = sys.stdin.buffer.read()
    sha, first, announced, received, reason = "-", "-", "-", "-", ""
    body = None
    try:
        fetches, tagged, errors = read_session(data)
        for f in fetches:
            if b"BODY[]" in f:
                body = bytes(f[b"BODY[]"])
                announced = received = str(len(body))
        if errors:
            reason = errors[0]
        elif body is None:
            reason = "no BODY[] returned"
    except Truncated as e:
        body = e.body
        announced, received = str(e.n), str(len(e.body))
        reason = str(e)
    except ParseError as e:
        reason = f"parse error: {e}"
    if body is not None:
        sha = hashlib.sha256(body).hexdigest()
        first = body[:4].hex() or "-"
    result = "same" if (sha == want and not reason) else "differs"
    reason = reason.replace("\t", " ") or "-"
    print("\t".join([mailbox, str(uid), result, sha, first, announced, received, reason]))


def main():
    a = sys.argv[1:]
    if len(a) in (2, 3) and a[0] == "cmd":
        cmd(*a[1:])
    elif len(a) == 2 and a[0] == "parse":
        parse(a[1])
    elif len(a) == 4 and a[0] == "single":
        single(a[1], a[2], a[3])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
