"""Parity vectors + fixtures for the `zeek_extra` family
(byakugan/mappings/zeek_extra.py — smtp.log → email and files.log → file, and
its two gates).

zeek_is_smtp_message is
    any(rec.get(k) for k in ("mailfrom", "rcptto", "from", "to", "subject"))
— an SMTP row maps ONLY when it carries actual message content. A STARTTLS
session exposes none of that (it is encrypted), so it stays raw rather than
assert a phantom `deliver` with no recipient. `any()` is per-element Python
truthiness, so an empty string / empty list / 0 / False does NOT count as
content, while "-" does.

zeek_is_file is `bool(rec.get("fuid"))`.

The seams the fixtures pin beyond the gates:
  * src_address = first("mailfrom", "from") and dest_address =
    first("rcptto", "to") — the ENVELOPE wins over the forgeable header, and
    `first` skips BLANKS ("", "-", None), so a blanked envelope falls through
    to the header value.
  * src_domain = domain_of(first("mailfrom", "from")) — a NESTED marker
    source. domain_of splits at the first '@' then at '/', and lowercases;
    it does NOT strip a trailing '>' , so a display-name header
    ("A <a@evil.com>") yields "evil.com>" — the Python behaviour, warts and
    all.
  * "from" is both a props key and a record key (a Python keyword as a field
    name); the fixtures carry it literally.
  * zeek_files guid is a ONE-element fields-guid {"fields": ["fuid"]}, so it
    renders "file-<fuid>" — and "-" is a legitimate component ("file--")
    while None voids it.
  * extension = ext("filename") — ntpath.splitext of the basename, dot
    stripped, LOWERCASED; file_name is the raw `filename` (honestly null when
    the wire never named the file).

    python tests/parity/genf/zeek_extra.py

Writes ONLY:
    go/internal/predicates/testdata/predicate_vectors/zeek_extra.json
    tests/parity/fixtures/zeek_extra_smtp/
    tests/parity/fixtures/zeek_extra_files/
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _lib  # noqa: E402

FAMILY = "zeek_extra"

# ---------------------------------------------------------------------------
# predicate vectors
# ---------------------------------------------------------------------------
# the STARTTLS row from tests/test_car_zeek_extra.py — content-less on purpose
_STARTTLS = {"ts": 1341856306.0, "uid": "Cs", "trans_depth": 1,
             "id.orig_h": "10.0.0.5", "id.resp_h": "1.2.3.4",
             "helo": "mail", "tls": True, "last_reply": "220 ready"}

PREDICATE_CASES = [
    # --- zeek_is_smtp_message: one case per scanned key, in tuple order -----
    ("zeek_is_smtp_message", dict(_STARTTLS)),                      # STARTTLS -> raw
    ("zeek_is_smtp_message", dict(_STARTTLS, mailfrom="a@evil.com",
                                  rcptto="v@corp.com", subject="hi",
                                  **{"from": "A <a@evil.com>", "to": "v@corp.com"})),
    ("zeek_is_smtp_message", {"mailfrom": "a@evil.com"}),
    ("zeek_is_smtp_message", {"rcptto": "v@corp.com"}),
    ("zeek_is_smtp_message", {"from": "A <a@evil.com>"}),
    ("zeek_is_smtp_message", {"to": "v@corp.com"}),
    ("zeek_is_smtp_message", {"subject": "hi"}),
    ("zeek_is_smtp_message", {}),
    # every scanned key present but FALSY -> no content
    ("zeek_is_smtp_message", {"mailfrom": "", "rcptto": "", "from": "",
                              "to": "", "subject": ""}),
    ("zeek_is_smtp_message", {"mailfrom": None, "rcptto": None, "from": None,
                              "to": None, "subject": None}),
    ("zeek_is_smtp_message", {"mailfrom": [], "rcptto": [], "from": 0,
                              "to": False, "subject": 0.0}),
    # "-" is a NON-EMPTY string: content, per plain truthiness
    ("zeek_is_smtp_message", {"mailfrom": "-"}),
    ("zeek_is_smtp_message", {"subject": " "}),
    # rcptto as a LIST (Zeek emits a set for the recipients)
    ("zeek_is_smtp_message", {"rcptto": ["v@corp.com", "w@corp.com"]}),
    ("zeek_is_smtp_message", {"rcptto": []}),
    # a blank envelope with a present header still counts (the `to` element)
    ("zeek_is_smtp_message", {"mailfrom": "", "rcptto": "", "to": "v@corp.com"}),
    ("zeek_is_smtp_message", {"subject": 0, "to": 1}),
    ("zeek_is_smtp_message", {"Subject": "wrong case"}),
    # --- zeek_is_file: bool(rec.get("fuid")) --------------------------------
    ("zeek_is_file", {"fuid": "FdEQ", "uid": "Cno6"}),
    ("zeek_is_file", {"fuid": "-"}),               # non-empty str -> TRUE
    ("zeek_is_file", {"fuid": ""}),
    ("zeek_is_file", {"fuid": None}),
    ("zeek_is_file", {}),
    ("zeek_is_file", {"uid": "Cno6"}),             # a flow-only row
    ("zeek_is_file", {"fuid": 0}),
    ("zeek_is_file", {"fuid": 1}),
    ("zeek_is_file", {"fuid": 0.0}),
    ("zeek_is_file", {"fuid": False}),
    ("zeek_is_file", {"fuid": True}),
    ("zeek_is_file", {"fuid": []}),
    ("zeek_is_file", {"fuid": ["FdEQ"]}),
    ("zeek_is_file", {"fuid": {}}),
    ("zeek_is_file", {"FUID": "FdEQ"}),            # wrong-case key: absent
]

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
_SMTP = dict(_STARTTLS, mailfrom="a@evil.com", rcptto="v@corp.com",
             subject="hi", date="Mon, 9 Jul 2012 17:51:46 +0000",
             **{"from": "A <a@evil.com>", "to": "v@corp.com",
                "id.orig_p": 46870, "id.resp_p": 25,
                "path": ["1.2.3.4", "10.0.0.5"], "fuids": ["Fabc"]})

_FILES = {"ts": 1341856306.0, "fuid": "FdEQ", "uid": "Cno6", "source": "HTTP",
          "mime_type": "application/x-dosexec", "seen_bytes": 94208}

j = _lib.j


def main() -> int:
    _lib.write_predicate_vectors(FAMILY, PREDICATE_CASES)

    # --- zeek_smtp: the STARTTLS gate + the envelope-vs-header preference ---
    _lib.write_fixture("zeek_extra_smtp",
                       {"artefacts": ["zeek_smtp"], "host": "cap",
                        "adapter": "none", "input": "input.jsonl"},
                       [j(_STARTTLS) + b"\n",                 # STARTTLS: dropped
                        j(_SMTP) + b"\n",
                        # envelope absent -> the header display values are used,
                        # and domain_of keeps the trailing '>' of "A <a@evil.com>"
                        j({k: v for k, v in dict(_SMTP, uid="Cnoenv").items()
                           if k not in ("mailfrom", "rcptto")}) + b"\n",
                        # BLANK envelope -> `first` skips it, same fall-through
                        j(dict(_SMTP, uid="Cblankenv", mailfrom="-",
                               rcptto="")) + b"\n",
                        j(dict(_SMTP, uid="Cnullenv", mailfrom=None,
                               rcptto=None)) + b"\n",
                        # subject-only content: addresses honestly null
                        j({"ts": 1341856306.0, "uid": "Csubj", "trans_depth": 1,
                           "subject": "just a subject"}) + b"\n",
                        # rcptto as a LIST (Zeek's recipient set)
                        j(dict(_SMTP, uid="Clist",
                               rcptto=["v@corp.com", "w@corp.com"])) + b"\n",
                        # a bare mailfrom with no '@' -> domain_of returns it lowered
                        j(dict(_SMTP, uid="Cnoat", mailfrom="postmaster",
                               **{"from": "postmaster"})) + b"\n",
                        # a UPPERCASE envelope domain -> lowered
                        j(dict(_SMTP, uid="Cupper",
                               mailfrom="A@EVIL.COM")) + b"\n",
                        # --- the fields-guid edges (uid + trans_depth) ------
                        j({k: v for k, v in dict(_SMTP, uid="Cnodepth").items()
                           if k != "trans_depth"}) + b"\n",    # guid voided
                        j(dict(_SMTP, uid="Czerodepth", trans_depth=0)) + b"\n",
                        j(dict(_SMTP, uid="", trans_depth=2)) + b"\n",
                        # --- ts variants ------------------------------------
                        j(dict(_SMTP, uid="Ciso",
                               ts="2012-07-09T17:51:46.593202Z")) + b"\n",
                        j(dict(_SMTP, uid="Cepochstr", ts="1341856306.5")) + b"\n",
                        j({k: v for k, v in dict(_SMTP, uid="Conts").items()
                           if k != "ts"}) + b"\n",
                        # --- all-falsy content: dropped ----------------------
                        j(dict(_STARTTLS, uid="Cfalsy", mailfrom="", rcptto="",
                               subject="", **{"from": "", "to": ""})) + b"\n"])

    # --- zeek_files: fuid + mime, hash lowering, extension ------------------
    _lib.write_fixture("zeek_extra_files",
                       {"artefacts": ["zeek_files"], "host": "cap",
                        "adapter": "none", "input": "input.jsonl"},
                       [j(_FILES) + b"\n",
                        j(dict(_FILES, fuid="FdEQnamed", filename="evil.exe")) + b"\n",
                        # hashes canonicalised to LOWERCASE
                        j(dict(_FILES, fuid="Fhash", filename="payload.DLL",
                               md5="D41D8CD98F00B204E9800998ECF8427E",
                               sha1="DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
                               sha256="E3B0C44298FC1C149AFBF4C8996FB924"
                                      "27AE41E4649B934CA495991B7852B855",
                               total_bytes=94208, is_orig=False,
                               analyzers=["MD5", "SHA1", "SHA256", "PE"])) + b"\n",
                        # extension edges: multi-dot, no ext, dotfile, path
                        j(dict(_FILES, fuid="Ftar", filename="archive.tar.GZ")) + b"\n",
                        j(dict(_FILES, fuid="Fnoext", filename="README")) + b"\n",
                        j(dict(_FILES, fuid="Fdot", filename=".bashrc")) + b"\n",
                        j(dict(_FILES, fuid="Fpath",
                               filename="C:\\Users\\jcloudy\\x.exe")) + b"\n",
                        j(dict(_FILES, fuid="Fposix",
                               filename="/var/tmp/a.bin")) + b"\n",
                        j(dict(_FILES, fuid="Fblankname", filename="-")) + b"\n",
                        j(dict(_FILES, fuid="Femptyname", filename="")) + b"\n",
                        # --- the gate edges ---------------------------------
                        j({k: v for k, v in dict(_FILES).items()
                           if k != "fuid"}) + b"\n",            # dropped
                        j(dict(_FILES, fuid="")) + b"\n",       # dropped
                        j(dict(_FILES, fuid=None)) + b"\n",     # dropped
                        j(dict(_FILES, fuid="-")) + b"\n",      # claims -> "file--"
                        # --- ts variants ------------------------------------
                        j(dict(_FILES, fuid="Fiso",
                               ts="2012-07-09T17:51:46.593202Z")) + b"\n",
                        j(dict(_FILES, fuid="Fepochstr", ts="1341856306.5")) + b"\n",
                        j({k: v for k, v in dict(_FILES, fuid="Fonts").items()
                           if k != "ts"}) + b"\n",
                        # --- sparse: fuid alone; blank mime -----------------
                        j({"fuid": "Fbare"}) + b"\n",
                        j(dict(_FILES, fuid="Fnomime", mime_type="-",
                               source="SMTP", seen_bytes=0,
                               **{"id.orig_h": "10.0.0.5",
                                  "id.resp_h": "1.2.3.4"})) + b"\n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
