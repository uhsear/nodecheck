#!/usr/bin/env python
"""Install-time prerequisites from a node table, reported UNVERIFIED, never PASS.

A node passes setup while the wrong ODBC driver, a deprecated linked-server
provider, a plaintext password in a compiled DSC MOF or a missing licence waits
to fail. The usual prerequisite sweep is a script with the topology typed into
it. It probes each node, and a probe that throws is read as "absent" or is left
out of the summary, so the last line says every checked item is fine while
half the items were never checked.

This tool splits the sweep in two. A node table (JSON) says what each node
requires. A facts file (JSON) records what a node was observed to have, and
when. The check compares the two and gives each requirement one of three
verdicts:

    FAIL        the facts show the requirement is not met
    UNVERIFIED  no usable fact: missing, stale, failed, conflicting or of the
                wrong shape
    OBSERVED    the fact met the requirement when it was gathered

There is no PASS. OBSERVED is evidence about one moment, not a promise that
the install will work.

    python nodecheck.py --self-test
    python nodecheck.py example > nodes.json
    python nodecheck.py gather nodes.json --node node-a
    python nodecheck.py gather nodes.json --node node-a --out facts/node-a.json --apply
    python nodecheck.py check nodes.json
    python nodecheck.py check nodes.json --node node-a
    python nodecheck.py mof dsc/node-a.mof dsc/node-b.mof

Nothing is written without --apply, and only gather --out writes. It creates
the folder, and it replaces an existing file only if that file is a nodecheck
facts file.

THE NODE TABLE (JSON, UTF-8 or UTF-16 with a byte order mark). The example
command prints a complete one. A key the format does not name is refused, so a
misspelt "requires" cannot drop checks. A key that appears twice is refused.

    format         "nodecheck/1". Required.
    max_age_hours  A positive number. Optional, default 24. A facts file older
                   than this, or dated more than 5 minutes ahead, is not used.
    roles          Optional. Role name -> list of requirements.
    nodes          Required, non-empty. Each node has:
        name       Required, unique.
        roles      Optional list of role names. Their requirements join the
                   node's own. A repeated requirement counts once.
        facts      A path or a list of paths to facts files, relative to the
                   table's folder. Optional, but a node with none is UNVERIFIED.
        requires   Optional list of requirements.
    note           Optional text, on the table or on a node. Ignored.

A requirement is {"fact": KEY, "op": OP, "value": V, "why": TEXT}. The why is
optional. OP is one of:

    ==         the fact equals V (string, number or boolean; a boolean never
               equals a number)
    >=         the fact is a number and is at least V
    version>=  the fact is a dotted version and is at least V (18.3 = 18.3.0)
    contains   the fact is a list that holds V
    excludes   the fact is a list that holds none of V (V is a list)
    in         the fact is one of V (V is a list)

A fact KEY names what to observe. gather has a collector for these keys only:

    tcp:HOST:PORT      true if a connection opens, false if it is refused.
                       Anything else (timeout, no route) is an error.
    disk_free_gb:PATH  free GiB at PATH, cut down to 0.1.
    odbc_drivers       list of installed ODBC drivers (Windows, 64-bit view).
    mof:PATH           ENCRYPTED, PLAINTEXT or NO_MSFT_CREDENTIAL for a
                       compiled DSC MOF, PATH relative to the table. A MOF
                       that is UNVERIFIED is an error.
    os.system, os.release, os.version, os.machine   text from platform.

Any other key is supplied by hand. gather records "no collector for this fact"
under errors and exits 3. To supply the value, edit the gathered file: delete
the key under errors and add it under facts. Do not put it in a second file,
because a value in one file and an error in another file conflict.

THE FACTS FILE (format "nodecheck-facts/1"), written by gather --apply:

    {"format": "nodecheck-facts/1", "node": "node-a",
     "gathered": "2026-01-31T12:00:00Z", "gathered_on": "host name",
     "facts": {KEY: value}, "errors": {KEY: "why it could not be observed"}}

A requirement is judged on a value in "facts". A key in "errors", a missing
key, a stale file or a file for another node gives UNVERIFIED. Two files that
disagree about one key give UNVERIFIED.

Exit codes: 0 every requirement OBSERVED (mof: every credential encrypted or
none present), 1 at least one FAIL (mof: a plaintext password), 2 a file could
not be read or written, 3 at least one UNVERIFIED and no FAIL (gather: at least
one fact could not be collected), 64 usage or table error.
"""

from __future__ import print_function

import argparse
import base64
import binascii
import contextlib
import datetime
import http.server
import importlib
import importlib.util
import io
import json
import math
import os
import platform
import re
import shutil
import socket
import sys
import tempfile
import threading
import urllib.request

# Only Windows has a registry. Elsewhere the ODBC probe records an error, and
# the requirement that needed it is UNVERIFIED rather than FAIL.
_WINREG = importlib.import_module("winreg") if sys.platform == "win32" else None

# =============================================================================
# CONFIGURATION. Deliberately not flags. Change here, not at the call site.
# =============================================================================

# How old a facts file may be before its facts stop counting. A table can
# override it with "max_age_hours". A day is long enough for a gather in the
# morning and a check in the afternoon, and short enough that last week's
# observation of a node somebody has since rebuilt does not count.
DEFAULT_MAX_AGE_HOURS = 24.0

# A facts file stamped this far in the future is refused. Clocks drift by
# seconds; a file an hour ahead was written on a machine with a wrong clock,
# and its age cannot be trusted.
CLOCK_SKEW_HOURS = 5.0 / 60.0

# Seconds a TCP probe waits for a connection before it records "closed".
TCP_TIMEOUT = 3.0

# =============================================================================

# What the example command prints. Every name in it is made up. The self-test
# loads it, so it cannot drift away from the format.
EXAMPLE_TABLE = r'''{
  "format": "nodecheck/1",
  "note": "Synthetic example. Every name here is made up.",
  "max_age_hours": 24,
  "roles": {
    "server": [
      {"fact": "os.system", "op": "==", "value": "Windows",
       "why": "the installer is for Windows"},
      {"fact": "odbc_drivers", "op": "contains",
       "value": "ODBC Driver 18 for SQL Server",
       "why": "the connection files name this driver"},
      {"fact": "disk_free_gb:C:\\", "op": ">=", "value": 40},
      {"fact": "tcp:db.example.test:1433", "op": "==", "value": true,
       "why": "the database port answers"}
    ],
    "sql-host": [
      {"fact": "linked_server_providers", "op": "excludes",
       "value": ["SQLNCLI", "SQLNCLI11"],
       "why": "supplied by hand: no collector exists for it"}
    ],
    "authoring": [
      {"fact": "mof:dsc/node-a.mof", "op": "in",
       "value": ["ENCRYPTED", "NO_MSFT_CREDENTIAL"]}
    ]
  },
  "nodes": [
    {"name": "node-a", "roles": ["server", "authoring"],
     "facts": "facts/node-a.json"},
    {"name": "node-b", "roles": ["server", "sql-host"],
     "facts": ["facts/node-b.json", "facts/node-b-authoring.json"],
     "requires": [{"fact": "license_seats", "op": ">=", "value": 4}]}
  ]
}
'''

TABLE_FORMAT = "nodecheck/1"
FACTS_FORMAT = "nodecheck-facts/1"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

FAIL = "FAIL"
UNVERIFIED = "UNVERIFIED"
OBSERVED = "OBSERVED"

OPS = ("==", ">=", "version>=", "contains", "excludes", "in")

TABLE_KEYS = ("format", "max_age_hours", "roles", "nodes", "note")
NODE_KEYS = ("name", "roles", "facts", "requires", "note")
REQ_KEYS = ("fact", "op", "value", "why")

# The keys a collector exists for. Any other fact is supplied by hand in a
# facts file, and gather records it as an error so the gap is visible.
PLATFORM_FACTS = ("os.system", "os.release", "os.version", "os.machine")
ODBC_FACT = "odbc_drivers"

# The registry key whose values list the installed ODBC drivers, each with the
# data "Installed". Microsoft: ODBC Drivers subkey.
ODBC_DRIVERS_KEY = r"SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers"

# mofcheck verdicts.
MOF_ENCRYPTED = "ENCRYPTED"
MOF_PLAINTEXT = "PLAINTEXT"
MOF_NONE = "NO_MSFT_CREDENTIAL"

CMS_BEGIN = "-----BEGIN CMS-----"
CMS_END = "-----END CMS-----"
# DER of OBJECT IDENTIFIER 1.2.840.113549.1.7.3, id-envelopedData (RFC 5652
# section 6.1), without its tag and length.
ENVELOPED_OID = bytes(bytearray([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                                 0x01, 0x07, 0x03]))


class InputError(Exception):
    """A file that exists but cannot be parsed. Exit 2, not 64."""


# ------------------------------------------------------------------ the table

def _is_number(value):
    # Compare with the largest float, not math.isfinite: isfinite raises
    # OverflowError on an integer of more than 308 digits.
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and -sys.float_info.max <= value <= sys.float_info.max)


def _kind(value):
    """The JSON type name of a value. bool is not a number here."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    if value is None:
        return "null"
    return "object"


def _same(a, b):
    # Python says True == 1. A fact of 1 must not meet a requirement of true.
    return _kind(a) == _kind(b) and a == b


def _is_scalar(value):
    return _kind(value) in ("boolean", "number", "string")


def _str_list(value):
    return isinstance(value, list) and all(
        isinstance(v, str) and v.strip() for v in value)


def _refuse_unknown(doc, allowed, where):
    # A misspelt "requires" would otherwise drop every check it held, and the
    # node would look covered by checks that never run.
    unknown = sorted(k for k in doc if k not in allowed)
    if unknown:
        raise ValueError("%s: unknown key(s) %s. Allowed: %s"
                         % (where, ", ".join(unknown), ", ".join(allowed)))


def parse_version(text):
    """'11.5.0' -> (11, 5, 0). Anything else raises ValueError."""
    if not isinstance(text, str) or not re.match(
            r"\A\d+(\.\d+)*\Z", text.strip(), re.ASCII):
        raise ValueError("not a dotted version: %r" % (text,))
    return tuple(int(p) for p in text.strip().split("."))


def split_tcp(key):
    """'tcp:host:1433' -> ('host', 1433). Brackets around IPv6 are removed."""
    host, sep, port = key[len("tcp:"):].rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not sep or not host \
            or not re.match(r"\A\d{1,5}\Z", port, re.ASCII) \
            or not 0 < int(port) < 65536:
        raise ValueError("%s: a TCP fact is tcp:HOST:PORT with a port from 1 "
                         "to 65535" % key)
    return host, int(port)


def _check_fact_key(key, where):
    if not isinstance(key, str) or not key.strip():
        raise ValueError("%s: fact must be a non-empty string" % where)
    if key.startswith("tcp:"):
        split_tcp(key)
    for prefix in ("disk_free_gb:", "mof:"):
        if key.startswith(prefix) and not key[len(prefix):].strip():
            raise ValueError("%s: %s needs a path after the colon"
                             % (where, prefix))


def _check_value(op, value, where):
    if op == ">=":
        ok = _is_number(value)
        need = "a number"
    elif op == "version>=":
        try:
            parse_version(value)
            ok = True
        except ValueError:
            ok = False
        need = "a dotted version string such as \"18.3\""
    elif op in ("excludes", "in"):
        ok = (isinstance(value, list) and len(value) > 0
              and all(_is_scalar(v) for v in value))
        need = "a non-empty list of strings, numbers or booleans"
    else:
        ok = _is_scalar(value) and (not isinstance(value, float)
                                    or math.isfinite(value))
        need = "a string, a number or a boolean"
    if not ok:
        raise ValueError("%s: op %s needs %s as its value, got %s"
                         % (where, op, need, json.dumps(value)))


def _requirements(reqs, where):
    if not isinstance(reqs, list):
        raise ValueError("%s: requirements must be a list" % where)
    out = []
    for i, req in enumerate(reqs):
        at = "%s requirement %d" % (where, i + 1)
        if not isinstance(req, dict):
            raise ValueError("%s: must be an object" % at)
        _refuse_unknown(req, REQ_KEYS, at)
        _check_fact_key(req.get("fact"), at)
        op = req.get("op")
        if op not in OPS:
            raise ValueError("%s: op must be one of %s, got %s"
                             % (at, ", ".join(OPS), json.dumps(op)))
        if "value" not in req:
            raise ValueError("%s: value is required" % at)
        _check_value(op, req["value"], at)
        why = req.get("why", "")
        if not isinstance(why, str):
            raise ValueError("%s: why must be a string" % at)
        out.append({"fact": req["fact"], "op": op, "value": req["value"],
                    "why": why})
    return out


def load_table(doc):
    """Validate a parsed node table. Raises ValueError naming the first fault."""
    if not isinstance(doc, dict):
        raise ValueError("the table must be a JSON object")
    _refuse_unknown(doc, TABLE_KEYS, "table")
    if doc.get("format") != TABLE_FORMAT:
        raise ValueError("table: format must be \"%s\", got %s"
                         % (TABLE_FORMAT, json.dumps(doc.get("format"))))
    max_age = doc.get("max_age_hours", DEFAULT_MAX_AGE_HOURS)
    if not _is_number(max_age) or max_age <= 0:
        raise ValueError("table: max_age_hours must be a positive number")
    roles = doc.get("roles", {})
    if not isinstance(roles, dict):
        raise ValueError("table: roles must be an object of role -> list")
    checked = {}
    for name, reqs in roles.items():
        checked[name] = _requirements(reqs, "role %s" % name)
    nodes = doc.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("table: nodes must be a non-empty list")
    seen = set()
    out = []
    for i, node in enumerate(nodes):
        where = "nodes[%d]" % i
        if not isinstance(node, dict):
            raise ValueError("%s: must be an object" % where)
        _refuse_unknown(node, NODE_KEYS, where)
        name = node.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("%s: name must be a non-empty string" % where)
        if name in seen:
            raise ValueError("%s: node %s is listed twice" % (where, name))
        seen.add(name)
        where = "node %s" % name
        node_roles = node.get("roles", [])
        if not _str_list(node_roles):
            raise ValueError("%s: roles must be a list of role names" % where)
        for role in node_roles:
            if role not in checked:
                raise ValueError("%s: role %s is not defined under roles"
                                 % (where, role))
        facts = node.get("facts", [])
        if isinstance(facts, str):
            facts = [facts]
        if not _str_list(facts):
            raise ValueError("%s: facts must be a path or a list of paths"
                             % where)
        reqs = []
        for role in node_roles:
            reqs.extend(checked[role])
        reqs.extend(_requirements(node.get("requires", []), where))
        unique = []
        keys = set()
        for req in reqs:
            # Two roles that both ask for the same thing count it once.
            key = (req["fact"], req["op"],
                   json.dumps(req["value"], sort_keys=True))
            if key not in keys:
                keys.add(key)
                unique.append(req)
        out.append({"name": name, "roles": list(node_roles), "facts": facts,
                    "requirements": unique})
    return {"max_age_hours": float(max_age), "nodes": out}


# ------------------------------------------------------------------ facts

def parse_time(text):
    if not isinstance(text, str):
        raise ValueError("not a time string")
    return datetime.datetime.strptime(text, TIME_FORMAT).replace(
        tzinfo=datetime.timezone.utc)


def format_time(moment):
    return moment.strftime(TIME_FORMAT)


def read_facts(doc, node, now, max_age_hours):
    """One parsed facts file, judged for one node at one moment.

    Returns a dict with facts, errors, problem, gathered, gathered_on and age.
    A problem means none of the file's facts may be used.
    """
    info = {"facts": {}, "errors": {}, "problem": None, "gathered": None,
            "gathered_on": None, "age": None}
    if not isinstance(doc, dict) or doc.get("format") != FACTS_FORMAT:
        info["problem"] = "not a %s document" % FACTS_FORMAT
        return info
    if doc.get("node") != node:
        info["problem"] = ("gathered for node %s, not %s"
                           % (json.dumps(doc.get("node")), node))
        return info
    facts = doc.get("facts", {})
    errors = doc.get("errors", {})
    if not isinstance(facts, dict) or not isinstance(errors, dict) or \
            not all(isinstance(v, str) for v in errors.values()):
        info["problem"] = "facts and errors must be objects"
        return info
    try:
        gathered = parse_time(doc.get("gathered"))
    except ValueError:
        info["problem"] = ("no gathered time in the form %s"
                           % "2026-01-31T12:00:00Z")
        return info
    age = (now - gathered).total_seconds() / 3600.0
    info.update({"gathered": format_time(gathered), "age": age,
                 "gathered_on": doc.get("gathered_on")})
    if age < -CLOCK_SKEW_HOURS:
        info["problem"] = ("gathered %.1f h in the future; the clock that "
                           "stamped it is wrong" % -age)
    elif age > max_age_hours:
        info["problem"] = ("stale: gathered %.1f h ago, the table allows %g h"
                           % (age, max_age_hours))
    else:
        info["facts"] = facts
        info["errors"] = errors
    return info


def _show(value):
    text = json.dumps(value, sort_keys=True)
    return text if len(text) <= 100 else text[:97] + "..."


def apply_op(op, fact, want):
    """(verdict, detail) for one fact against one requirement value."""
    seen = "observed %s" % _show(fact)
    if op == "==":
        if _kind(fact) != _kind(want):
            return UNVERIFIED, ("observed a %s, the requirement compares a %s"
                                % (_kind(fact), _kind(want)))
        return (OBSERVED if fact == want else FAIL), seen
    if op == ">=":
        if not _is_number(fact):
            return UNVERIFIED, "observed %s, which is not a number" % _show(fact)
        return (OBSERVED if fact >= want else FAIL), seen
    if op == "version>=":
        try:
            have = parse_version(fact)
        except ValueError:
            return UNVERIFIED, ("observed %s, which is not a dotted version"
                                % _show(fact))
        need = parse_version(want)
        width = max(len(have), len(need))
        have = have + (0,) * (width - len(have))
        need = need + (0,) * (width - len(need))
        return (OBSERVED if have >= need else FAIL), seen
    if op in ("contains", "excludes"):
        if not isinstance(fact, list):
            return UNVERIFIED, ("observed %s, which is not a list"
                                % _show(fact))
        if op == "contains":
            hit = any(_same(item, want) for item in fact)
            return (OBSERVED if hit else FAIL), seen
        hits = [w for w in want if any(_same(item, w) for item in fact)]
        if hits:
            return FAIL, "%s; holds %s" % (seen, _show(hits))
        return OBSERVED, seen
    # op == "in", the last of OPS; load_table refuses any other.
    if not _is_scalar(fact):
        return UNVERIFIED, "observed %s, which is not one value" % _show(fact)
    return (OBSERVED if any(_same(fact, w) for w in want) else FAIL), seen


def evaluate(req, sources):
    """(verdict, detail) for one requirement over every facts file of a node.

    sources is a list of (label, info) from read_facts. A requirement is only
    ever judged on a value that one usable file holds and no other contradicts.
    """
    key = req["fact"]
    outcomes = []
    for label, info in sources:
        if key in info["facts"]:
            outcomes.append((label, "value",
                             json.dumps(info["facts"][key], sort_keys=True),
                             info["facts"][key]))
        elif key in info["errors"]:
            outcomes.append((label, "error", info["errors"][key], None))
    if len(set((kind, text) for _, kind, text, _ in outcomes)) > 1:
        return UNVERIFIED, ("conflicting evidence in %s"
                            % ", ".join(label for label, _, _, _ in outcomes))
    if outcomes:
        label, kind, text, value = outcomes[0]
        if kind == "error":
            return UNVERIFIED, "probe failed in %s: %s" % (label, text)
        return apply_op(req["op"], value, req["value"])
    problems = ["%s: %s" % (label, info["problem"])
                for label, info in sources if info["problem"]]
    if problems:
        return UNVERIFIED, "no usable fact; " + "; ".join(problems)
    if not sources:
        return UNVERIFIED, "no facts file is listed for this node"
    return UNVERIFIED, ("no such fact in %s"
                        % ", ".join(label for label, _ in sources))


def evaluate_node(node, sources):
    rows = [(evaluate(req, sources), req) for req in node["requirements"]]
    if not rows:
        # A node with nothing required of it was not checked. Counting it as
        # clean is how a role-specific check falls out of a summary.
        rows = [((UNVERIFIED, "no requirement applies to this node, so "
                  "nothing was checked"), None)]
    return {"name": node["name"], "roles": node["roles"], "sources": sources,
            "rows": [(verdict, req, detail)
                     for (verdict, detail), req in rows]}


def describe_req(req):
    if req is None:
        return "(no requirement)"
    return "%s %s %s" % (req["fact"], req["op"], _show(req["value"]))


def describe(results):
    """The report as lines. It never uses the word PASS."""
    lines = []
    counts = {FAIL: 0, UNVERIFIED: 0, OBSERVED: 0}
    for res in results:
        lines.append("")
        lines.append("%s  [%s]" % (res["name"], ", ".join(res["roles"])
                                   or "no roles"))
        for label, info in res["sources"]:
            if info["problem"]:
                lines.append("  facts  %s  NOT USED: %s"
                             % (label, info["problem"]))
            else:
                lines.append("  facts  %s  gathered %s on %s, %.1f h old"
                             % (label, info["gathered"],
                                info["gathered_on"] or "an unnamed host",
                                info["age"]))
        for verdict, req, detail in res["rows"]:
            counts[verdict] += 1
            lines.append("  %-10s  %s" % (verdict, describe_req(req)))
            lines.append("              %s" % detail)
            if req is not None and req["why"]:
                lines.append("              why: %s" % req["why"])
    total = sum(counts.values())
    lines.append("")
    lines.append("summary: %d node(s), %d requirement(s): %d FAIL, "
                 "%d UNVERIFIED, %d OBSERVED"
                 % (len(results), total, counts[FAIL], counts[UNVERIFIED],
                    counts[OBSERVED]))
    if counts[FAIL]:
        lines.append("Not ready. Fix every FAIL before the install.")
    elif counts[UNVERIFIED]:
        lines.append("Not shown ready. Each UNVERIFIED line is a "
                     "prerequisite nobody has observed.")
    else:
        lines.append("Every requirement was OBSERVED as met when its facts "
                     "were gathered. That is evidence about that moment, "
                     "not a promise the install will work.")
    return lines


def gate(results):
    verdicts = [row[0] for res in results for row in res["rows"]]
    if FAIL in verdicts:
        return 1
    if UNVERIFIED in verdicts:
        return 3
    return 0


# ------------------------------------------------------------------ mofcheck

_INSTANCE_RE = re.compile(
    r"instance\s+of\s+(\w+)(?:\s+as\s+(\$\w+))?\s*\{", re.IGNORECASE)

# One token of MOF text: a string literal (closed or not), a // comment, a
# /* */ comment (closed or not), a run of anything else, or a lone slash.
_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"?|//[^\r\n]*|/\*.*?(?:\*/|\Z)|[^"/]+|/', re.DOTALL)
_SPACE_RE = re.compile(r"\s*")
_PROP_RE = re.compile(r"(\w+)\s*=\s*")
_BARE_RE = re.compile(r'[^;,"{}]*')


def strip_comments(text):
    """text with every MOF comment replaced by spaces. Newlines are kept.

    DSP0221 clause 5.4: a comment is whitespace, and // or /* inside a string
    literal is not a comment. Without this, an "instance of MSFT_Credential"
    written inside a comment would be read as a live credential. A block
    comment that is never closed raises ValueError: the specification ends it
    at the end of the file, but a file cut short is not a file this tool can
    vouch for.
    """
    out = []
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        if token.startswith("//"):
            out.append(" " * len(token))
        elif token.startswith("/*"):
            if not (len(token) >= 4 and token.endswith("*/")):
                raise ValueError("a block comment is never closed")
            out.append(re.sub(r"[^\r\n]", " ", token))
        else:
            out.append(token)
    return "".join(out)


def _mof_string(text, i):
    """Parse one MOF string literal at text[i] == '"'. Returns (value, end).

    The escapes are the ones DSP0221 clause 7.6.1.3 lists, except the hex
    escape (backslash, x, digits), which is refused. The error never names
    the character after the backslash: in a password it is part of the secret.
    """
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
               "\\": "\\", "\"": "\"", "'": "'"}
    out = []
    i += 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            nxt = text[i + 1:i + 2]
            if nxt not in escapes:
                raise ValueError("an unknown escape sequence in a string")
            out.append(escapes[nxt])
            i += 2
        elif ch == "\"":
            return "".join(out), i + 1
        else:
            out.append(ch)
            i += 1
    raise ValueError("a string is not closed")


def _mof_value(text, i):
    """One property value at text[i]. Returns (value, end).

    A string is a str. Adjacent string literals join into one (DSP0221 clause
    7.6.1.3). An array is ("array", count) and anything else, such as NULL or
    a $reference, is ("bare", token).
    """
    if text.startswith("\"", i):
        value, i = _mof_string(text, i)
        while text.startswith("\"", _SPACE_RE.match(text, i).end()):
            more, i = _mof_string(text, _SPACE_RE.match(text, i).end())
            value += more
        return value, i
    if text.startswith("{", i):
        i = _SPACE_RE.match(text, i + 1).end()
        count = 0
        while not text.startswith("}", i):
            _, i = _mof_value(text, i)
            count += 1
            i = _SPACE_RE.match(text, i).end()
            if text.startswith(",", i):
                i = _SPACE_RE.match(text, i + 1).end()
            elif not text.startswith("}", i):
                raise ValueError("an array is not closed")
        return ("array", count), i + 1
    bare = _BARE_RE.match(text, i)
    return ("bare", bare.group(0).strip()), bare.end()


def _mof_body(text, start):
    """Properties of the instance whose '{' ends at start. (dict, end).

    Keys are lower case. Comments must already be removed (strip_comments).
    """
    props = {}
    i = start
    while True:
        i = _SPACE_RE.match(text, i).end()
        if text.startswith("}", i):
            return props, i + 1
        match = _PROP_RE.match(text, i)
        if not match:
            raise ValueError("cannot read a property at offset %d" % i)
        name = match.group(1).lower()
        value, i = _mof_value(text, match.end())
        i = _SPACE_RE.match(text, i).end()
        if not text.startswith(";", i):
            raise ValueError("property %s is not ended by ;" % name)
        props[name] = value
        i += 1


def is_enveloped_data(der):
    """True when der is a DER SEQUENCE whose first element is id-envelopedData.

    A structure check, not a decryption. It proves the value is a CMS
    EnvelopedData message, not which certificate it was sealed to.
    """
    def length_at(i):
        first = der[i]
        if first < 0x80:
            return first, i + 1
        width = first & 0x7F
        if width == 0 or width > 4 or i + 1 + width > len(der):
            raise ValueError("bad DER length")
        return int.from_bytes(der[i + 1:i + 1 + width], "big"), i + 1 + width
    try:
        if len(der) < 2 or der[0] != 0x30:
            return False
        length, i = length_at(1)
        if i + length != len(der) or der[i] != 0x06:
            return False
        oid_len, j = length_at(i + 1)
        return der[j:j + oid_len] == ENVELOPED_OID and j + oid_len < len(der)
    except (ValueError, IndexError):
        return False


def _b64(text):
    return base64.b64decode("".join(text.split()).encode("ascii"),
                            validate=True)


def classify_password(value):
    """(verdict, reason) for one MSFT_Credential Password value.

    The length of the value is never the test. A long plaintext passphrase is
    still plaintext, and the reason text never repeats the value.
    """
    text = value.strip()
    if not text.startswith(CMS_BEGIN):
        try:
            bare = _b64(text) if text else b""
        except (binascii.Error, ValueError, UnicodeEncodeError):
            bare = b""
        if is_enveloped_data(bare):
            return UNVERIFIED, ("EnvelopedData without the CMS armour that "
                                "Protect-CmsMessage writes")
        return MOF_PLAINTEXT, "not a CMS message: the password is readable"
    if not text.endswith(CMS_END):
        return UNVERIFIED, "the CMS armour is not closed"
    try:
        der = _b64(text[len(CMS_BEGIN):-len(CMS_END)])
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return UNVERIFIED, "the CMS armour does not hold base64"
    if not is_enveloped_data(der):
        return UNVERIFIED, ("CMS armour, but not an EnvelopedData message "
                            "(RFC 5652 section 6)")
    return MOF_ENCRYPTED, "CMS EnvelopedData, %d bytes" % len(der)


def _document_row(reason):
    return UNVERIFIED, [(0, "(document)", UNVERIFIED, reason)]


def _password_verdict(password):
    """(verdict, reason) for a Password that is not a string literal.

    The reason never repeats the token. An unquoted token is a password
    written in the clear, so it is PLAINTEXT, not merely unreadable.
    """
    kind, token = password
    if kind == "array":
        return UNVERIFIED, "Password is an array, not a string"
    if token.upper() == "NULL":
        return UNVERIFIED, "Password is NULL, not a string"
    if token.startswith("$"):
        return UNVERIFIED, "Password is a reference, not a string"
    return MOF_PLAINTEXT, "Password is not a quoted string: it is readable"


def mof_verdict(text):
    """(verdict, findings) for one MOF document.

    findings is a list of (line, alias, verdict, reason), one per credential,
    plus one document-level row when the encryption marker disagrees. Text
    that holds no MSFT_Credential and no OMI_ConfigurationDocument instance is
    UNVERIFIED, not clean: a compiled MOF always ends with the document, so
    an empty file or a file of another kind was not a MOF this tool read.
    """
    if "\x00" in text:
        return _document_row("the text holds NUL characters, so it is not "
                             "UTF-8 or UTF-16 with a byte order mark")
    try:
        text = strip_comments(text)
    except ValueError as exc:
        return _document_row(str(exc))
    findings = []
    marker = False
    seen = False
    for match in _INSTANCE_RE.finditer(text):
        cls = match.group(1).lower()
        if cls not in ("msft_credential", "omi_configurationdocument"):
            continue
        line = text.count("\n", 0, match.start()) + 1
        alias = match.group(2) or "(no alias)"
        try:
            props, _ = _mof_body(text, match.end())
        except ValueError as exc:
            if cls == "msft_credential":
                seen = True
                findings.append((line, alias, UNVERIFIED,
                                 "cannot parse the instance: %s" % exc))
            continue
        seen = True
        if cls == "omi_configurationdocument":
            marker = marker or props.get("contenttype") == "PasswordEncrypted"
            continue
        password = props.get("password")
        if password is None:
            findings.append((line, alias, UNVERIFIED,
                             "the credential has no Password property"))
        elif isinstance(password, tuple):
            verdict, reason = _password_verdict(password)
            findings.append((line, alias, verdict, reason))
        else:
            verdict, reason = classify_password(password)
            findings.append((line, alias, verdict, reason))
    verdicts = [f[2] for f in findings]
    if not seen:
        return _document_row("not a DSC MOF: no MSFT_Credential or "
                             "OMI_ConfigurationDocument instance was found")
    if not findings:
        return MOF_NONE, findings
    if MOF_PLAINTEXT in verdicts:
        return MOF_PLAINTEXT, findings
    if UNVERIFIED in verdicts:
        return UNVERIFIED, findings
    if not marker:
        # The compiler writes ContentType="PasswordEncrypted" whenever it
        # encrypted a password. CMS values without it were edited in by hand.
        findings.append((0, "(document)", UNVERIFIED,
                         "credentials are CMS, but no OMI_ConfigurationDocument "
                         "says ContentType=\"PasswordEncrypted\""))
        return UNVERIFIED, findings
    return MOF_ENCRYPTED, findings


def decode_text(raw):
    """File bytes to text: UTF-16 with a BOM, or UTF-8 with or without one.

    Windows PowerShell 5 writes UTF-16 with a BOM from Out-File and from the
    redirect operator, so a MOF, a table or a facts file can arrive that way.
    """
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("not UTF-8 or UTF-16 text")


def read_mof(path):
    with open(path, "rb") as handle:
        return decode_text(handle.read())


# ------------------------------------------------------------------ gather

def tcp_open(host, port, connect=socket.create_connection):
    """True when a TCP connection opens, False when it is refused.

    Only a refusal proves the port is closed: the host answered and said no.
    A timeout, an unreachable network and a name that does not resolve all
    raise, so collect records an error. The probe never reached the port, and
    "closed" would be a made-up observation.
    """
    try:
        conn = connect((host, port), TCP_TIMEOUT)
    except ConnectionRefusedError:
        return False
    conn.close()
    return True


def disk_free_gb(path, usage=shutil.disk_usage):
    """Free GiB (1024 ** 3 bytes) cut down to 0.1. Rounding up would let 39.96
    GiB meet a requirement of 40."""
    return math.floor(usage(path).free / float(1024 ** 3) * 10) / 10.0


def odbc_drivers(reg=_WINREG):
    """Installed ODBC driver names from the 64-bit registry view."""
    if reg is None:
        raise OSError("no Windows registry on this platform")
    key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, ODBC_DRIVERS_KEY, 0,
                      reg.KEY_READ | reg.KEY_WOW64_64KEY)
    try:
        names = []
        for index in range(reg.QueryInfoKey(key)[1]):
            name, data, _ = reg.EnumValue(key, index)
            if data == "Installed":
                names.append(name)
        return sorted(names)
    finally:
        reg.CloseKey(key)


def mof_fact(path):
    verdict, findings = mof_verdict(read_mof(path))
    if verdict == UNVERIFIED:
        reasons = sorted(set(f[3] for f in findings if f[2] == UNVERIFIED))
        raise ValueError("mofcheck UNVERIFIED: %s" % "; ".join(reasons))
    return verdict


def platform_fact(key):
    return {"os.system": platform.system, "os.release": platform.release,
            "os.version": platform.version,
            "os.machine": platform.machine}[key]()


PROBES = {"tcp": tcp_open, "disk": disk_free_gb, "odbc": odbc_drivers,
          "mof": mof_fact, "platform": platform_fact}


def collect(key, base, probes=None):
    """(value, None) or (None, error text) for one fact key on this host."""
    use = dict(PROBES)
    use.update(probes or {})
    try:
        if key.startswith("tcp:"):
            return use["tcp"](*split_tcp(key)), None
        if key.startswith("disk_free_gb:"):
            return use["disk"](key[len("disk_free_gb:"):]), None
        if key.startswith("mof:"):
            return use["mof"](os.path.join(base, key[len("mof:"):])), None
        if key == ODBC_FACT:
            return use["odbc"](), None
        if key in PLATFORM_FACTS:
            return use["platform"](key), None
    except (OSError, ValueError) as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)
    return None, ("no collector for this fact; supply it by hand in a "
                  "facts file")


def gather(node, keys, base, now, probes=None, host=None):
    facts = {}
    errors = {}
    for key in keys:
        value, error = collect(key, base, probes)
        if error is None:
            facts[key] = value
        else:
            errors[key] = error
    return {"format": FACTS_FORMAT, "node": node, "gathered": format_time(now),
            "gathered_on": platform.node() if host is None else host,
            "facts": facts, "errors": errors}


# ------------------------------------------------------------------ I/O

def _no_repeated_key(pairs):
    # json.load keeps the last of two equal keys. A second "requires" in a node
    # would silently drop the first block of checks.
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("the key %s appears twice in one object"
                             % json.dumps(key))
        out[key] = value
    return out


def _refuse_constant(name):
    raise ValueError("%s is not a JSON number" % name)


def _refuse_overflow(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("%s is too large for a number" % text)
    return value


def _read_json(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        text = decode_text(raw)
        if "\x00" in text:
            raise ValueError("the file holds NUL characters. Save it as UTF-8 "
                             "or as UTF-16 with a byte order mark")
        return json.loads(text, object_pairs_hook=_no_repeated_key,
                          parse_constant=_refuse_constant,
                          parse_float=_refuse_overflow)
    except ValueError as exc:
        raise InputError("%s: not valid JSON: %s" % (path, exc))


def _plain(text):
    """text as printable ASCII. Gathered values, why texts and file names come
    from files, so a control character or an escape sequence in one must not
    reach the terminal, and a character the console cannot encode must not
    stop the report part-way."""
    def escape(match):
        code = ord(match.group(0))
        return ("\\x%02x" if code < 256 else "\\u%04x" if code < 65536
                else "\\U%08x") % code
    return re.sub(r"[^\x20-\x7e]", escape, text)


def _emit(text, stream=None):
    print(_plain(text), file=stream)


def _check_overwrite(path):
    """Refuse to replace a file that is not a nodecheck facts file. --out
    pointed at the node table would otherwise destroy it."""
    if not os.path.lexists(path):
        return
    try:
        doc = _read_json(path)
    except (OSError, InputError):
        doc = None
    if not isinstance(doc, dict) or doc.get("format") != FACTS_FORMAT:
        raise OSError("it exists and is not a %s file, so it was not "
                      "replaced" % FACTS_FORMAT)


def _write_atomic(path, text):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    handle, tmp = tempfile.mkstemp(prefix=".nodecheck-", dir=folder)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.remove(tmp)
        raise


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _parse(argv):
    ap = argparse.ArgumentParser(
        prog="nodecheck.py",
        description="Install-time prerequisites from a node table, reported "
                    "UNVERIFIED, never PASS.",
        epilog="Nothing is written without --apply.",
        allow_abbrev=False)
    ap.add_argument("--self-test", dest="self_test", action="store_true",
                    help="run the offline assertions and exit")
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")
    g = sub.add_parser("gather", allow_abbrev=False,
                       help="observe this host's facts for one node")
    g.add_argument("table", help="the node table, JSON")
    g.add_argument("--node", required=True, help="the node this host is")
    g.add_argument("--only", default="",
                   help="gather only the facts whose key starts with this")
    g.add_argument("--out", help="path for the facts file")
    g.add_argument("--apply", action="store_true",
                   help="write --out. Without this nothing is written.")
    c = sub.add_parser("check", allow_abbrev=False,
                       help="judge every node's facts against the table")
    c.add_argument("table", help="the node table, JSON")
    c.add_argument("--node", help="check only this node")
    sub.add_parser("example", allow_abbrev=False,
                   help="print an example node table")
    m = sub.add_parser("mof", allow_abbrev=False,
                       help="find plaintext passwords in compiled DSC MOFs")
    m.add_argument("paths", nargs="+", metavar="MOF")
    return ap.parse_args(argv)


def _find_node(table, name):
    for node in table["nodes"]:
        if node["name"] == name:
            return node
    raise ValueError("no node named %s in the table. It has: %s"
                     % (name, ", ".join(n["name"] for n in table["nodes"])))


def mof_exit(codes):
    """The exit code for a run over several MOFs. A readable password (1)
    outranks a file that could not be read (2), which outranks UNVERIFIED (3).
    """
    for code in (1, 2, 3):
        if code in codes:
            return code
    return 0


def _cmd_mof(paths):
    codes = []
    for path in paths:
        try:
            verdict, findings = mof_verdict(read_mof(path))
        except (OSError, ValueError) as exc:
            _emit("error: %s: %s" % (path, exc), sys.stderr)
            codes.append(2)
            continue
        _emit("%s: %s  %d credential(s)"
              % (path, verdict, len([f for f in findings if f[0]])))
        for line, alias, row_verdict, reason in findings:
            where = "line %d %s" % (line, alias) if line else alias
            _emit("  %-10s  %s  %s" % (row_verdict, where, reason))
        codes.append({MOF_PLAINTEXT: 1, UNVERIFIED: 3}.get(verdict, 0))
    return mof_exit(codes)


def _cmd_gather(args, table, base):
    node = _find_node(table, args.node)
    keys = []
    for req in node["requirements"]:
        if req["fact"].startswith(args.only) and req["fact"] not in keys:
            keys.append(req["fact"])
    if not keys:
        raise ValueError("node %s requires no fact starting with %s"
                         % (node["name"], json.dumps(args.only)))
    doc = gather(node["name"], keys, base, _utcnow())
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    sys.stdout.write(text)
    if args.out:
        if args.apply:
            try:
                _check_overwrite(args.out)
                _write_atomic(args.out, text)
            except OSError as exc:
                _emit("error: could not write %s: %s" % (args.out, exc),
                      sys.stderr)
                return 2
            _emit("wrote %s" % args.out, sys.stderr)
        else:
            _emit("Check only. %s was not written. Re-run with --apply."
                  % args.out, sys.stderr)
    return 3 if doc["errors"] else 0


def _cmd_check(args, table, base):
    nodes = table["nodes"]
    if args.node:
        nodes = [_find_node(table, args.node)]
    now = _utcnow()
    results = []
    for node in nodes:
        sources = []
        for rel in node["facts"]:
            try:
                doc = _read_json(os.path.join(base, rel))
                info = read_facts(doc, node["name"], now,
                                  table["max_age_hours"])
            except (OSError, InputError) as exc:
                info = read_facts(None, node["name"], now, 1.0)
                info["problem"] = "cannot read: %s" % (
                    exc.strerror if isinstance(exc, OSError) and exc.strerror
                    else exc)
            sources.append((rel, info))
        results.append(evaluate_node(node, sources))
    _emit("nodecheck: %s, %d node(s)" % (args.table, len(results)))
    for line in describe(results):
        _emit(line)
    return gate(results)


def main(argv=None):
    try:
        args = _parse(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        # argparse exits 2 on a flag it refuses, and 2 here means a file could
        # not be read. A mistyped --ap is a usage error, so it gets 64.
        return 64 if exc.code == 2 else exc.code
    if args.self_test:
        return self_test()
    if args.command is None:
        _emit("error: name a command: gather, check, mof or example. Use "
              "--self-test to verify the tool without any input.", sys.stderr)
        return 64
    if args.command == "example":
        sys.stdout.write(EXAMPLE_TABLE)
        return 0
    if args.command == "mof":
        return _cmd_mof(args.paths)
    if args.command == "gather" and args.apply and not args.out:
        _emit("error: --apply needs --out.", sys.stderr)
        return 64
    try:
        table = load_table(_read_json(args.table))
    except (OSError, InputError) as exc:
        _emit("error: %s" % exc, sys.stderr)
        return 2
    except ValueError as exc:
        _emit("error: %s: %s" % (args.table, exc), sys.stderr)
        return 64
    base = os.path.dirname(os.path.abspath(args.table))
    try:
        if args.command == "gather":
            return _cmd_gather(args, table, base)
        return _cmd_check(args, table, base)
    except ValueError as exc:
        _emit("error: %s" % exc, sys.stderr)
        return 64


# ------------------------------------------------------------------ self-test

def self_test():
    """Assertions over the core, the probes and the CLI. Offline."""
    passed = [0]
    failed = []

    def check(cond, label):
        if cond:
            passed[0] += 1
            print("ok    %s" % label)
        else:
            failed.append(label)
            print("FAIL  %s" % label)

    def raises(fn, label, needle=""):
        try:
            fn()
        except ValueError as exc:
            check(needle in str(exc), label if needle in str(exc) else
                  "%s (message was %r)" % (label, str(exc)))
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)

    def run_cli(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    print("nodecheck self-test: synthetic table, local stub server, no "
          "credentials")
    print("-" * 68)

    # ---- the table format
    def table(**over):
        doc = {"format": TABLE_FORMAT,
               "roles": {"server": [
                   {"fact": "odbc_drivers", "op": "contains",
                    "value": "ODBC Driver 18 for SQL Server"}]},
               "nodes": [{"name": "node-a", "roles": ["server"],
                          "facts": "facts/node-a.json"}]}
        doc.update(over)
        return doc

    t = load_table(table())
    check(t["max_age_hours"] == DEFAULT_MAX_AGE_HOURS,
          "a table without max_age_hours gets the 24 hour default")
    check(t["nodes"][0]["facts"] == ["facts/node-a.json"],
          "a single facts path is read as a list of one")
    check(len(t["nodes"][0]["requirements"]) == 1,
          "a node inherits the requirements of its role")
    raises(lambda: load_table([]), "a table that is not an object is refused",
           "JSON object")
    raises(lambda: load_table(table(format="nodecheck/2")),
           "an unknown format version is refused", "format must be")
    raises(lambda: load_table(table(requires=[])),
           "an unknown top-level key is refused", "unknown key(s) requires")
    raises(lambda: load_table(table(max_age_hours=0)),
           "a max age of zero is refused", "max_age_hours")
    raises(lambda: load_table(table(max_age_hours=True)),
           "a max age of true is refused, bool is not a number",
           "max_age_hours")
    raises(lambda: load_table(table(roles=[])), "roles as a list is refused",
           "roles must be")
    raises(lambda: load_table(table(nodes=[])), "an empty node list is refused",
           "non-empty list")
    raises(lambda: load_table(table(nodes=["node-a"])),
           "a node that is a bare string is refused", "must be an object")
    raises(lambda: load_table(table(nodes=[{"name": "node-a",
                                            "require": []}])),
           "a misspelt requires key is refused, not silently dropped"
           "  <-- pinned defect", "unknown key(s) require")
    raises(lambda: load_table(table(nodes=[{"name": " "}])),
           "a blank node name is refused", "name must be")
    raises(lambda: load_table(table(nodes=[{"name": "node-a"},
                                           {"name": "node-a"}])),
           "a node listed twice is refused", "listed twice")
    raises(lambda: load_table(table(nodes=[{"name": "node-a",
                                            "roles": "server"}])),
           "roles as a string is refused", "roles must be a list")
    raises(lambda: load_table(table(nodes=[{"name": "node-a",
                                            "roles": ["portal"]}])),
           "a role the table does not define is refused", "not defined")
    raises(lambda: load_table(table(nodes=[{"name": "node-a",
                                            "facts": [""]}])),
           "a blank facts path is refused", "facts must be")
    raises(lambda: load_table(table(nodes=[{"name": "node-a",
                                            "requires": {}}])),
           "requires as an object is refused", "must be a list")

    def req_error(req):
        return lambda: load_table(table(nodes=[{"name": "node-a",
                                                "requires": [req]}]))

    raises(req_error("odbc_drivers"), "a requirement that is a string is "
           "refused", "must be an object")
    raises(req_error({"fact": "x", "op": "==", "value": 1, "note": "n"}),
           "an unknown requirement key is refused", "unknown key(s) note")
    raises(req_error({"fact": "", "op": "==", "value": 1}),
           "a blank fact key is refused", "fact must be")
    raises(req_error({"fact": "x", "op": "<=", "value": 1}),
           "an op outside the six is refused", "op must be one of")
    raises(req_error({"fact": "x", "op": "=="}),
           "a requirement with no value is refused", "value is required")
    raises(req_error({"fact": "x", "op": "==", "value": [1]}),
           "== against a list is refused", "string, a number or a boolean")
    raises(req_error({"fact": "x", "op": "==", "value": None}),
           "== against null is refused", "string, a number or a boolean")
    raises(req_error({"fact": "x", "op": ">=", "value": "40"}),
           ">= against a string is refused", "needs a number")
    raises(req_error({"fact": "x", "op": "version>=", "value": "18.x"}),
           "version>= against a non-version is refused", "dotted version")
    raises(req_error({"fact": "x", "op": "in", "value": []}),
           "in against an empty list is refused", "non-empty list")
    raises(req_error({"fact": "x", "op": "excludes", "value": [["a"]]}),
           "excludes against a nested list is refused", "non-empty list")
    raises(req_error({"fact": "x", "op": "==", "value": 1, "why": 2}),
           "a why that is not a string is refused", "why must be")
    raises(req_error({"fact": "tcp:db.example.test", "op": "==",
                      "value": True}),
           "a tcp fact without a port is refused", "tcp:HOST:PORT")
    raises(req_error({"fact": "tcp:db.example.test:70000", "op": "==",
                      "value": True}),
           "a tcp port above 65535 is refused", "1 to 65535")
    raises(req_error({"fact": "tcp:db.example.test:65536", "op": "==",
                      "value": True}),
           "a tcp port of 65536 is refused, the first one past the range"
           "  <-- pinned defect", "1 to 65535")
    raises(req_error({"fact": "tcp:db.example.test:0", "op": "==",
                      "value": True}),
           "a tcp port of 0 is refused, the first one before the range"
           "  <-- pinned defect", "1 to 65535")
    check(split_tcp("tcp:db.example.test:65535")[1] == 65535
          and split_tcp("tcp:db.example.test:1")[1] == 1,
          "ports 1 and 65535 are accepted, both ends of the range")
    raises(req_error({"fact": "tcp:db.example.test:\u0661\u0664", "op": "==",
                      "value": True}),
           "a tcp port written in non-ASCII digits is refused"
           "  <-- pinned defect", "1 to 65535")
    raises(req_error({"fact": "tcp::1433", "op": "==", "value": True}),
           "a tcp fact without a host is refused", "tcp:HOST:PORT")
    raises(req_error({"fact": "disk_free_gb: ", "op": ">=", "value": 1}),
           "a disk fact without a path is refused", "needs a path")
    raises(req_error({"fact": "mof:", "op": "==", "value": "ENCRYPTED"}),
           "a mof fact without a path is refused", "needs a path")
    check(split_tcp("tcp:[::1]:443") == ("::1", 443),
          "an IPv6 host in brackets is unwrapped")
    dup = load_table(table(
        roles={"a": [{"fact": "x", "op": "==", "value": 1}],
               "b": [{"fact": "x", "op": "==", "value": 1}]},
        nodes=[{"name": "node-a", "roles": ["a", "b"],
                "requires": [{"fact": "x", "op": "==", "value": 2}]}]))
    check(len(dup["nodes"][0]["requirements"]) == 2,
          "the same requirement from two roles counts once, a different "
          "value stays")
    check(parse_version(" 18.3.2 ") == (18, 3, 2),
          "a dotted version parses with surrounding space")
    raises(lambda: parse_version("1\u00b2"),
           "a superscript digit is not a version digit", "dotted version")
    check([_kind(v) for v in (True, 1, 1.5, "a", [], None, {})]
          == ["boolean", "number", "number", "string", "list", "null",
              "object"], "every JSON shape has its own kind name")
    check(load_table(table(roles={"s": [{"fact": "x", "op": "version>=",
                                         "value": "18.3"}]},
                           nodes=[{"name": "n", "roles": ["s"]}]))
          ["nodes"][0]["requirements"][0]["value"] == "18.3",
          "a version>= requirement with a dotted version is loaded")
    raises(lambda: load_table(table(max_age_hours=10 ** 400)),
           "a max age of 400 digits is refused, not an OverflowError"
           "  <-- pinned defect", "max_age_hours")
    check(apply_op(">=", 10 ** 400, 40)[0] == UNVERIFIED,
          "an integer of 400 digits is not a usable number, UNVERIFIED"
          "  <-- pinned defect")
    check(not _is_number(float("nan")) and not _is_number(float("inf")),
          "NaN and infinity are not numbers")
    check(not _show("x" * 98).endswith("...")
          and _show("x" * 99).endswith("..."),
          "a value of exactly 100 characters is shown whole, one more is cut")

    # ---- facts files: who, when, and whether they count
    now = datetime.datetime(2026, 1, 31, 12, 0, 0,
                            tzinfo=datetime.timezone.utc)

    def facts_doc(node="node-a", gathered="2026-01-31T10:00:00Z", facts=None,
                  errors=None, host="authoring-01"):
        return {"format": FACTS_FORMAT, "node": node, "gathered": gathered,
                "gathered_on": host, "facts": facts or {},
                "errors": errors or {}}

    info = read_facts(facts_doc(facts={"x": 1}), "node-a", now, 24.0)
    check(info["problem"] is None and info["facts"] == {"x": 1}
          and abs(info["age"] - 2.0) < 1e-9,
          "a two hour old facts file for the right node is used")
    check(read_facts([], "node-a", now, 24.0)["problem"]
          == "not a nodecheck-facts/1 document",
          "a facts file that is not an object is not used")
    check("gathered for node \"node-b\", not node-a" in read_facts(
        facts_doc(node="node-b"), "node-a", now, 24.0)["problem"],
          "facts gathered for another node are not used for this one"
          "  <-- pinned defect")
    check(read_facts(facts_doc(errors={"x": 1}), "node-a", now, 24.0)
          ["problem"] == "facts and errors must be objects",
          "an error entry that is not text makes the file unusable")
    check("no gathered time" in read_facts(
        facts_doc(gathered="31/01/2026"), "node-a", now, 24.0)["problem"],
          "a gathered time in another format makes the file unusable")
    check("no gathered time" in read_facts(
        facts_doc(gathered=None), "node-a", now, 24.0)["problem"],
          "a missing gathered time makes the file unusable")
    stale = read_facts(facts_doc(gathered="2026-01-29T12:00:00Z",
                                 facts={"x": 1}), "node-a", now, 24.0)
    check(stale["problem"].startswith("stale: gathered 48.0 h ago")
          and stale["facts"] == {},
          "a facts file two days old is stale and its facts are dropped"
          "  <-- pinned defect")
    edge = read_facts(facts_doc(gathered="2026-01-30T12:00:00Z"),
                      "node-a", now, 24.0)
    check(edge["problem"] is None,
          "exactly the maximum age still counts, the limit is inclusive")
    future = read_facts(facts_doc(gathered="2026-01-31T13:00:00Z"),
                        "node-a", now, 24.0)
    check("in the future" in future["problem"],
          "a facts file stamped an hour ahead is refused")
    skew = read_facts(facts_doc(gathered="2026-01-31T12:04:00Z"),
                      "node-a", now, 24.0)
    check(skew["problem"] is None,
          "four minutes of clock skew is tolerated")
    edge_skew = read_facts(facts_doc(gathered="2026-01-31T12:05:00Z"),
                           "node-a", now, 24.0)
    check(edge_skew["problem"] is None,
          "exactly the allowed clock skew is tolerated, the limit is "
          "inclusive  <-- pinned defect")
    over_skew = read_facts(facts_doc(gathered="2026-01-31T12:05:01Z"),
                           "node-a", now, 24.0)
    check("in the future" in over_skew["problem"],
          "one second past the allowed clock skew is refused"
          "  <-- pinned defect")

    # ---- every op, on every shape of fact
    check(apply_op("==", True, True)[0] == OBSERVED, "== true on true is "
          "OBSERVED")
    check(apply_op("==", False, True)[0] == FAIL, "== true on false is FAIL")
    check(apply_op("==", 1, True)[0] == UNVERIFIED,
          "== true on the number 1 is UNVERIFIED, not OBSERVED"
          "  <-- pinned defect")
    check(apply_op(">=", 112.4, 40)[0] == OBSERVED,
          ">= 40 on 112.4 is OBSERVED")
    check(apply_op(">=", 40, 40)[0] == OBSERVED,
          ">= is inclusive at the boundary")
    check(apply_op(">=", 12.0, 40)[0] == FAIL, ">= 40 on 12.0 is FAIL")
    check(apply_op(">=", "112", 40)[0] == UNVERIFIED,
          ">= on a string is UNVERIFIED, not compared as text")
    check(apply_op(">=", True, 0)[0] == UNVERIFIED,
          ">= on a boolean is UNVERIFIED")
    check(apply_op("version>=", "18.3.2.1", "18.3")[0] == OBSERVED,
          "version 18.3.2.1 meets 18.3")
    check(apply_op("version>=", "11.5", "11.5.0")[0] == OBSERVED,
          "11.5 and 11.5.0 are the same version")
    check(apply_op("version>=", "9.10", "10.1")[0] == FAIL,
          "9.10 is below 10.1, not above it as text would say")
    check(apply_op("version>=", "17.10", "17.9")[0] == OBSERVED,
          "17.10 is above 17.9, not below it as text would say"
          "  <-- pinned defect")
    check(apply_op("version>=", "unknown", "1")[0] == UNVERIFIED,
          "version>= on a non-version is UNVERIFIED")
    drivers = ["ODBC Driver 17 for SQL Server", "SQL Server"]
    check(apply_op("contains", drivers,
                   "ODBC Driver 18 for SQL Server")[0] == FAIL,
          "contains on a list without the driver is FAIL")
    check(apply_op("contains", drivers + ["ODBC Driver 18 for SQL Server"],
                   "ODBC Driver 18 for SQL Server")[0] == OBSERVED,
          "contains on a list with the driver is OBSERVED")
    check(apply_op("contains", [1], True)[0] == FAIL,
          "contains true on [1] is FAIL, 1 is not true")
    check(apply_op("contains", "ODBC Driver 18 for SQL Server",
                   "ODBC Driver 18 for SQL Server")[0] == UNVERIFIED,
          "contains on a string is UNVERIFIED, not a substring test")
    verdict, detail = apply_op("excludes", ["SQLNCLI11", "MSOLEDBSQL"],
                               ["SQLNCLI", "SQLNCLI10", "SQLNCLI11"])
    check(verdict == FAIL and "holds [\"SQLNCLI11\"]" in detail,
          "excludes names the deprecated provider it found")
    check(apply_op("excludes", ["MSOLEDBSQL"], ["SQLNCLI11"])[0] == OBSERVED,
          "excludes on a list without them is OBSERVED")
    check(apply_op("excludes", {"a": 1}, ["a"])[0] == UNVERIFIED,
          "excludes on an object is UNVERIFIED")
    check(apply_op("in", "ENCRYPTED", ["ENCRYPTED", "NO_MSFT_CREDENTIAL"])[0]
          == OBSERVED, "in on a listed value is OBSERVED")
    check(apply_op("in", "PLAINTEXT", ["ENCRYPTED", "NO_MSFT_CREDENTIAL"])[0]
          == FAIL, "in on an unlisted value is FAIL")
    check(apply_op("in", ["ENCRYPTED"], ["ENCRYPTED"])[0] == UNVERIFIED,
          "in on a list is UNVERIFIED")
    long_value = apply_op("==", "x" * 200, "y")[1]
    check(len(long_value) < 120 and long_value.endswith("..."),
          "a long observed value is cut in the report")

    # ---- one requirement over several facts files
    req = {"fact": "odbc_drivers", "op": "contains",
           "value": "ODBC Driver 18 for SQL Server", "why": ""}
    good = read_facts(facts_doc(facts={"odbc_drivers": [
        "ODBC Driver 18 for SQL Server"]}), "node-a", now, 24.0)
    other = read_facts(facts_doc(facts={"odbc_drivers": [
        "ODBC Driver 17 for SQL Server"]}), "node-a", now, 24.0)
    failed_probe = read_facts(facts_doc(errors={
        "odbc_drivers": "OSError: no Windows registry on this platform"}),
        "node-a", now, 24.0)
    empty = read_facts(facts_doc(), "node-a", now, 24.0)
    check(evaluate(req, [("a.json", good)])[0] == OBSERVED,
          "one usable file with the fact decides it")
    check(evaluate(req, [("a.json", good), ("b.json", good)])[0] == OBSERVED,
          "two files that agree decide it")
    verdict, detail = evaluate(req, [("a.json", good), ("b.json", other)])
    check(verdict == UNVERIFIED and "conflicting evidence in a.json, b.json"
          in detail, "two files that disagree are UNVERIFIED, the later one "
          "does not win  <-- pinned defect")
    check(evaluate(req, [("a.json", good), ("b.json", failed_probe)])[0]
          == UNVERIFIED, "a value in one file and a failed probe in another "
          "is UNVERIFIED")
    verdict, detail = evaluate(req, [("a.json", failed_probe)])
    check(verdict == UNVERIFIED and detail.startswith("probe failed in a.json"),
          "a failed probe is UNVERIFIED, never read as absent and FAIL"
          "  <-- pinned defect")
    verdict, detail = evaluate(req, [("a.json", stale)])
    check(verdict == UNVERIFIED and "stale" in detail,
          "a fact only in a stale file is UNVERIFIED and says why")
    check(evaluate(req, [("a.json", stale), ("b.json", good)])[0] == OBSERVED,
          "a fresh file still decides when a stale one sits beside it")
    verdict, detail = evaluate(req, [])
    check(verdict == UNVERIFIED and "no facts file" in detail,
          "a node with no facts file is UNVERIFIED")
    verdict, detail = evaluate(req, [("a.json", empty)])
    check(verdict == UNVERIFIED and detail == "no such fact in a.json",
          "a fact nobody recorded is UNVERIFIED")

    node = load_table(table())["nodes"][0]
    res = evaluate_node(node, [("a.json", good)])
    check(gate([res]) == 0 and res["rows"][0][0] == OBSERVED,
          "a node whose only requirement is observed gates 0")
    bare = load_table(table(nodes=[{"name": "node-z"}]))["nodes"][0]
    res_bare = evaluate_node(bare, [])
    check(res_bare["rows"][0][0] == UNVERIFIED and gate([res_bare]) == 3,
          "a node with no requirement is UNVERIFIED, not clean"
          "  <-- pinned defect")
    res_fail = evaluate_node(node, [("a.json", other)])
    check(gate([res, res_fail, res_bare]) == 1,
          "one FAIL outranks every UNVERIFIED in the gate")
    report = "\n".join(describe([res, res_fail, res_bare]))
    check("summary: 3 node(s), 3 requirement(s): 1 FAIL, 1 UNVERIFIED, "
          "1 OBSERVED" in report, "the summary counts every verdict")
    counted = [{"name": "n", "roles": [], "sources": [],
                "rows": [(FAIL, None, "d")] * 2 + [(UNVERIFIED, None, "d")] * 3
                + [(OBSERVED, None, "d")]}]
    check("1 node(s), 6 requirement(s): 2 FAIL, 3 UNVERIFIED, 1 OBSERVED"
          in "\n".join(describe(counted)),
          "the summary puts each count under its own verdict, 2 / 3 / 1"
          "  <-- pinned defect")
    check("Not ready." in report, "a report with a FAIL says not ready")
    report_u = "\n".join(describe([res, res_bare]))
    check("Not shown ready." in report_u and "Not ready." not in report_u,
          "a report with only UNVERIFIED says not shown ready, not ready")
    report_o = "\n".join(describe([res]))
    check("not a promise" in report_o,
          "an all-OBSERVED report still says it is not a promise")
    stale_res = evaluate_node(node, [("old.json", stale)])
    report_s = "\n".join(describe([stale_res]))
    check("NOT USED: stale" in report_s,
          "a stale file is shown as not used, with the reason")
    check("gathered 2026-01-31T10:00:00Z on authoring-01, 2.0 h old"
          in report_o, "a used file shows when and where it was gathered")
    nameless = read_facts(facts_doc(host=None), "node-a", now, 24.0)
    check("on an unnamed host" in "\n".join(
        describe([evaluate_node(node, [("n.json", nameless)])])),
          "a facts file with no host says so")
    why_node = load_table(table(roles={"server": [dict(req, why="the "
                                                       "geodatabase connects "
                                                       "through it")]}))
    report_w = "\n".join(describe([evaluate_node(why_node["nodes"][0],
                                                 [("a.json", good)])]))
    check("why: the geodatabase connects through it" in report_w,
          "a requirement's why is printed under it")
    every = "\n".join([report, report_u, report_o, report_s, report_w])
    check("PASS" not in every and " OK" not in every,
          "no report ever says PASS or OK  <-- pinned defect")

    # ---- mofcheck
    def der(tag, content):
        n = len(content)
        if n < 0x80:
            head = bytes(bytearray([tag, n]))
        else:
            head = bytes(bytearray([tag, 0x82, n >> 8, n & 0xFF]))
        return head + content

    oid = der(0x06, ENVELOPED_OID)
    # Synthetic EnvelopedData: the right outer structure, filler inside.
    filler = der(0xA0, der(0x30, der(0x02, b"\x00") + b"\x5a" * 300))
    envelope = der(0x30, oid + filler)
    armoured = (CMS_BEGIN + "\n" +
                base64.encodebytes(envelope).decode("ascii") + CMS_END)
    data_oid = der(0x06, bytes(bytearray([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                                          0x01, 0x07, 0x01])))
    not_envelope = der(0x30, data_oid + filler)

    check(is_enveloped_data(envelope), "a DER EnvelopedData is recognised")
    check(not is_enveloped_data(not_envelope),
          "a CMS Data message is not EnvelopedData")
    check(not is_enveloped_data(b""), "no bytes are not EnvelopedData")
    check(not is_enveloped_data(b"\x04\x01\x00"),
          "an OCTET STRING is not EnvelopedData")
    check(not is_enveloped_data(envelope[:-1]),
          "a truncated message is not EnvelopedData")
    check(not is_enveloped_data(der(0x30, b"\x02\x01\x00")),
          "a SEQUENCE that starts with an INTEGER is not EnvelopedData")
    check(not is_enveloped_data(der(0x30, oid)),
          "the OID with nothing after it is not EnvelopedData")
    check(not is_enveloped_data(b"\x30\x80\x06"),
          "an indefinite length is refused")
    check(not is_enveloped_data(b"\x30\x85\x00\x00\x00\x00\x00"),
          "a five byte length is refused")
    check(not is_enveloped_data(b"\x30\x02\x06"),
          "a length that runs past the end is refused")

    check(classify_password(armoured)[0] == MOF_ENCRYPTED,
          "an armoured EnvelopedData password is ENCRYPTED")
    passphrase = "correct horse battery staple " * 5
    verdict, reason = classify_password(passphrase)
    check(verdict == MOF_PLAINTEXT and len(passphrase) > 100,
          "a plaintext passphrase over 100 characters is PLAINTEXT, length "
          "proves nothing  <-- pinned defect")
    check("correct horse" not in reason and str(len(passphrase)) not in reason,
          "the reason repeats neither the password nor its length")
    check(classify_password("")[0] == MOF_PLAINTEXT,
          "an empty password is PLAINTEXT, not encrypted")
    check(classify_password("c2VjcmV0")[0] == MOF_PLAINTEXT,
          "a base64 password that is not CMS is PLAINTEXT")
    check(classify_password("p\u00e4ss")[0] == MOF_PLAINTEXT,
          "a non-ASCII password is PLAINTEXT")
    verdict, reason = classify_password(
        base64.b64encode(envelope).decode("ascii"))
    check(verdict == UNVERIFIED and "without the CMS armour" in reason,
          "EnvelopedData with its armour stripped is UNVERIFIED")
    check(classify_password(CMS_BEGIN + "\nAAAA")[0] == UNVERIFIED,
          "armour that is never closed is UNVERIFIED")
    check(classify_password(CMS_BEGIN + "\n!!!!\n" + CMS_END)[0]
          == UNVERIFIED, "armour around non-base64 is UNVERIFIED")
    verdict, reason = classify_password(
        CMS_BEGIN + "\n" + base64.b64encode(not_envelope).decode("ascii")
        + "\n" + CMS_END)
    check(verdict == UNVERIFIED and "RFC 5652" in reason,
          "armour around a non-EnvelopedData message is UNVERIFIED")

    def mof_escape(text):
        # How the DSC compiler writes a string: \ doubled, newline as \n,
        # quote as \".
        return text.replace("\\", "\\\\").replace("\n", "\\n").replace(
            "\"", "\\\"")

    def mof(passwords, marker=True, extra=""):
        parts = ["/*\n@TargetNode='node-a'\n*/\n"]
        for i, pw in enumerate(passwords):
            value = pw if pw.startswith("NULL") else "\"%s\"" % mof_escape(pw)
            parts.append("\ninstance of MSFT_Credential as $MSFT_Credential%d"
                         "ref\n{\nPassword = %s;\n UserName = \"svc-example\";\n\n"
                         "};\n" % (i + 1, value))
        parts.append(extra)
        # The header carries an array property, as a compiled MOF does.
        parts.append("\ninstance of OMI_ConfigurationDocument\n{\n "
                     "Version=\"2.0.0\";\n CompatibleVersionAdditionalProperties"
                     "= {\"Omi_BaseResource:ConfigurationName\"};\n"
                     "%s Name=\"Example\";\n};\n"
                     % (" ContentType=\"PasswordEncrypted\";\n"
                        if marker else ""))
        return "".join(parts)

    verdict, findings = mof_verdict(mof([armoured, armoured]))
    check(verdict == MOF_ENCRYPTED and len(findings) == 2,
          "a MOF whose two credentials are CMS, marked, is ENCRYPTED")
    check(findings[0][0] == 5 and findings[0][1] == "$MSFT_Credential1ref",
          "a finding names the line and the alias of its credential")
    verdict, findings = mof_verdict(mof([armoured, "Example-Pass-1"]))
    check(verdict == MOF_PLAINTEXT and findings[1][2] == MOF_PLAINTEXT,
          "one plaintext credential among encrypted ones makes the MOF "
          "PLAINTEXT")
    check(mof_verdict(mof(["a\"b\\c"]))[0] == MOF_PLAINTEXT,
          "a plaintext password with escaped quote and backslash is read")
    check(mof_verdict(mof([armoured], marker=False))[0] == UNVERIFIED,
          "CMS credentials without the PasswordEncrypted marker are "
          "UNVERIFIED")
    check(mof_verdict(mof([]))[0] == MOF_NONE,
          "a MOF with no credential is NO_MSFT_CREDENTIAL")
    verdict, findings = mof_verdict(mof(["NULL"]))
    check(verdict == UNVERIFIED and "NULL" in findings[0][3],
          "a NULL password is UNVERIFIED")
    no_pw = ("instance of MSFT_Credential as $c\n{\n UserName = \"u\";\n};\n"
             + mof([]))
    check(mof_verdict(no_pw)[0] == UNVERIFIED,
          "a credential with no Password property is UNVERIFIED")
    broken = "instance of MSFT_Credential as $c\n{\nPassword = \"abc\n"
    check(mof_verdict(broken)[0] == UNVERIFIED,
          "a credential whose string never closes is UNVERIFIED")
    for body, label in (("Password \"x\";", "a property without ="),
                        ("Password = \"x\" }", "a property without ;"),
                        ("Password = \"\\q\";", "an unknown escape")):
        text = "instance of MSFT_Credential as $c\n{\n%s\n};\n" % body
        check(mof_verdict(text)[0] == UNVERIFIED,
              "%s makes the credential UNVERIFIED" % label)
    lower = mof([armoured]).replace("MSFT_Credential", "msft_credential")
    check(mof_verdict(lower)[0] == MOF_ENCRYPTED,
          "class names match without regard to case, as MOF says")
    not_cred = mof([], extra="\ninstance of MSFT_FileResource as $f\n{\n "
                   "Password = \"not-a-credential\";\n};\n")
    check(mof_verdict(not_cred)[0] == MOF_NONE,
          "a Password field outside MSFT_Credential is not a credential")
    bad_doc = mof([armoured], marker=False) + (
        "\ninstance of OMI_ConfigurationDocument\n{\n Version 2;\n};\n")
    check(mof_verdict(bad_doc)[0] == UNVERIFIED,
          "an unreadable OMI_ConfigurationDocument is skipped, not a marker")
    check(mof_verdict(broken)[1][0][2] == UNVERIFIED,
          "the verdict of a credential that cannot be parsed is UNVERIFIED"
          "  <-- pinned defect")
    broken_marked = broken + mof([], marker=True)
    check(mof_verdict(broken_marked)[0] == UNVERIFIED
          and mof_verdict(broken_marked)[1][0][2] == UNVERIFIED,
          "an unparseable credential beside a marked document stays "
          "UNVERIFIED, the marker does not clear it  <-- pinned defect")
    check(mof_verdict(mof([armoured]))[0] == MOF_ENCRYPTED
          and "CompatibleVersionAdditionalProperties" in mof([armoured]),
          "a document header with an array property still sets the marker"
          "  <-- pinned defect")
    for text, label in (("", "an empty file"),
                        ("   \n", "a file of white space"),
                        ("{\"format\": \"nodecheck/1\"}", "a JSON file"),
                        ("instance of MSFT_FileResource as $f\n{\n};\n",
                         "a MOF with only another class")):
        verdict, found = mof_verdict(text)
        check(verdict == UNVERIFIED and found[0][1] == "(document)"
              and "not a DSC MOF" in found[0][3],
              "%s is UNVERIFIED, never NO_MSFT_CREDENTIAL"
              "  <-- pinned defect" % label)
    check(mof_verdict("instance of MSFT_Credential as $c\n{\n")[0]
          == UNVERIFIED, "a credential cut short inside its body is "
          "UNVERIFIED")
    utf16_plain = mof(["Example-Pass-1"]).encode("utf-16-le")
    verdict, found = mof_verdict(decode_text(utf16_plain))
    check(verdict == UNVERIFIED and "NUL" in found[0][3],
          "a UTF-16 MOF with no byte order mark is UNVERIFIED, not clean"
          "  <-- pinned defect")
    # Comments. DSP0221 clause 5.4: a comment is whitespace.
    commented = ("/* instance of MSFT_Credential as $c\n{\nPassword = "
                 "\"Example-Pass-1\";\n};\n*/\n"
                 "// instance of MSFT_Credential as $d { Password = \"x\"; };\n"
                 + mof([armoured]))
    verdict, found = mof_verdict(commented)
    check(verdict == MOF_ENCRYPTED and len(found) == 1,
          "an instance written inside a comment is not a live credential"
          "  <-- pinned defect")
    check(found[0][0] == 11, "a finding after a block comment keeps its "
          "true line number")
    in_body = ("instance of MSFT_Credential as $c\n{\n// a note\nPassword = "
               "/* a note */ \"Example-Pass-1\"; // end\n};\n")
    verdict, found = mof_verdict(in_body)
    check(verdict == MOF_PLAINTEXT and found[0][0] == 1,
          "comments inside a credential body are skipped, and the "
          "plaintext password behind them is found")
    quoted_slashes = ("instance of MSFT_Credential as $c\n{\nPassword = "
                      "\"a//b/*c\";\n};\n")
    check(mof_verdict(quoted_slashes)[0] == MOF_PLAINTEXT,
          "// and /* inside a string literal are not comments")
    for text, label in (("/* never closed\ninstance of MSFT_Credential "
                         "as $c\n{\nPassword = \"x\";\n};\n",
                         "a block comment that is never closed"),
                        ("/*/ x", "a block comment opened by a lone slash")):
        verdict, found = mof_verdict(text)
        check(verdict == UNVERIFIED and "never closed" in found[0][3],
              "%s is UNVERIFIED, it cannot hide a credential" % label)
    check(mof_verdict("/**/\n" + mof([armoured]))[0] == MOF_ENCRYPTED,
          "an empty block comment is a comment")
    check(strip_comments("a / b") == "a / b",
          "a lone slash is not a comment")
    # Password values that are not a string literal. None may echo a token.
    for body, want, label in (
            ("Password = Hunter2Pass;", MOF_PLAINTEXT, "an unquoted token"),
            ("Password = 12345678;", MOF_PLAINTEXT, "an unquoted number"),
            ("Password = ;", MOF_PLAINTEXT, "an empty unquoted value"),
            ("Password = NULL;", UNVERIFIED, "NULL"),
            ("Password = null;", UNVERIFIED, "lower case null"),
            ("Password = $other;", UNVERIFIED, "a reference"),
            ("Password = {\"Hunter2Pass\", \"b\"};", UNVERIFIED, "an array"),
            ("Password = \"ab\\Xcd\";", UNVERIFIED, "an unknown escape")):
        text = "instance of MSFT_Credential as $c\n{\n%s\n};\n" % body
        verdict, found = mof_verdict(text)
        shown = " ".join(str(part) for row in found for part in row)
        check(verdict == want and "Hunter2Pass" not in shown
              and "12345678" not in shown and "\\X" not in shown
              and "other" not in shown and "X" not in found[0][3],
              "%s is %s and its text never reaches the report"
              "  <-- pinned defect" % (label, want))
    check(mof_verdict("instance of MSFT_Credential as $c\n{\nPassword = "
                      "\"Exam\"\n  \"ple\";\n};\n")[0] == MOF_PLAINTEXT,
          "adjacent string literals join into one value")
    check(mof_verdict("instance of MSFT_Credential as $c\n{\nPassword = "
                      "\"a\\b\\fc\";\n};\n")[0] == MOF_PLAINTEXT,
          "the backspace and form feed escapes are read")
    for text, label in (("{\"a\" \"b\"", "an array that is never closed"),
                        ("{\"a\" \"b\" 3}", "two values with no comma")):
        raises(lambda: _mof_value(text, 0), "%s is refused" % label,
               "array")
    check(_mof_value("{ 1, \"a\" , }", 0) == (("array", 2), 12),
          "an array of two values with a trailing comma is counted")
    check(_mof_value("{}", 0) == (("array", 0), 2), "an empty array is read")
    no_alias = "instance of MSFT_Credential\n{\nPassword = \"x\";\n};\n"
    check(mof_verdict(no_alias)[1][0][1] == "(no alias)",
          "a credential without an alias is still found")
    check(decode_text(mof([armoured]).encode("utf-16")) == mof([armoured]),
          "a UTF-16 MOF with a BOM is read")
    check(decode_text(b"\xef\xbb\xbfabc") == "abc",
          "a UTF-8 MOF with a BOM is read")
    raises(lambda: decode_text(b"\xff\x00abc"),
           "a MOF that is neither UTF-8 nor UTF-16 is refused", "not UTF-8")

    # ---- probes, against real sockets and fake registries
    class Stub(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Stub)
    worker = threading.Thread(target=server.serve_forever)
    worker.daemon = True
    worker.start()
    open_port = server.server_address[1]
    check(tcp_open("127.0.0.1", open_port) is True,
          "a port with the local stub server listening is open")
    spare = socket.socket()
    spare.bind(("127.0.0.1", 0))
    closed_port = spare.getsockname()[1]
    spare.close()
    check(tcp_open("127.0.0.1", closed_port) is False,
          "a port nobody listens on is closed")

    def no_dns(address, timeout):
        raise socket.gaierror(11001, "name does not resolve")

    value, error = collect("tcp:db.example.test:1433", ".", {"tcp": (
        lambda host, port: tcp_open(host, port, connect=no_dns))})
    check(value is None and error.startswith("gaierror"),
          "a name that does not resolve is an error, not a closed port"
          "  <-- pinned defect")
    value, error = collect("tcp:127.0.0.1:%d" % open_port, ".")
    check(value is True and error is None,
          "the tcp collector reaches the stub through the fact key")
    with contextlib.closing(urllib.request.urlopen(
            "http://127.0.0.1:%d/" % open_port, timeout=5)) as reply:
        check(reply.status == 200,
              "the stub server answers a real HTTP request, so it is a "
              "real server and not a bare socket")

    def refused(address, timeout):
        raise ConnectionRefusedError(10061, "refused")

    def timed_out(address, timeout):
        raise socket.timeout("timed out")

    def unreachable(address, timeout):
        raise OSError(101, "network is unreachable")

    check(tcp_open("192.0.2.1", 1, connect=refused) is False,
          "a refused connection is the one answer that means closed")
    for fake, label in ((timed_out, "a timeout"),
                        (unreachable, "an unreachable network")):
        value, error = collect("tcp:192.0.2.1:1434", ".", {"tcp": (
            lambda host, port, fake=fake: tcp_open(host, port,
                                                   connect=fake))})
        check(value is None and error is not None,
              "%s is an error, not a closed port  <-- pinned defect" % label)
    verdict, detail = evaluate(
        {"fact": "tcp:192.0.2.1:1434", "op": "==", "value": False, "why": ""},
        [("f.json", read_facts(facts_doc(errors={
            "tcp:192.0.2.1:1434": "timeout"}), "node-a", now, 24.0))])
    check(verdict == UNVERIFIED,
          "a port that must be closed is UNVERIFIED when the probe timed out"
          "  <-- pinned defect")
    server.shutdown()
    server.server_close()

    value, error = collect("disk_free_gb:.", ".")
    check(isinstance(value, float) and value >= 0 and error is None,
          "free space on this host's working directory is a number of GB")
    gib = float(1024 ** 3)
    check([disk_free_gb("x", usage=lambda p: type("U", (), {"free": int(n)})())
           for n in (39.96 * gib, 40 * gib, 0)] == [39.9, 40.0, 0.0],
          "free space is cut down to 0.1 GiB, so 39.96 does not meet 40"
          "  <-- pinned defect")
    tmp = tempfile.mkdtemp(prefix="nodecheck-selftest-")
    value, error = collect("disk_free_gb:%s" % os.path.join(tmp, "absent"),
                           ".")
    check(value is None and "Error" in error,
          "free space on a path that does not exist is an error")

    class FakeReg(object):
        HKEY_LOCAL_MACHINE = "HKLM"
        KEY_READ = 1
        KEY_WOW64_64KEY = 256

        def __init__(self, values):
            self.values = values
            self.opened = None
            self.closed = False

        def OpenKey(self, root, path, reserved, access):
            self.opened = (root, path, access)
            return "key"

        def QueryInfoKey(self, key):
            return (0, len(self.values), 0)

        def EnumValue(self, key, index):
            name, data = self.values[index]
            return name, data, 1

        def CloseKey(self, key):
            self.closed = True

    reg = FakeReg([("SQL Server", "Installed"),
                   ("ODBC Driver 18 for SQL Server", "Installed"),
                   ("Half Removed", "")])
    check(odbc_drivers(reg) == ["ODBC Driver 18 for SQL Server",
                                "SQL Server"],
          "only drivers whose value reads Installed are listed")
    check(reg.opened == ("HKLM", ODBC_DRIVERS_KEY, 257) and reg.closed,
          "the 64-bit view of the ODBC Drivers key is opened and closed")
    value, error = collect("odbc_drivers", ".", {"odbc": (
        lambda: odbc_drivers(None))})
    check(value is None and "no Windows registry" in error,
          "without a registry the driver list is an error, not empty"
          "  <-- pinned defect")
    value, error = collect("odbc_drivers", ".")
    check(isinstance(value, list) or "no Windows registry" in error,
          "the real registry probe returns a list on Windows, an error "
          "elsewhere")
    value, error = collect("os.system", ".")
    check(isinstance(value, str) and value and error is None,
          "the operating system name is collected")
    value, error = collect("local_admin:svc-example", ".")
    check(value is None and "supply it by hand" in error,
          "a fact with no collector asks to be supplied by hand")

    def tmpfile(name, text, encoding="utf-8"):
        path = os.path.join(tmp, name)
        with open(path, "w", encoding=encoding) as out:
            out.write(text)
        return path

    tmpfile("enc.mof", mof([armoured]))
    tmpfile("plain.mof", mof(["Example-Pass-1"]))
    tmpfile("nomark.mof", mof([armoured], marker=False))
    check(collect("mof:enc.mof", tmp) == (MOF_ENCRYPTED, None),
          "a mof fact is read relative to the table's folder")
    check(collect("mof:plain.mof", tmp) == (MOF_PLAINTEXT, None),
          "a plaintext MOF is the fact PLAINTEXT")
    value, error = collect("mof:nomark.mof", tmp)
    check(value is None and "PasswordEncrypted" in error,
          "an UNVERIFIED MOF is a probe error, so no op can read it as met")
    value, error = collect("mof:absent.mof", tmp)
    check(value is None and error.startswith("FileNotFoundError"),
          "a MOF that is not there is an error")

    stamp = datetime.datetime(2026, 1, 31, 9, 30, 0,
                              tzinfo=datetime.timezone.utc)
    doc = gather("node-a", ["os.machine", "local_admin:svc-example"], tmp, stamp,
                 host="authoring-01")
    check(doc["gathered"] == "2026-01-31T09:30:00Z" and doc["node"] == "node-a"
          and "os.machine" in doc["facts"]
          and "local_admin:svc-example" in doc["errors"],
          "gather records each fact as a value or as an error, never both")
    check(read_facts(doc, "node-a", now, 24.0)["problem"] is None,
          "what gather writes, read_facts accepts")
    hand = json.loads(json.dumps(doc))
    hand["gathered"] = format_time(now)
    hand["errors"].pop("local_admin:svc-example")
    hand["facts"]["local_admin:svc-example"] = ["svc-example"]
    check(evaluate({"fact": "local_admin:svc-example", "op": "contains",
                    "value": "svc-example", "why": ""},
                   [("f.json", read_facts(hand, "node-a", now, 24.0))])[0]
          == OBSERVED,
          "a hand-supplied fact moved from errors to facts in the gathered "
          "file is judged, the way the README says")
    check(gather("node-a", [], tmp, stamp)["gathered_on"] == platform.node(),
          "gather names the host it ran on")

    # ---- the command line, end to end on synthetic files
    the_table = {
        "format": TABLE_FORMAT, "max_age_hours": 24,
        "note": "synthetic example",
        "roles": {
            "server": [
                {"fact": "odbc_drivers", "op": "contains",
                 "value": "ODBC Driver 18 for SQL Server",
                 "why": "the geodatabase connection uses it"},
                {"fact": "disk_free_gb:.", "op": ">=", "value": 0}],
            "sql-host": [
                {"fact": "linked_server_providers", "op": "excludes",
                 "value": ["SQLNCLI", "SQLNCLI10", "SQLNCLI11"]}],
            "authoring": [
                {"fact": "mof:enc.mof", "op": "in",
                 "value": [MOF_ENCRYPTED, MOF_NONE]}]},
        "nodes": [
            {"name": "node-a", "roles": ["server", "authoring"],
             "facts": ["node-a.json", "manual-a.json"]},
            {"name": "node-b", "roles": ["sql-host"],
             "facts": "node-b.json"}]}
    table_path = tmpfile("nodes.json", json.dumps(the_table))
    fresh = format_time(_utcnow())
    tmpfile("node-a.json", json.dumps(facts_doc(
        gathered=fresh, facts={
            "odbc_drivers": ["ODBC Driver 18 for SQL Server"],
            "disk_free_gb:.": 50.0, "mof:enc.mof": MOF_ENCRYPTED})))
    tmpfile("manual-a.json", json.dumps(facts_doc(gathered=fresh)))
    tmpfile("node-b.json", json.dumps(facts_doc(
        node="node-b", gathered=fresh, facts={
            "linked_server_providers": ["SQLNCLI11"]})))

    code, out, err = run_cli(["check", table_path, "--node", "node-a"])
    check(code == 0 and "3 OBSERVED" in out and "PASS" not in out,
          "check on a node whose every fact is met exits 0, without PASS")
    code, out, err = run_cli(["check", table_path])
    check(code == 1 and "holds [\"SQLNCLI11\"]" in out,
          "check over the table exits 1 on the deprecated provider")
    tmpfile("node-b.json", "{not json")
    code, out, err = run_cli(["check", table_path, "--node", "node-b"])
    check(code == 3 and "NOT USED: cannot read" in out,
          "an unparseable facts file is UNVERIFIED, not a crash")
    os.remove(os.path.join(tmp, "node-b.json"))
    code, out, err = run_cli(["check", table_path, "--node", "node-b"])
    check(code == 3 and "NOT USED: cannot read: No such file" in out,
          "a facts file not yet gathered is UNVERIFIED, exit 3")
    code, out, err = run_cli(["check", table_path, "--node", "node-q"])
    check(code == 64 and "no node named node-q" in err,
          "check on a node the table lacks is a usage error")

    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk_free_gb:"])
    check(code == 0 and json.loads(out)["facts"].get("disk_free_gb:.")
          is not None and "Check only" not in err,
          "gather prints the facts as JSON and writes nothing")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a"])
    check(code in (0, 3) and json.loads(out)["facts"]["mof:enc.mof"]
          == MOF_ENCRYPTED,
          "gather runs every collector the node needs")
    code, out, err = run_cli(["gather", table_path, "--node", "node-b"])
    check(code == 3 and "linked_server_providers" in json.loads(out)["errors"],
          "gather exits 3 when a fact could not be collected")
    out_path = os.path.join(tmp, "gathered.json")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk", "--out", out_path])
    check(code == 0 and not os.path.exists(out_path)
          and "Check only. %s was not written" % out_path in err,
          "gather --out without --apply writes nothing")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk", "--out", out_path, "--apply"])
    with open(out_path, encoding="utf-8") as handle:
        written = json.load(handle)
    check(code == 0 and written["node"] == "node-a" and "wrote" in err,
          "gather --out --apply writes the facts file")
    check(not [n for n in os.listdir(tmp) if n.startswith(".nodecheck-")],
          "the write leaves no temporary file behind")
    nested = os.path.join(tmp, "absent", "deeper", "x.json")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk", "--out", nested, "--apply"])
    check(code == 0 and os.path.isfile(nested),
          "gather --out --apply creates the folder it writes into, so the "
          "first command in the README works on a fresh checkout"
          "  <-- pinned defect")
    before = open(table_path, "rb").read()
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk", "--out", table_path,
                              "--apply"])
    check(code == 2 and "was not replaced" in err
          and open(table_path, "rb").read() == before,
          "gather --out aimed at the node table is refused and the table is "
          "untouched  <-- pinned defect")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk", "--out", tmp, "--apply"])
    check(code == 2 and "could not write" in err,
          "gather --out aimed at a folder exits 2")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk", "--out",
                              os.path.join(tmp, "enc.mof", "x.json"),
                              "--apply"])
    check(code == 2 and "could not write" in err,
          "a folder that cannot be made exits 2")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "disk", "--out", nested, "--apply"])
    check(code == 0, "gather --out replaces an older facts file")
    _write_atomic(os.path.join(tmp, "dir-target"), "x")
    os.remove(os.path.join(tmp, "dir-target"))
    os.mkdir(os.path.join(tmp, "dir-target"))
    outcome = "replaced"
    try:
        _write_atomic(os.path.join(tmp, "dir-target"), "x")
    except OSError:
        outcome = "refused"
    check(outcome == "refused" and not [n for n in os.listdir(tmp)
                                        if n.startswith(".nodecheck-")],
          "a failed replace removes its temporary file")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--only", "tcp:"])
    check(code == 64 and "requires no fact starting with" in err,
          "gather with an --only that matches nothing is a usage error")
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--apply"])
    check(code == 64 and "--apply needs --out" in err,
          "gather --apply without --out is a usage error")

    code, out, err = run_cli(["mof", os.path.join(tmp, "enc.mof")])
    check(code == 0 and "ENCRYPTED  1 credential(s)" in out,
          "mof on an encrypted MOF exits 0")
    code, out, err = run_cli(["mof", os.path.join(tmp, "plain.mof"),
                              os.path.join(tmp, "nomark.mof")])
    check(code == 1 and "Example-Pass-1" not in out,
          "mof exits 1 on a plaintext MOF and never prints the password"
          "  <-- pinned defect")
    code, out, err = run_cli(["mof", os.path.join(tmp, "nomark.mof"),
                              os.path.join(tmp, "plain.mof")])
    check(code == 1, "a plaintext MOF outranks an UNVERIFIED one in any order")
    code, out, err = run_cli(["mof", os.path.join(tmp, "nomark.mof"),
                              os.path.join(tmp, "enc.mof")])
    check(code == 3 and "(document)" in out,
          "mof exits 3 when the worst MOF is UNVERIFIED")
    code, out, err = run_cli(["mof", os.path.join(tmp, "absent.mof")])
    check(code == 2 and "absent.mof" in err, "a MOF that cannot be read "
          "exits 2")
    code, out, err = run_cli(["mof", os.path.join(tmp, "enc.mof"),
                              os.path.join(tmp, "absent.mof"),
                              os.path.join(tmp, "plain.mof")])
    check(code == 1 and "plain.mof: PLAINTEXT" in out
          and "enc.mof: ENCRYPTED" in out and "absent.mof" in err,
          "an unreadable MOF does not stop the run: a plaintext MOF after it "
          "is still found and exits 1  <-- pinned defect")
    code, out, err = run_cli(["mof", os.path.join(tmp, "absent.mof"),
                              os.path.join(tmp, "nomark.mof")])
    check(code == 2 and "nomark.mof: UNVERIFIED" in out,
          "an unreadable MOF outranks an UNVERIFIED one, and both are "
          "reported")
    check([mof_exit(c) for c in ([], [0], [3], [2, 3], [3, 2, 1], [0, 3])]
          == [0, 0, 3, 2, 1, 3],
          "the MOF exit code ranks 1 over 2 over 3 over 0")
    tmpfile("empty.mof", "")
    code, out, err = run_cli(["mof", os.path.join(tmp, "empty.mof")])
    check(code == 3 and "not a DSC MOF" in out,
          "mof on an empty file exits 3, not 0  <-- pinned defect")
    tmpfile("bare.mof", "instance of MSFT_Credential as $c\n{\nPassword = "
            "Hunter2Pass;\nUserName = \"u\";\n};\n")
    code, out, err = run_cli(["mof", os.path.join(tmp, "bare.mof")])
    check(code == 1 and "Hunter2Pass" not in out + err,
          "an unquoted password exits 1 and is never printed"
          "  <-- pinned defect")
    tmpfile("dup.json", "{\"format\": \"nodecheck/1\", \"nodes\": "
            "[{\"name\": \"n\", \"requires\": [{\"fact\": \"x\", \"op\": "
            "\"==\", \"value\": 1}], \"requires\": []}]}")
    code, out, err = run_cli(["check", os.path.join(tmp, "dup.json")])
    check(code == 2 and "appears twice" in err and "\"requires\"" in err,
          "a node with two requires keys is refused, the first block of "
          "checks is not dropped  <-- pinned defect")
    tmpfile("dup-roles.json", "{\"format\": \"nodecheck/1\", \"roles\": "
            "{\"a\": [], \"a\": []}, \"nodes\": [{\"name\": \"n\"}]}")
    code, out, err = run_cli(["check", os.path.join(tmp, "dup-roles.json")])
    check(code == 2 and "appears twice" in err,
          "a role defined twice is refused  <-- pinned defect")
    tmpfile("odd-facts.json", "{\"x\": 1, \"x\": 2}")
    check_table = tmpfile("one.json", json.dumps({
        "format": TABLE_FORMAT, "nodes": [{
            "name": "node-a", "facts": ["odd-facts.json"],
            "requires": [{"fact": "x", "op": "==", "value": 2}]}]}))
    code, out, err = run_cli(["check", check_table])
    check(code == 3 and "NOT USED: cannot read" in out
          and "appears twice" in out,
          "a facts file with a repeated key is not used, so 2 never wins"
          "  <-- pinned defect")
    for text, label in (("{\"x\": NaN}", "NaN"), ("{\"x\": 1e999}", "1e999"),
                        ("{\"x\": -Infinity}", "-Infinity")):
        tmpfile("odd-facts.json", text)
        code, out, err = run_cli(["check", check_table])
        check(code == 3 and "NOT USED: cannot read" in out,
              "a facts file holding %s is not used, UNVERIFIED  "
              "<-- pinned defect" % label)
    tmpfile("odd-facts.json", json.dumps(facts_doc(
        gathered=format_time(_utcnow()), facts={"x": 10 ** 400})))
    code, out, err = run_cli(["check", check_table])
    check(code == 1 and "Traceback" not in err,
          "an integer of 400 digits in a facts file is judged, not a "
          "traceback  <-- pinned defect")
    tmpfile("big-age.json", "{\"format\": \"nodecheck/1\", "
            "\"max_age_hours\": 1" + "0" * 400 + ", \"nodes\": "
            "[{\"name\": \"n\"}]}")
    code, out, err = run_cli(["check", os.path.join(tmp, "big-age.json")])
    check(code == 64 and "max_age_hours" in err,
          "a max age of 400 digits exits 64, not with a traceback"
          "  <-- pinned defect")

    code, out, err = run_cli(["check", os.path.join(tmp, "absent.json")])
    check(code == 2, "a table that cannot be read exits 2")
    bad = tmpfile("bad.json", "[1,")
    code, out, err = run_cli(["check", bad])
    check(code == 2 and "not valid JSON" in err,
          "a table that is not JSON exits 2")
    invalid = tmpfile("invalid.json", json.dumps({"format": "x"}))
    code, out, err = run_cli(["check", invalid])
    check(code == 64 and "format must be" in err,
          "a table that is JSON but not a node table exits 64")
    bom = tmpfile("bom.json", json.dumps(the_table), encoding="utf-8-sig")
    code, out, err = run_cli(["check", bom, "--node", "node-a"])
    check(code == 0, "a table saved with a byte order mark is read")
    u16 = tmpfile("table16.json", json.dumps(the_table), encoding="utf-16")
    code, out, err = run_cli(["check", u16, "--node", "node-a"])
    check(code == 0, "a table saved as UTF-16 with a byte order mark is read")
    code, out, err = run_cli(["example"])
    example = load_table(json.loads(out))
    check(code == 0 and out == EXAMPLE_TABLE and len(example["nodes"]) == 2
          and example["nodes"][1]["facts"] == ["facts/node-b.json",
                                               "facts/node-b-authoring.json"],
          "the example command prints a node table that load_table accepts")
    check(len(example["nodes"][0]["requirements"]) == 5
          and example["nodes"][1]["requirements"][-1]["fact"]
          == "license_seats",
          "the example's roles and its own requires both reach the node")
    odd = tmpfile("odd-why.json", json.dumps({
        "format": TABLE_FORMAT, "nodes": [{
            "name": "node-\u0416", "facts": ["u16.json", "nul.json"],
            "requires": [{"fact": "x", "op": ">=", "value": 5,
                          "why": "needs \u2265 5 \x1b[31mred"}]}]}))
    tmpfile("u16.json", json.dumps(facts_doc(
        node="node-\u0416", gathered=format_time(_utcnow()),
        facts={"x": 1})), encoding="utf-16")
    tmpfile("nul.json", json.dumps(facts_doc()), encoding="utf-16-le")
    code, out, err = run_cli(["check", odd])
    check(code == 1 and "FAIL" in out and "observed 1" in out,
          "a facts file saved as UTF-16 with a byte order mark is read, as "
          "Windows PowerShell 5 writes it  <-- pinned defect")
    check("holds NUL characters" in out and "NOT USED" in out,
          "a UTF-16 file with no byte order mark says why it is not read"
          "  <-- pinned defect")
    check(all(32 <= ord(c) < 127 or c == "\n" for c in out + err)
          and "\\x1b[31mred" in out and "\\u2265" in out
          and "node-\\u0416" in out,
          "control characters and non-ASCII text in a why or a node name "
          "are escaped, so the report is never cut short and never moves "
          "the cursor  <-- pinned defect")
    check(_plain("a\U0001f600\tb") == "a\\U0001f600\\x09b",
          "a character beyond the first plane is escaped in full")
    code, out, err = run_cli(["mof", os.path.join(tmp, "caf\xe9.mof")])
    check(code == 2 and "caf\\xe9.mof" in err,
          "a file name with a non-ASCII letter is escaped in an error")
    code, out, err = run_cli([])
    check(code == 64 and "name a command" in err,
          "no command is a usage error")
    code, out, err = run_cli(["--help"])
    check(code == 0 and "gather" in out, "--help exits 0 and lists commands")

    # With abbreviations on, --ap parses as --apply and writes the file.
    code, out, err = run_cli(["gather", table_path, "--node", "node-a",
                              "--out", out_path, "--ap"])
    check(code == 64 and "unrecognized arguments: --ap" in err,
          "a unique prefix of --apply is refused, not read as --apply"
          "  <-- pinned defect")
    code, out, err = run_cli(["gather", table_path, "--no", "node-a"])
    check(code == 64, "a unique prefix of --node is refused too")
    code, out, err = run_cli(["--self", "--ap"])
    check(code == 64, "a prefix of --self-test is refused at the top level")

    # ---- the harness itself
    mark = len(failed)
    probe_out = io.StringIO()
    with contextlib.redirect_stdout(probe_out):
        check(False, "probe one")
        raises(lambda: None, "probe two")
        raises(lambda: {}["x"], "probe three")
        raises(lambda: parse_version("x"), "probe four", "absent words")
    probe = failed[mark:]
    del failed[mark:]
    check(len(probe) == 4,
          "check() and raises() really do record a failure  <-- pinned defect")

    def summary(passed_count, failures):
        print("-" * 68)
        total = passed_count + len(failures)
        if failures:
            print("%d assertions, %d failed" % (total, len(failures)))
            for f in failures:
                print("  FAILED: %s" % f)
            return 1
        print("%d assertions, 0 failed" % total)
        return 0

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        red = summary(1, ["probe one", "probe two"])
    check(red == 1 and "3 assertions, 2 failed" in buf.getvalue()
          and "  FAILED: probe two" in buf.getvalue(),
          "the footer reports failures by count and by name, and exits 1"
          "  <-- pinned defect")

    spec = importlib.util.spec_from_file_location(
        "nodecheck_imported", os.path.abspath(__file__))
    imported = importlib.util.module_from_spec(spec)
    buf = io.StringIO()
    cache_before = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        with contextlib.redirect_stdout(buf):
            spec.loader.exec_module(imported)
    finally:
        sys.dont_write_bytecode = cache_before
    check(buf.getvalue() == "" and imported.gate([]) == 0,
          "importing the module prints nothing and exposes the core")

    shutil.rmtree(tmp, ignore_errors=True)
    return summary(passed[0], failed)


if __name__ == "__main__":
    sys.exit(main())
