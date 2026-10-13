# nodecheck

Check install-time prerequisites against a table of nodes, and report each one as FAIL, UNVERIFIED
or OBSERVED. There is no PASS. Includes `mof`, which finds plaintext passwords in compiled DSC MOF
files.

A three-node install passed its prerequisite sweep. The sweep was a script with the topology typed
into it. It probed each node for the ODBC driver, the linked-server provider and the licence. A
probe that threw an error was read as "absent" or was left out of the summary. The last line said
every checked item was fine, and half the items had never been checked.

Two weeks later the install failed on a node. A linked server still used a provider that its vendor
no longer ships. A compiled DSC MOF in the same job held a service password in clear text. The
sweep could not have found either one, because nobody had told it to look. (This is a composite
story, not a report of one site.)

The fix is not a longer script. It is a script that cannot say "fine" about something it did not
see. `nodecheck` splits the sweep in two. A node table says what each node requires. A facts file
says what a node was observed to have, and when. The check compares the two. A requirement with no
usable fact is UNVERIFIED. It is never counted as met.

```
FAIL        the facts show the requirement is not met
UNVERIFIED  no usable fact: missing, stale, failed, conflicting or of the wrong shape
OBSERVED    the fact met the requirement when it was gathered
```

OBSERVED is evidence about one moment. It is not a promise that the install will work.

```
$ python nodecheck.py --self-test
nodecheck self-test: synthetic table, local stub server, no credentials
--------------------------------------------------------------------
ok    a table without max_age_hours gets the 24 hour default
...
ok    a misspelt requires key is refused, not silently dropped  <-- pinned defect
...
ok    a tcp port of 65536 is refused, the first one past the range  <-- pinned defect
...
ok    exactly the allowed clock skew is tolerated, the limit is inclusive  <-- pinned defect
...
ok    the summary puts each count under its own verdict, 2 / 3 / 1  <-- pinned defect
...
ok    the verdict of a credential that cannot be parsed is UNVERIFIED  <-- pinned defect
...
ok    an empty file is UNVERIFIED, never NO_MSFT_CREDENTIAL  <-- pinned defect
...
ok    an unquoted token is PLAINTEXT and its text never reaches the report  <-- pinned defect
...
ok    a name that does not resolve is an error, not a closed port  <-- pinned defect
...
ok    a timeout is an error, not a closed port  <-- pinned defect
...
ok    free space is cut down to 0.1 GiB, so 39.96 does not meet 40  <-- pinned defect
...
ok    gather --out --apply creates the folder it writes into, so the first command in the README works on a fresh checkout  <-- pinned defect
ok    gather --out aimed at the node table is refused and the table is untouched  <-- pinned defect
...
ok    mof exits 1 on a plaintext MOF and never prints the password  <-- pinned defect
...
ok    an unreadable MOF does not stop the run: a plaintext MOF after it is still found and exits 1  <-- pinned defect
...
ok    a facts file with a repeated key is not used, so 2 never wins  <-- pinned defect
...
ok    a facts file saved as UTF-16 with a byte order mark is read, as Windows PowerShell 5 writes it  <-- pinned defect
...
ok    control characters and non-ASCII text in a why or a node name are escaped, so the report is never cut short and never moves the cursor  <-- pinned defect
...
ok    a unique prefix of --apply is refused, not read as --apply  <-- pinned defect
...
ok    check() and raises() really do record a failure  <-- pinned defect
ok    the footer reports failures by count and by name, and exits 1  <-- pinned defect
ok    importing the module prints nothing and exposes the core
--------------------------------------------------------------------
260 assertions, 0 failed
```

The full run prints all 260 assertions. Each `...` line above is where this block is cut. The
harness prints `ok` and not `PASS` for a passing assertion, because this tool never uses that word.

## What already exists

Checks as code are a solved problem. [Pester](https://pester.dev/docs/quick-start) describes itself
as "a testing and mocking framework for PowerShell". The GitHub projects
[Serverspec](https://github.com/mizzy/serverspec) ("RSpec tests for your servers") and
[InSpec](https://github.com/inspec/inspec) ("Auditing and Testing Framework") do the same for
servers in general. Each is far more general than this tool. A check in those tools is code that you write.

This tool takes the opposite trade. The checks are a fixed list of six comparisons. In return, the
rule "a fact nobody observed is not a pass" is in the tool and not in each author's code. A missing
fact, a stale file, a failed probe, a fact for the wrong node and two files that disagree are all
UNVERIFIED. I did not test whether a Pester or InSpec suite can be written to behave the same way.

On 2026-10-13 a GitHub search for `nodecheck` found a GraphQL schema linter
([gqlgo/nodecheck](https://github.com/gqlgo/nodecheck)), a web uptime monitor family
([apocas/nodechecker.com](https://github.com/apocas/nodechecker.com)) and a Node.js monitor
([evantahler/nodeChecker](https://github.com/evantahler/nodeChecker)). None of them checks install
prerequisites from a table of nodes. That shows only what the search found.

Microsoft DSC already refuses to compile a plaintext password unless the configuration data sets
`PsDscAllowPlainTextPassword` ([Credentials Options in Configuration Data](https://learn.microsoft.com/en-us/powershell/dsc/configurations/configdatacredentials?view=dsc-1.1)).
That check runs on the authoring host at compile time. The `mof` command reads MOF files that
already exist, such as the ones on a share.

## Requirements

Python 3.9 or newer and nothing else. No third-party package. The self-test opens a local HTTP stub
on `127.0.0.1` and removes its temporary files at the end.

The self-test prints the same 260 assertions on Windows (Python 3.13.2), on Python 3.9.25 and on
Ubuntu (Python 3.12.3). `coverage run --branch nodecheck.py --self-test` reports 100 percent of
lines and branches on Windows.

```
git clone https://github.com/uhsear/nodecheck.git
```

## Usage

```
python nodecheck.py --self-test
python nodecheck.py example > nodes.json
python nodecheck.py gather nodes.json --node node-a
python nodecheck.py gather nodes.json --node node-a --out facts/node-a.json --apply
python nodecheck.py gather nodes.json --node node-a --only tcp:
python nodecheck.py check nodes.json
python nodecheck.py check nodes.json --node node-a
python nodecheck.py mof dsc/node-a.mof dsc/node-b.mof
```

Run `gather` on each node. It observes this host only. Copy the facts files to one place. Run
`check` there.

| Flag | What it does |
|---|---|
| `--node NAME` | On `gather`: the node this host is. Required. On `check`: check only this node. |
| `--only PREFIX` | On `gather`: collect only the facts whose key starts with PREFIX. |
| `--out PATH` | On `gather`: the facts file to write. Needs `--apply`. |
| `--apply` | On `gather`: actually write `--out`. Without it nothing is written. |
| `--self-test` | Run the assertions and exit. |

Every flag must be spelled in full. The parser sets `allow_abbrev=False`, so `--ap` is refused with
exit 64 and is not read as `--apply`.

Nothing writes without `--apply`, and only `gather --out` writes. It makes the folder if the folder
is missing. It replaces an existing file only when that file is a nodecheck facts file, so an
`--out` that names the node table is refused and the table is untouched. The tool writes a
temporary file in the same folder and renames it over the target.

## The node table

`python nodecheck.py example` prints a complete table. Every name in it is made up. The self-test
loads that exact text, so the example cannot drift away from the format.

```
{
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
```

The table is JSON in UTF-8, or in UTF-16 with a byte order mark. A key that the format does not name
is refused, so a misspelt `requires` cannot silently drop its checks. A key that appears twice in
one object is refused for the same reason.

| Key | Meaning |
|---|---|
| `format` | `"nodecheck/1"`. Required. |
| `max_age_hours` | A positive number. Default 24. A facts file older than this is not used. |
| `roles` | Role name to a list of requirements. Optional. |
| `nodes` | A non-empty list. Required. |
| `note` | Text for a human. Ignored. Allowed on the table and on a node. |

Each node has `name` (unique), `roles` (a list of role names), `facts` (a path or a list of paths,
relative to the table's folder) and `requires` (its own requirements, added to its roles'). A
requirement that two roles share counts once. A node with no `facts` path is UNVERIFIED on every
line.

A requirement is `{"fact": KEY, "op": OP, "value": V, "why": TEXT}`. The `why` is optional and is
printed under the verdict.

| `op` | The requirement is met when |
|---|---|
| `==` | The fact equals V. A boolean never equals a number. |
| `>=` | The fact is a number and is at least V. |
| `version>=` | The fact is a dotted version and is at least V. `18.3` equals `18.3.0`. |
| `contains` | The fact is a list that holds V. |
| `excludes` | The fact is a list that holds none of the values in V. |
| `in` | The fact is one of the values in V. |

A fact the op cannot read is UNVERIFIED, not FAIL. For example, `>=` against a string gives
UNVERIFIED.

## What `gather` observes

Only these keys have a collector:

| Fact key | Value | Where it comes from |
|---|---|---|
| `tcp:HOST:PORT` | `true` or `false` | A TCP connect from this host. `false` only for a refused connection. |
| `disk_free_gb:PATH` | A number | Free GiB at PATH, cut down to 0.1. |
| `odbc_drivers` | A list of names | The Windows registry. Windows only. |
| `mof:PATH` | `ENCRYPTED`, `PLAINTEXT` or `NO_MSFT_CREDENTIAL` | The `mof` check below. PATH is relative to the table. |
| `os.system`, `os.release`, `os.version`, `os.machine` | Text | Python `platform`. |

Everything else is supplied by hand. This includes the deprecated linked-server provider and the
licence from the story above. `gather` has no collector for either one. It records `no collector
for this fact` under `errors` and exits 3. To supply the value, edit the gathered file. Delete the
key under `errors` and add it under `facts`. Do not put it in a second file, because a value in
one file and an error in another file conflict, and the answer is UNVERIFIED.

A probe that cannot observe a fact records an error. It never records a guess. A timeout, an
unreachable network and a name that does not resolve are errors. A connection that is refused is the
only answer that means a port is closed, because only then did the host answer
([Python: ConnectionRefusedError](https://docs.python.org/3.12/library/exceptions.html#ConnectionRefusedError)
"corresponds to `errno` ECONNREFUSED"; a timeout is a separate error).

The ODBC list reads `HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers`. Microsoft says
the values under that subkey "list the installed drivers", each with the data `Installed`
([ODBC Drivers Subkey](https://learn.microsoft.com/en-us/sql/odbc/reference/install/odbc-drivers-subkey?view=sql-server-ver16)).
The probe opens the key with `KEY_WOW64_64KEY`, which gives the 64-bit view from any process
([Accessing an Alternate Registry View](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view)).

## The facts file

`gather --apply` writes it. `check` reads it.

```
{
  "format": "nodecheck-facts/1",
  "node": "node-a",
  "gathered": "2026-01-31T12:00:00Z",
  "gathered_on": "host name",
  "facts": {"os.system": "Windows"},
  "errors": {"odbc_drivers": "OSError: no Windows registry on this platform"}
}
```

A facts file is not used when it is for another node, is older than `max_age_hours`, is stamped more
than five minutes in the future, is not valid JSON, repeats a key, holds `NaN` or a number too large
to read, or cannot be opened. The report prints `NOT USED` and the reason. UTF-8 and UTF-16 with a
byte order mark are both read.

## A real run

These runs are on this tool's own synthetic table: a local `python -m http.server` for the open port
and nothing on the closed port. The `odbc_drivers` line is a real read of the registry of the
Windows 11 host. The host names are replaced. The ODBC list is cut to fit.

```
$ python nodecheck.py gather nodes.json --node node-a --out facts/node-a.json --apply
wrote facts/node-a.json
$ python nodecheck.py check nodes.json --node node-a
node-a  [server, authoring, authoring-b]
  facts  facts/node-a.json  gathered 2026-10-13T21:18:48Z on build-host-1, 0.0 h old
  OBSERVED    os.system == "Windows"
  FAIL        odbc_drivers contains "ODBC Driver 18 for SQL Server"
              observed ["Microsoft Access Driver (*.mdb, *.accdb)", ...
  OBSERVED    disk_free_gb:C:\ >= 40
  OBSERVED    tcp:127.0.0.1:18431 == true
  OBSERVED    tcp:127.0.0.1:18432 == false
  OBSERVED    mof:dsc/node-a.mof in ["ENCRYPTED", "NO_MSFT_CREDENTIAL"]
  FAIL        mof:dsc/node-b.mof in ["ENCRYPTED", "NO_MSFT_CREDENTIAL"]
              observed "PLAINTEXT"
```

The `facts` folder did not exist before the first command, and the command made it. The same table
gathered on Ubuntu (Python 3.12.3) has no registry and no `C:\` drive, so those two lines are
UNVERIFIED. The run still exits 1, because `os.system` is Linux and `node-b.mof` is PLAINTEXT:

```
  UNVERIFIED  odbc_drivers contains "ODBC Driver 18 for SQL Server"
              probe failed in facts/node-a.json: OSError: no Windows registry on this platform
  UNVERIFIED  disk_free_gb:C:\ >= 40
              probe failed in facts/node-a.json: FileNotFoundError: [Errno 2] No such file or directory: 'C:\\'
summary: 1 node(s), 7 requirement(s): 2 FAIL, 2 UNVERIFIED, 3 OBSERVED
```

## `mof`: plaintext passwords in compiled DSC MOF files

```
python nodecheck.py mof dsc/node-a.mof dsc/node-b.mof
```

A compiled MOF holds each credential as an `instance of MSFT_Credential` with a `Password` property
(the plaintext form is shown in Microsoft's
[Credentials Options in Configuration Data](https://learn.microsoft.com/en-us/powershell/dsc/configurations/configdatacredentials?view=dsc-1.1)).
When a configuration is compiled with a certificate
([Securing the MOF File](https://learn.microsoft.com/en-us/powershell/dsc/pull-server/secureMOF?view=dsc-1.1)),
the compiled value is a CMS message, as the real run below shows. CMS is RFC 5652, and
`Protect-CmsMessage` writes the same format
([Protect-CmsMessage](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/protect-cmsmessage?view=powershell-5.1)).

The command gives each credential one verdict, and the file gets the worst one:

| Verdict | Meaning | Exit |
|---|---|---|
| `PLAINTEXT` | A password that is not a CMS message. An unquoted token counts. | 1 |
| `UNVERIFIED` | The tool could not decide. See the list below. | 3 |
| `ENCRYPTED` | Every password is a CMS EnvelopedData message, and the document says `ContentType="PasswordEncrypted"`. | 0 |
| `NO_MSFT_CREDENTIAL` | A real MOF with no `MSFT_Credential` in it. | 0 |

Several files get the worst exit code in the order 1, 2, 3, 0. A file that cannot be read exits 2
and the later files are still read. A plaintext file after it still exits 1.

This is a real run on two MOF files compiled by Windows PowerShell 5.1 on the Windows host. One used
a document-encryption certificate. The other used `PsDscAllowPlainTextPassword`. The passwords were
synthetic.

```
$ python nodecheck.py mof enc/node-a.mof
enc/node-a.mof: ENCRYPTED  1 credential(s)
  ENCRYPTED   line 8 $MSFT_Credential1ref  CMS EnvelopedData, 445 bytes
$ echo $?
0
$ python nodecheck.py mof plain/node-a.mof
plain/node-a.mof: PLAINTEXT  1 credential(s)
  PLAINTEXT   line 8 $MSFT_Credential1ref  not a CMS message: the password is readable
$ echo $?
1
```

What the tool treats as UNVERIFIED and not as clean:

- A file with no `MSFT_Credential` and no `OMI_ConfigurationDocument` instance. An empty file, a log
  file and a JSON file all land here.
- A file with NUL characters. That is UTF-16 saved without a byte order mark.
- A `Password` of `NULL`, a `$reference` or an array.
- A `Password` that holds a CMS-looking value that is not an EnvelopedData message.
- A CMS password in a file whose document does not say `ContentType="PasswordEncrypted"`. Windows
  PowerShell writes that line, as the compiled file above shows. Microsoft's pages that I read do
  not mention it, so it is treated as a sign of a compiled file and not as a documented rule.
- A block comment that is never closed. MOF ends such a comment at the end of the file
  ([DSP0221](https://www.dmtf.org/sites/default/files/standards/documents/DSP0221_3.0.1.pdf), clause 5.4), but a file cut short is not
  a file this tool can vouch for.
- A string with an escape that the tool does not read, including the hex escape.

The password text never reaches the report. A reason names what is wrong with the value, and never
the value or the character after a backslash. The self-test greps the output for the password.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every requirement is OBSERVED. For `mof`: every credential is encrypted or none exists. |
| 1 | At least one FAIL. For `mof`: a plaintext password. |
| 2 | A file could not be read or written. |
| 3 | At least one UNVERIFIED and no FAIL. For `gather`: a fact could not be collected. |
| 64 | A usage error, a table that is not valid, or a command line the parser refuses. |

## Limits

- The tool observes only what is in the collector table above. The ODBC driver list, TCP
  reachability, free disk space, the operating system fields and the MOF check are the only facts it
  collects. Every other fact is typed by hand.
- The ODBC probe reads the 64-bit registry view only, so a driver that is installed only as a
  32-bit driver is reported as absent.
- On a host with no Windows registry (tested on Ubuntu) the `odbc_drivers` fact is always an error,
  so every requirement on it is UNVERIFIED.
- If the ODBC Drivers registry key is missing, the probe errors and the requirement is UNVERIFIED.
  A host with no ODBC drivers reads as unknown, not as empty.
- `gather` trusts the `--node` label. Running `gather --node node-b` on the host of node-a files
  node-a's facts under node-b. Compare the `gathered ... on <host>` line in the report with the node.
- A firewall that answers a connection with a refusal looks the same as a closed port.
- The `tcp:` probe connects to whatever host and port the table names. A table from an untrusted
  source turns `gather` into a port scanner. Run only tables you wrote.
- A facts file holds the gathering host's real name in `gathered_on` and the raw text of any probe
  error, which can include local paths. Keep facts files and tables out of public repositories.
- `gather --apply` replaces an existing facts file with no backup. It refuses to replace any other
  kind of file.
- `disk_free_gb` is GiB (1024 cubed bytes), not 10 to the 9th. It is cut down to 0.1, so 39.96 GiB
  reads as 39.9.
- Version parts compare as integers, so `18.03` equals `18.3`.
- `mof` reads `MSFT_Credential` instances only. A plaintext string property called `Password` on
  any other resource class is not seen. The verdict for such a file is `NO_MSFT_CREDENTIAL` for that
  reason, and not "clean".
- `ENCRYPTED` means the value parses as a CMS message of type EnvelopedData: an outer SEQUENCE whose
  first element is the id-envelopedData object identifier from [RFC 5652 section 6.1](https://www.rfc-editor.org/rfc/rfc5652.html#section-6.1).
  It does not prove that the value decrypts on any node.
- A CMS message in BER indefinite-length form is refused and reported UNVERIFIED, not ENCRYPTED.
- Hex escapes in a MOF string make that credential UNVERIFIED. A password written as an array is
  UNVERIFIED too. Both fail safe.
- The `mof` command does not expand wildcards. `cmd.exe` and PowerShell do not do it for a native
  command either, so `mof dsc\*.mof` is read as one literal path and exits 2.
- A backslash path in a `mof:` fact or a `facts` entry does not resolve on Linux. That fails safe
  as UNVERIFIED.
- If one facts file holds the same key under both `facts` and `errors`, the value wins and the error
  is ignored. `gather` never writes both, so only a hand-edited file does this.
- `check` prints the observed value of each fact, cut at 100 characters. A secret that someone
  types in as a fact value appears in the report.
- When two roles require the same fact, operator and value with different `why` texts, only the first
  `why` is printed.
- A facts file that is stale, in the future or for another node is dropped whole. A fresh file is
  then judged without the dropped file's facts, and the report does not say what they held.
- The line `gathered ... on <host>` is text from the file. The tool does not check it.
- The coverage run needs the `coverage` package, which is not part of this tool. Coverage was
  measured on Windows only. On Ubuntu the self-test passes with the same assertion count.

## Sources

| Behaviour | Source |
|---|---|
| ODBC Drivers subkey and the `Installed` data | [ODBC Drivers Subkey](https://learn.microsoft.com/en-us/sql/odbc/reference/install/odbc-drivers-subkey?view=sql-server-ver16) |
| 64-bit registry view | [Accessing an Alternate Registry View](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view) |
| Native Client is not shipped from SQL Server 2022 and is not recommended for new work | [SQL Server Native Client](https://learn.microsoft.com/en-us/sql/relational-databases/native-client/sql-server-native-client?view=sql-server-ver15) |
| Plaintext `MSFT_Credential` in a MOF | [Credentials Options in Configuration Data](https://learn.microsoft.com/en-us/powershell/dsc/configurations/configdatacredentials?view=dsc-1.1) |
| Encrypting credentials in a MOF with a certificate | [Securing the MOF File](https://learn.microsoft.com/en-us/powershell/dsc/pull-server/secureMOF?view=dsc-1.1) |
| CMS messages from PowerShell | [Protect-CmsMessage](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/protect-cmsmessage?view=powershell-5.1) |
| EnvelopedData and id-envelopedData | [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.html#section-6.1) |
| MOF comments (clause 5.4) and string escapes (clause 7.6.1.3) | [DMTF DSP0221 3.0.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0221_3.0.1.pdf) |
| A refused connection is `ECONNREFUSED` | [Python exceptions](https://docs.python.org/3.12/library/exceptions.html#ConnectionRefusedError) |

The deprecated provider named in the story is the SQL Server Native Client. The Microsoft page above
calls SQLNCLI and SQLNCLI11 "not recommended for new application development". The example table
lists those two names under `excludes`, as a requirement you supply by hand.

## Contributing

Open an issue or pull request on GitHub.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [bkpbase](https://github.com/uhsear/bkpbase) - the same refusal to call a gate clean on rows that
  cannot support it, applied to exported backup history. It refuses snapshot rows, copy-only rows and
  fulls that a later backup overwrote.
- [sessorigin](https://github.com/uhsear/sessorigin) - a verdict that is never MIGRATED while a node
  still holds sessions on the old server. Run it after the nodes pass this check.
- [stalehost](https://github.com/uhsear/stalehost) - find every ArcGIS file that still names the host
  you are retiring, and never call a tree clean that it could not finish reading.
