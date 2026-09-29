# PQC Discovery

Standalone Python commands for post-quantum cryptography evidence collection,
repository inventory, classification, CBOM export, and offline drift analysis.

Requires Python 3.10 or newer. Python dependencies are installed with the package.
Git, OpenSSL, and Subfinder remain independent tools: this package neither
installs nor launches them. Install the tools needed by your chosen workflow
separately. TLS collection requires an OpenSSL build supporting the
`X25519MLKEM768` and `MLKEM768` groups.

## Install

From a checkout, on Linux or macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/pqc-discovery doctor
```

Or use the convenience installer, which needs Python's `venv` and pip support:

```bash
bash install.sh
```

The default installation is `~/.local/share/pqc-discovery/venv`. Add its `bin`
directory to `PATH`. Override the interpreter and destination when needed:

```bash
PQC_PYTHON=python3.12 PQC_VENV_DIR=/opt/pqc-discovery/venv bash install.sh
```

Install the tagged release directly from GitHub using pipx:

```bash
pipx install 'git+https://github.com/MQ-xz/pqc-discovery.git@v0.2.1'
```

For an existing virtual environment, use `python -m pip install` with the same
Git URL. Git URL installation requires Git on the installing machine. A wheel
installation does not require Git.

## Commands

| Command | Purpose |
| --- | --- |
| `pqc-discovery` | Collect, prepare, inventory, classify, and report evidence |
| `rdp-tls-bridge` | Independent authenticated RDP-to-TLS CONNECT bridge |

Each command accepts `--help`. `pqc-discovery --version` prints the package
version; `doctor` checks the Python dependencies without invoking external tools.

Each processing stage runs separately. `--out` names its artifact directory;
stages read predecessor artifacts from that directory. Independent workflow
nodes should share that directory and declare their artifact dependencies.

| Stage | Input | Output |
| --- | --- | --- |
| `discover --scope DOMAIN [--hosts FILE]` | Domain, optional Subfinder text and sibling `.status` file | `discovery.json` (also fetches crt.sh CT data) |
| `resolve` | `discovery.json` | `resolved.json`, `excluded.jsonl` |
| `ports [--nonweb]` | `resolved.json` | `ports.json` |
| `prepare_probes` | `ports.json` | `probe-plan.json`, `probe-plan.tsv`, `rdp-targets.json` |
| `probe --transcripts DIR` | Probe plan, ports, external OpenSSL transcripts | `evidence.json` |
| `classify` | `evidence.json` | Findings, observations, certificates, `export.json` |
| `report` | Classified evidence | CBOM, budget, scorecard, heatmap, vendor, board artifacts |
| `ssh` | `ports.json` | `ssh.jsonl` |
| `dnssec` | `resolved.json` | `dnssec.jsonl` |
| `prepare_repo --scope URL` | HTTPS repository URL | `repository-url.txt` |
| `select_blobs` | External Git `repository-tree.bin` | Manifest and `repository-objects.txt` |
| `inventory --blobs FILE` | Manifest, commit file, external Git batch blobs | Six repository inventory JSONL files |
| `stage --scope FILE [--scope-root DIR]` | Export bundle or comparison bundle | `before.json`, `evidence.json` |
| `diff` | Before/current evidence | `drift.jsonl` |

### Offline reclassification

Given an existing `export.json` in the current directory:

```bash
pqc-discovery stage --scope export.json --scope-root . --out artifacts/review
pqc-discovery classify --out artifacts/review
pqc-discovery diff --out artifacts/review
```

The scope root defaults to `SCOPE_STORAGE_PATH`, then `STORAGE_PATH/scopes` if
configured, otherwise the current directory. Uploaded paths must stay inside
that root. Evidence bundles use `pqc-discovery-evidence-1`; comparisons use
`pqc-discovery-comparison-1` with `before` and `after` evidence bundles.

### External tool artifacts

Subfinder output is one hostname per line. Alongside `subfinder.txt`, write
`subfinder.status` containing its numeric exit status. Pass the text file with
`discover --hosts subfinder.txt`; discovery records incomplete provider coverage.

For repository inventory, run Git separately to produce:

- `repository-tree.bin`: `git ls-tree -rlz HEAD` output.
- `repository-commit.txt`: `git rev-parse HEAD` output.
- After `select_blobs`, feed `repository-objects.txt` to `git cat-file --batch`
  and save the binary output for `inventory --blobs`.

Use a clone without checkout, hooks, or submodule recursion; do not execute
repository code. Restrict Git transport to HTTPS and disable redirects.

For TLS, `probe-plan.tsv` contains index, connection target, hostname, and groups,
separated by tabs. `baseline` means no forced TLS version/group. Run OpenSSL
separately with `s_client -showcerts -msg -no_ign_eof`, the target and hostname,
and `-tls1_3 -groups GROUPS` for non-baseline rows. The transcript directory needs:

- `version.txt`: `openssl version` output.
- `INDEX.txt`: combined stdout/stderr for each probe.
- `INDEX.status`: exit status, elapsed milliseconds, and UTC observation time,
  separated by tabs. Accepted statuses are 0, 1, and 124 (timeout).
- `completed`: a marker written only after the entire collection finishes.

### Independent RDP bridge

```bash
rdp-tls-bridge \
  --targets artifacts/pqc/rdp-targets.json \
  --ready artifacts/pqc/rdp-ready.tsv \
  --done artifacts/pqc/openssl.done \
  --completed artifacts/pqc/rdp-completed
```

Targets are JSON objects with `ip` and `port` in an array; only public IPs on
port 3389 are accepted. The bridge writes its address and generated password to
the permission-restricted ready file. A separate OpenSSL process connects using
`-proxy ADDRESS -proxy_user rdp -proxy_pass env:RDP_PROXY_PASSWORD`. Supply the
password from the ready file through that environment variable.

Run the bridge concurrently with OpenSSL. Create the `--done` file after the
consumer stops; the bridge then exits and writes `--completed`. For separate
workers, configure shared artifact storage, concurrent capacity, and network
reachability. `--bind`, `--advertise`, and `--timeout` control the listener and
lifetime. Only local bridge behavior has been verified; cross-worker deployment
requires environment-specific verification.

## Build a release

```bash
python -m pip install build
python -m build
```

The resulting wheel and source archive are in `dist/`. A wheel can be installed
with `python -m pip install dist/pqc_discovery-0.2.1-py3-none-any.whl`; pip also
needs access to the declared Python dependencies or a prepared local wheelhouse.

## Interpretation limits

Hybrid key exchange does not establish post-quantum authentication or
organization-wide readiness. Repository matches are heuristic references, not
proof of runtime use. DNSSEC inventory does not validate a chain of trust. SSH
inventory does not authenticate. Evidence hashes detect corruption, not
authenticity, and missing observations do not establish remediation.

## License

[MIT](LICENSE), copyright 2026 Mahshooq Zubair.
