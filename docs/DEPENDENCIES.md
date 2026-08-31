# Everything the agent needs installed

A complete, audited inventory (2026-08-25) of what BS2 + the A/B require on the
box that runs them. Loopback-only lab; no cloud services needed.

## 1. OS baseline

- Linux (x86_64), a normal user with `sudo`, ~20GB free disk
- Python 3.10+ (the suite runs 3.12)

## 2. Python packages

```bash
pip install cryptography playwright requests
playwright install chromium          # downloads the browser the adapters drive
```

- `cryptography` — Lenz terminal-projection signing (ed25519), REQUIRED
- `playwright` — the browser adapters (registry probes + future browser lanes)
- `requests` — used by the playwright ecosystem; cheap insurance

Everything else the runtime imports is stdlib. The reference scorer
(`scorer/crapi_score.py`) is stdlib-only (urllib).

## 3. System tools (apt / package manager)

Required for the core loop (hand-checked against recipes + hands + trooper):

```bash
sudo apt install -y curl nmap netcat-openbsd searchsploit gobuster ffuf \
                    smbclient enum4linux hydra sqlmap nuclei
```

| Tool | Why |
|---|---|
| curl | the transport of nearly everything (governed curls, probes) |
| nmap | hands recon sweeps (charter-scoped) |
| netcat (nc) | connectivity checks, banner grabs |
| searchsploit (exploitdb) | CVE lookup rituals |
| gobuster / ffuf | web-enum / fuzzing lanes |
| smbclient / enum4linux | SMB lanes |
| hydra | auth brute lanes (governed) |
| sqlmap | SQLi lane (gated: only after a credible injection hypothesis) |
| nuclei | template scans (governed) |

Optional scanner family (the registry reports them honestly as absent until
installed — the engine degrades, never fails):

```bash
sudo apt install -y mitmproxy          # + pip install katana? see below
# katana: github.com/projectdiscovery/katana (single binary -> /usr/local/bin)
# zap: zaproxy.org (the registry probes a local ZAP daemon if present)
# schemathesis / restler / interactsh: pip/github — registry-optional
```

The tool registry (`live/tools_registry.py`) PROBES for each and records
catalogued/routable/runnable/verified — an absent tool is a known gap, never a
silent assumption. The manager can still run on curl+nmap alone.

## 4. Docker (for the lab targets)

```bash
curl -fsSL https://get.docker.com | sh
sudo apt install -y docker-compose-plugin    # 'docker compose' (v2)
```

- crAPI stack + MailHog: see STANDUP.md §1 (the isolated dockerd is OPTIONAL —
  it only moves lab storage off the root disk; a main-daemon install works)
- Juice Shop canary: see STANDUP.md §2

## 5. Model access (the two brains)

- **Trooper** (cheap trigger model): a DeepSeek API key, exposed via env at launch:
  ```bash
  export TROOPER_BASE=https://api.deepseek.com
  export TROOPER_MODEL=deepseek-v4-flash
  export TROOPER_KEY_FILE=/home/<you>/.ds_key   # 600 file containing the key
  ```
  Never in argv, never in a log.
- **Manager** (Opus-class, content-blind): the canonical engine calls it through
  the `claude` CLI (Claude Code headless `claude -p`). Install Claude Code and
  authenticate once. Any capable model behind an equivalent interface works —
  the call site is `manager/run_htb.py::call_manager`.

## 6. What the agent does NOT need

- No other machines, VPNs, cloud accounts, or external services — the lab is
  loopback-only and the seam is local python
- No GPU (the harness is model-API driven)
- No database: run state is JSON files under the run dir

## 7. Verification checklist (run once after installing)

```bash
python3 -c "import cryptography, playwright, requests; print('py ok')"
which curl nmap nc searchsploit gobuster ffuf smbclient enum4linux hydra sqlmap nuclei
docker compose version
crapi status && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8888/
cd gunbelt && python3 -m pytest tests/ -q      # all pass, 1 known skip
```
