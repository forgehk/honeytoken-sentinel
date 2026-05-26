# honeytoken-sentinel

> Mint decoy credentials. Place them in the spots an attacker would search after a breach. Get an alert the moment one fires.

[![Tests](https://img.shields.io/badge/tests-19%2F19%20passing-success.svg)]()
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This is a tripwire system. Honeytokens are credentials that **look real** (right prefix, right length, right shape) but are bound to no account — so the only way one ever gets used is if someone is somewhere they shouldn't be.

You scatter them across the places attackers reach first after they get a foothold: `~/.aws/credentials`, the bottom of a `.env`, a comment in `deploy.sh`, a "FINANCIALS_FINAL.xlsx" on the shared drive. The moment any of them is fetched, logged, or used, you get a high-confidence intrusion signal — typically before the attacker has done meaningful damage.

This is the [Thinkst Canary](https://canarytokens.org/) concept, in self-hosted Python form.

## What it mints

| Kind | Looks like | Where you'd plant it |
|---|---|---|
| `aws` | `AKIA…` access key + secret | `~/.aws/credentials`, `terraform.tfvars` |
| `github` | `github_pat_11AAAA…` PAT | comment block in a deploy script |
| `stripe` | `sk_live_…` secret key | `.env`, payment service config |
| `url` | `https://your-canary.example.com/c/<id>` | internal wiki, README, "click here for keys" |
| `doc` | A registered "decoy doc" filename | shared drive, top-level folder |

Every minted token carries an opaque `token_id` that's recognized when it fires. Tokens look authentic but contain no real secret material.

## Install

```bash
git clone https://github.com/forgehk/honeytoken-sentinel.git
cd honeytoken-sentinel
pip install -e ".[dev]"
```

## Use it

### Mint a token

```bash
# AWS-shaped key pair, placed in ~/.aws/credentials on a staging box
honeytoken mint aws --hint "staging-box-3 ~/.aws/credentials"
```

```json
{
  "token_id": "aws_xUq3kV2NbT8z",
  "kind": "aws_key",
  "value": "aws_access_key_id = AKIAQX7Z2K3M4PNRBTHV\naws_secret_access_key = ...",
  "placement_hint": "staging-box-3 ~/.aws/credentials",
  "created_at": "2026-05-25T18:42:11+00:00",
  "metadata": {"access_key": "AKIAQX7Z2K3M4PNRBTHV", "fingerprint": "8b21a4e9c7f3"}
}
```

### List what you have

```bash
honeytoken list
```

```
aws_xUq3kV2NbT8z   aws_key       2026-05-25T18:42:11+00:00   triggers=0   staging-box-3 ~/.aws/credentials
url_pT91kF2vL7zX   url           2026-05-25T18:43:05+00:00   triggers=2   internal wiki page
```

### Run the canary listener

```bash
honeytoken serve --port 8080 --slack-webhook https://hooks.slack.com/services/...
```

Anyone fetching `http://your-host:8080/c/<token_id>` triggers:
1. An event recorded in the registry with source IP, user agent, headers
2. A Slack alert (if configured)
3. A response indistinguishable from a normal asset — a transparent 1×1 GIF, no JSON, no error pages, no hint that they tripped anything

### Scan logs for token leakage

```bash
# Did one of your tokens show up in a log dump or pasted in a chat?
honeytoken scan logs/access.log dumps/leaked.txt
```

```
[HIT] dumps/leaked.txt contains aws_xUq3kV2NbT8z (aws_key)
scanned 2 file(s), 1 hit(s)
```

Exit code 1 means at least one match — easy to wire into a CI gate.

### Review trigger events

```bash
honeytoken events --token url_pT91kF2vL7zX
```

```
2026-05-25T19:10:33+00:00   url_pT91kF2vL7zX   203.0.113.7    Mozilla/5.0 (Windows…
2026-05-25T19:14:08+00:00   url_pT91kF2vL7zX   203.0.113.7    curl/7.88.0
```

## How it works

The system has three pieces with clean boundaries:

```
        ┌──────────────────┐
        │     tokens.py    │  mint_aws_key(), mint_canary_url(), …
        │                  │  detect_in_text(blob, registry)
        └────────┬─────────┘
                 │
                 v
        ┌──────────────────┐
        │   registry.py    │  atomic JSON store (tokens + trigger events)
        │                  │  add_token / record_trigger / events_for
        └────────┬─────────┘
                 │
                 v
        ┌──────────────────┐         ┌─────────────────┐
        │   listener.py    │────────>│   Slack /       │
        │  /c/<id> handler │         │   webhook       │
        └──────────────────┘         └─────────────────┘
```

The listener is **stdlib only** — no Flask, no FastAPI. `BaseHTTPRequestHandler` is enough, and removing the dependency means this runs on a stripped Alpine container the same as anywhere else.

The registry uses **atomic writes** (write-temp + `os.replace`) so a crash mid-write can't leave a partial JSON file that breaks the listener on restart.

The canary endpoint **always returns the same 200 + transparent GIF**, even for unknown token IDs. That way an attacker probing `/c/aaa`, `/c/bbb`, `/c/ccc` can't bisect which IDs are live tokens.

## Operational notes

- Run the listener behind a TLS terminator (Caddy, nginx) and use a memorable hostname like `canary.<yourcompany>.com`.
- Tokens are pseudonymous — losing one only burns that token; the registry contains zero real secrets.
- Pair with `honeytoken scan` in CI: if any pre-minted token appears in a code repo, fail the build.
- For external email canaries, plant tokens in `WHEN_USED.txt` files inside zipped "Q4 Compensation" decoys.

## Tests

```bash
pytest -q
# 19 passed
```

The suite covers token shape & uniqueness, registry persistence and atomicity, and a real loopback HTTP integration test for the listener (spins up `BaseHTTPRequestHandler` on `127.0.0.1:0` and exercises `/c/<id>` end to end).

## Limitations

- No DNS-tracker token (subdomain canaries — a known nice extension)
- No PDF/DOCX watermark generator (the registry tracks the watermark, doc generation is up to you)
- The HTTP listener is a single process — fine for personal/team use, put it behind a load balancer for scale

## License

MIT — see [LICENSE](LICENSE).
